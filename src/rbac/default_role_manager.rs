use crate::{
    error::RbacError,
    rbac::{MatchingFn, RoleManager},
    Result,
};
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use std::collections::{hash_map::Entry, HashMap, HashSet};

#[cfg(feature = "cached")]
use crate::cache::{Cache, DefaultCache};

#[cfg(feature = "cached")]
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

const DEFAULT_DOMAIN: &str = "DEFAULT";

pub struct DefaultRoleManager {
    all_domains: HashMap<String, StableDiGraph<String, EdgeVariant>>,
    all_domains_indices: HashMap<String, HashMap<String, NodeIndex<u32>>>,
    #[cfg(feature = "cached")]
    cache: DefaultCache<u64, bool>,
    max_hierarchy_level: usize,
    role_matching_fn: Option<MatchingFn>,
    domain_matching_fn: Option<MatchingFn>,
}

#[derive(Debug)]
enum EdgeVariant {
    Link,
    Match,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            all_domains: HashMap::new(),
            all_domains_indices: HashMap::new(),
            max_hierarchy_level,
            #[cfg(feature = "cached")]
            cache: DefaultCache::new(50),
            role_matching_fn: None,
            domain_matching_fn: None,
        }
    }

    fn get_or_create_role(
        &mut self,
        name: &str,
        domain: Option<&str>,
    ) -> NodeIndex<u32> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        let graph = self.all_domains.entry(domain.into()).or_default();

        let role_entry = self
            .all_domains_indices
            .entry(domain.into())
            .or_default()
            .entry(name.into());

        let vacant_entry = match role_entry {
            Entry::Occupied(e) => return *e.get(),
            Entry::Vacant(e) => e,
        };

        let new_role_id = graph.add_node(name.into());
        vacant_entry.insert(new_role_id);

        if let Some(role_matching_fn) = self.role_matching_fn {
            let mut added = false;

            let node_ids: Vec<_> =
                graph.node_indices().filter(|&i| graph[i] != name).collect();

            for existing_role_id in node_ids {
                added |= link_if_matches(
                    graph,
                    role_matching_fn,
                    new_role_id,
                    existing_role_id,
                );

                added |= link_if_matches(
                    graph,
                    role_matching_fn,
                    existing_role_id,
                    new_role_id,
                );
            }

            if added {
                #[cfg(feature = "cached")]
                self.cache.clear();
            }
        }

        new_role_id
    }

    fn matched_domains(&self, domain: Option<&str>) -> Vec<String> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);
        if let Some(domain_matching_fn) = self.domain_matching_fn {
            self.all_domains
                .keys()
                .filter_map(|key| {
                    if domain_matching_fn(domain, key) {
                        Some(key.to_owned())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
        } else {
            self.all_domains
                .get(domain)
                .map_or(vec![], |_| vec![domain.to_owned()])
        }
    }

    fn domain_has_role(&self, name: &str, domain: Option<&str>) -> bool {
        let matched_domains = self.matched_domains(domain);

        matched_domains.iter().any(|domain| {
            // try to find direct match of role
            if self.all_domains_indices[domain].contains_key(name) {
                true
            } else if let Some(role_matching_fn) = self.role_matching_fn {
                // else if role_matching_fn is set, iterate all graph nodes and try to find matching role
                let graph = &self.all_domains[domain];

                graph
                    .node_weights()
                    .any(|role| role_matching_fn(name, role))
            } else {
                false
            }
        })
    }
}

/// link node of `not_pattern_id` to `maybe_pattern_id` if
/// `not_pattern` matches `maybe_pattern`'s pattern and
/// there doesn't exist a match edge yet
fn link_if_matches(
    graph: &mut StableDiGraph<String, EdgeVariant>,
    role_matching_fn: fn(&str, &str) -> bool,
    not_pattern_id: NodeIndex<u32>,
    maybe_pattern_id: NodeIndex<u32>,
) -> bool {
    let not_pattern = &graph[not_pattern_id];
    let maybe_pattern = &graph[maybe_pattern_id];

    if !role_matching_fn(maybe_pattern, not_pattern) {
        return false;
    }

    let add_edge =
        if let Some(idx) = graph.find_edge(not_pattern_id, maybe_pattern_id) {
            !matches!(graph[idx], EdgeVariant::Match)
        } else {
            true
        };

    if add_edge {
        graph.add_edge(not_pattern_id, maybe_pattern_id, EdgeVariant::Match);

        true
    } else {
        false
    }
}

impl RoleManager for DefaultRoleManager {
    fn clear(&mut self) {
        self.all_domains_indices.clear();
        self.all_domains.clear();
        #[cfg(feature = "cached")]
        self.cache.clear();
    }

    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) {
        if name1 == name2 {
            return;
        }

        let role1 = self.get_or_create_role(name1, domain);
        let role2 = self.get_or_create_role(name2, domain);

        let graph = self
            .all_domains
            .get_mut(domain.unwrap_or(DEFAULT_DOMAIN))
            .unwrap();

        let add_link = if let Some(edge) = graph.find_edge(role1, role2) {
            !matches!(graph[edge], EdgeVariant::Link)
        } else {
            true
        };

        if add_link {
            graph.add_edge(role1, role2, EdgeVariant::Link);

            #[cfg(feature = "cached")]
            self.cache.clear()
        }
    }

    fn matching_fn(
        &mut self,
        role_matching_fn: Option<MatchingFn>,
        domain_matching_fn: Option<MatchingFn>,
    ) {
        self.domain_matching_fn = domain_matching_fn;
        self.role_matching_fn = role_matching_fn;
    }

    fn delete_link(
        &mut self,
        name1: &str,
        name2: &str,
        domain: Option<&str>,
    ) -> Result<()> {
        if !self.domain_has_role(name1, domain)
            || !self.domain_has_role(name2, domain)
        {
            return Err(
                RbacError::NotFound(format!("{} OR {}", name1, name2)).into()
            );
        }

        let role1 = self.get_or_create_role(name1, domain);
        let role2 = self.get_or_create_role(name2, domain);

        let graph = self
            .all_domains
            .get_mut(domain.unwrap_or(DEFAULT_DOMAIN))
            .unwrap();

        if let Some(edge_index) = graph.find_edge(role1, role2) {
            graph.remove_edge(edge_index).unwrap();

            #[cfg(feature = "cached")]
            self.cache.clear();
        }

        Ok(())
    }

    fn has_link(&self, name1: &str, name2: &str, domain: Option<&str>) -> bool {
        if name1 == name2 {
            return true;
        }

        #[cfg(feature = "cached")]
        let cache_key = {
            let mut hasher = DefaultHasher::new();
            name1.hash(&mut hasher);
            name2.hash(&mut hasher);
            domain.unwrap_or(DEFAULT_DOMAIN).hash(&mut hasher);
            hasher.finish()
        };

        #[cfg(feature = "cached")]
        if let Some(res) = self.cache.get(&cache_key) {
            return res;
        }

        let matched_domains = self.matched_domains(domain);

        let mut res = false;

        for domain in matched_domains {
            let graph = self.all_domains.get(&domain).unwrap();
            let indices = self.all_domains_indices.get(&domain).unwrap();

            let role1 = if let Some(role1) = indices.get(name1) {
                Some(*role1)
            } else {
                graph.node_indices().find(|&i| {
                    let role_name = &graph[i];

                    role_name == name1
                        || self
                            .role_matching_fn
                            .map(|f| f(name1, role_name))
                            .unwrap_or_default()
                })
            };

            let role1 = if let Some(role1) = role1 {
                role1
            } else {
                continue;
            };

            let mut bfs = matching_bfs::Bfs::new(
                graph,
                role1,
                self.max_hierarchy_level,
                self.role_matching_fn.is_some(),
            );

            while let Some(node) = bfs.next(graph) {
                let role_name = &graph[node];

                if role_name == name2
                    || self
                        .role_matching_fn
                        .map(|f| f(role_name, name2))
                        .unwrap_or_default()
                {
                    res = true;
                    break;
                }
            }
        }

        #[cfg(feature = "cached")]
        self.cache.set(cache_key, res);

        res
    }

    fn get_roles(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let matched_domains = self.matched_domains(domain);

        let res = matched_domains.into_iter().fold(
            HashSet::new(),
            |mut set, domain| {
                let graph = &self.all_domains[&domain];

                if let Some(role_node) = graph.node_indices().find(|&i| {
                    graph[i] == name
                        || self.role_matching_fn.unwrap_or(|_, _| false)(
                            name, &graph[i],
                        )
                }) {
                    let neighbors = matching_bfs::bfs_iterator(
                        graph,
                        role_node,
                        self.role_matching_fn.is_some(),
                    )
                    .map(|i| graph[i].clone());

                    set.extend(neighbors);
                }

                set
            },
        );
        res.into_iter().collect()
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let matched_domains = self.matched_domains(domain);

        let res = matched_domains.into_iter().fold(
            HashSet::new(),
            |mut set, domain| {
                let graph = &self.all_domains[&domain];

                if let Some(role_node) = graph.node_indices().find(|&i| {
                    graph[i] == name
                        || self
                            .role_matching_fn
                            .map(|f| f(name, &graph[i]))
                            .unwrap_or_default()
                }) {
                    let neighbors = graph
                        .neighbors_directed(
                            role_node,
                            petgraph::Direction::Incoming,
                        )
                        .map(|i| graph[i].clone());

                    set.extend(neighbors);
                }

                set
            },
        );

        res.into_iter().collect()
    }
}

mod matching_bfs {
    use super::EdgeVariant;
    use fixedbitset::FixedBitSet;
    use petgraph::graph::NodeIndex;
    use petgraph::stable_graph::StableDiGraph;
    use petgraph::visit::{EdgeRef, VisitMap, Visitable};
    use std::collections::VecDeque;

    #[derive(Clone)]
    pub(super) struct Bfs {
        /// The queue of nodes to visit
        pub queue: VecDeque<NodeIndex<u32>>,
        /// The map of discovered nodes
        pub discovered: FixedBitSet,
        /// Maximum depth
        pub max_depth: usize,
        /// Consider `Match` edges
        pub with_pattern_matching: bool,

        /// Current depth
        depth: usize,
        /// Number of elements until next depth is reached
        depth_elements_remaining: usize,
    }

    impl Bfs {
        /// Create a new **Bfs**, using the graph's visitor map, and put **start**
        /// in the stack of nodes to visit.
        pub fn new(
            graph: &StableDiGraph<String, EdgeVariant>,
            start: NodeIndex<u32>,
            max_depth: usize,
            with_pattern_matching: bool,
        ) -> Self {
            let mut discovered = graph.visit_map();
            discovered.visit(start);

            let mut queue = VecDeque::new();
            queue.push_front(start);

            Bfs {
                queue,
                discovered,
                max_depth,
                with_pattern_matching,
                depth: 0,
                depth_elements_remaining: 1,
            }
        }

        /// Return the next node in the bfs, or **None** if the traversal is done.
        pub fn next(
            &mut self,
            graph: &StableDiGraph<String, EdgeVariant>,
        ) -> Option<NodeIndex<u32>> {
            if self.max_depth <= self.depth {
                return None;
            }

            if let Some(node) = self.queue.pop_front() {
                self.update_depth();

                let mut counter = 0;
                for succ in
                    bfs_iterator(graph, node, self.with_pattern_matching)
                {
                    if self.discovered.visit(succ) {
                        self.queue.push_back(succ);
                        counter += 1;
                    }
                }

                self.depth_elements_remaining += counter;

                Some(node)
            } else {
                None
            }
        }

        fn update_depth(&mut self) {
            self.depth_elements_remaining -= 1;
            if self.depth_elements_remaining == 0 {
                self.depth += 1
            }
        }
    }

    pub(super) fn bfs_iterator(
        graph: &StableDiGraph<String, EdgeVariant>,
        node: NodeIndex<u32>,
        with_matches: bool,
    ) -> Box<dyn Iterator<Item = NodeIndex<u32>> + '_> {
        // outgoing LINK edges of node
        let outgoing_direct_edge = graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .filter_map(|edge| match *edge.weight() {
                EdgeVariant::Link => Some(edge.target()),
                EdgeVariant::Match => None,
            });

        if !with_matches {
            return Box::new(outgoing_direct_edge);
        }

        // x := outgoing LINK edges of node
        // outgoing_match_edge : outgoing MATCH edges of x FOR ALL x
        let outgoing_match_edge = graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .filter(|edge| matches!(*edge.weight(), EdgeVariant::Link))
            .flat_map(move |edge| {
                graph
                    .edges_directed(
                        edge.target(),
                        petgraph::Direction::Outgoing,
                    )
                    .filter_map(|edge| match *edge.weight() {
                        EdgeVariant::Match => Some(edge.target()),
                        EdgeVariant::Link => None,
                    })
            });

        // x := incoming MATCH edges of node
        // sibling_matched_by := outgoing LINK edges of x FOR ALL x
        let sibling_matched_by = graph
            .edges_directed(node, petgraph::Direction::Incoming)
            .filter(|edge| matches!(*edge.weight(), EdgeVariant::Match))
            .flat_map(move |edge| {
                graph
                    .edges_directed(
                        edge.source(),
                        petgraph::Direction::Outgoing,
                    )
                    .filter_map(|edge| match *edge.weight() {
                        EdgeVariant::Link => Some(edge.target()),
                        EdgeVariant::Match => None,
                    })
            });

        Box::new(
            outgoing_direct_edge
                .chain(outgoing_match_edge)
                .chain(sibling_matched_by),
        )
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use petgraph::stable_graph::StableDiGraph;

        #[test]
        fn test_max_depth() {
            let mut deps = StableDiGraph::<String, EdgeVariant>::new();
            let pg = deps.add_node("petgraph".into());
            let fb = deps.add_node("fixedbitset".into());
            let qc = deps.add_node("quickcheck".into());
            let rand = deps.add_node("rand".into());
            let libc = deps.add_node("libc".into());

            deps.extend_with_edges([
                (pg, fb, EdgeVariant::Link),
                (pg, qc, EdgeVariant::Link),
                (qc, rand, EdgeVariant::Link),
                (rand, libc, EdgeVariant::Link),
            ]);

            let mut bfs = Bfs::new(&deps, pg, 2, false);

            let mut nodes = vec![];
            while let Some(x) = bfs.next(&deps) {
                nodes.push(x);
            }

            assert!(nodes.contains(&fb));
            assert!(nodes.contains(&qc));
            assert!(nodes.contains(&rand));
            assert!(!nodes.contains(&libc));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sort_unstable<T: Ord>(mut v: Vec<T>) -> Vec<T> {
        v.sort_unstable();
        v
    }

    #[test]
    fn test_role() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", None);
        rm.add_link("u2", "g1", None);
        rm.add_link("u3", "g2", None);
        rm.add_link("u4", "g2", None);
        rm.add_link("u4", "g3", None);
        rm.add_link("g1", "g3", None);

        assert_eq!(true, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(true, rm.has_link("u1", "g3", None));
        assert_eq!(true, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(true, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(true, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(true, rm.has_link("u4", "g2", None));
        assert_eq!(true, rm.has_link("u4", "g3", None));

        // test get_roles
        assert_eq!(vec!["g1"], rm.get_roles("u1", None));
        assert_eq!(vec!["g1"], rm.get_roles("u2", None));
        assert_eq!(vec!["g2"], rm.get_roles("u3", None));
        assert_eq!(vec!["g2", "g3"], sort_unstable(rm.get_roles("u4", None)));
        assert_eq!(vec!["g3"], rm.get_roles("g1", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g2", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g3", None));

        // test delete_link
        rm.delete_link("g1", "g3", None).unwrap();
        rm.delete_link("u4", "g2", None).unwrap();
        assert_eq!(true, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(false, rm.has_link("u1", "g3", None));
        assert_eq!(true, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(false, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(true, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(false, rm.has_link("u4", "g2", None));
        assert_eq!(true, rm.has_link("u4", "g3", None));
        assert_eq!(vec!["g1"], rm.get_roles("u1", None));
        assert_eq!(vec!["g1"], rm.get_roles("u2", None));
        assert_eq!(vec!["g2"], rm.get_roles("u3", None));
        assert_eq!(vec!["g3"], rm.get_roles("u4", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g1", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g2", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g3", None));
    }

    #[test]
    fn test_clear() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", None);
        rm.add_link("u2", "g1", None);
        rm.add_link("u3", "g2", None);
        rm.add_link("u4", "g2", None);
        rm.add_link("u4", "g3", None);
        rm.add_link("g1", "g3", None);

        rm.clear();
        assert_eq!(false, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(false, rm.has_link("u1", "g3", None));
        assert_eq!(false, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(false, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(false, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(false, rm.has_link("u4", "g2", None));
        assert_eq!(false, rm.has_link("u4", "g3", None));
    }

    #[test]
    fn test_domain_role() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", Some("domain1"));
        rm.add_link("u2", "g1", Some("domain1"));
        rm.add_link("u3", "admin", Some("domain2"));
        rm.add_link("u4", "admin", Some("domain2"));
        rm.add_link("u4", "admin", Some("domain1"));
        rm.add_link("g1", "admin", Some("domain1"));

        assert_eq!(true, rm.has_link("u1", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u1", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain2")));

        assert_eq!(true, rm.has_link("u2", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u2", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u3", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u3", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u3", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u3", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u4", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain2")));

        rm.delete_link("g1", "admin", Some("domain1")).unwrap();

        rm.delete_link("u4", "admin", Some("domain2")).unwrap();

        assert_eq!(true, rm.has_link("u1", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain2")));

        assert_eq!(true, rm.has_link("u2", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u3", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u3", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u3", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u3", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u4", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "admin", Some("domain2")));
    }

    #[test]
    fn test_users() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", Some("domain1"));
        rm.add_link("u2", "g1", Some("domain1"));

        rm.add_link("u3", "g2", Some("domain2"));
        rm.add_link("u4", "g2", Some("domain2"));

        rm.add_link("u5", "g3", None);

        assert_eq!(
            vec!["u1", "u2"],
            sort_unstable(rm.get_users("g1", Some("domain1")))
        );
        assert_eq!(
            vec!["u3", "u4"],
            sort_unstable(rm.get_users("g2", Some("domain2")))
        );
        assert_eq!(vec!["u5"], rm.get_users("g3", None));
    }

    #[test]
    fn test_pattern_domain() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(3);
        rm.matching_fn(None, Some(key_match));
        rm.add_link("u1", "g1", Some("*"));

        assert!(rm.domain_has_role("u1", Some("domain2")));
    }

    #[test]
    fn test_basic_role_matching() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(Some(key_match), None);
        rm.add_link("bob", "book_group", None);
        rm.add_link("*", "book_group", None);
        rm.add_link("*", "pen_group", None);
        rm.add_link("eve", "pen_group", None);

        assert!(rm.has_link("alice", "book_group", None));
        assert!(rm.has_link("eve", "book_group", None));
        assert!(rm.has_link("bob", "book_group", None));

        assert_eq!(
            vec!["book_group", "pen_group"],
            sort_unstable(rm.get_roles("alice", None))
        );
    }

    #[test]
    fn test_basic_role_matching2() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(Some(key_match), None);
        rm.add_link("alice", "book_group", None);
        rm.add_link("alice", "*", None);
        rm.add_link("bob", "pen_group", None);

        assert!(rm.has_link("alice", "book_group", None));
        assert!(rm.has_link("alice", "pen_group", None));
        assert!(rm.has_link("bob", "pen_group", None));
        assert!(!rm.has_link("bob", "book_group", None));

        assert_eq!(
            vec!["*", "alice", "bob", "book_group", "pen_group"],
            sort_unstable(rm.get_roles("alice", None))
        );

        assert_eq!(vec!["alice"], sort_unstable(rm.get_users("*", None)));
    }
}
