use crate::{error::RbacError, rbac::RoleManager, Result};

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

const DEFAULT_DOMAIN: &'static str = "DEFAULT";

type MatchingFn = fn(&str, &str) -> bool;

#[derive(Clone)]
pub struct MatchingFnEntry {
    matching_fn: Option<MatchingFn>,
    matched_patterns: HashMap<String, HashSet<String>>,
}

impl Default for MatchingFnEntry {
    fn default() -> Self {
        MatchingFnEntry {
            matching_fn: None,
            matched_patterns: HashMap::new(),
        }
    }
}

impl MatchingFnEntry {
    pub fn set_matching_fn(&mut self, f: MatchingFn) {
        self.matching_fn = Some(f);
        self.matched_patterns.clear();
    }

    pub fn get_matching_fn(&self) -> Option<MatchingFn> {
        self.matching_fn
    }

    pub fn has_matching_fn(&self) -> bool {
        self.matching_fn.is_some()
    }

    pub fn add_matched_pattern(&mut self, matched: &str, pattern: &str) {
        if self.matching_fn.is_none() {
            return;
        }

        self.matched_patterns
            .entry(matched.to_owned())
            .or_insert_with(|| HashSet::new())
            .insert(pattern.to_owned());
    }

    pub fn get_patterns(&self, matched: Option<&str>) -> Vec<String> {
        self.matched_patterns
            .get(matched.unwrap_or(DEFAULT_DOMAIN))
            .map_or(vec![], |x| x.iter().map(|y| y.to_owned()).collect())
    }
}

#[derive(Clone)]
pub struct DefaultRoleManager {
    all_roles: HashMap<String, HashMap<String, Arc<RwLock<Role>>>>,
    max_hierarchy_level: usize,
    domain_matching_entry: MatchingFnEntry,
}

impl DefaultRoleManager {
    pub fn set_domain_matching_fn(&mut self, f: fn(&str, &str) -> bool) {
        self.domain_matching_entry.set_matching_fn(f);
    }

    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level,
            domain_matching_entry: Default::default(),
        }
    }

    fn create_role(&mut self, name: &str, domain: Option<&str>) -> Arc<RwLock<Role>> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        let role = Arc::clone(
            self.all_roles
                .entry(domain.into())
                .or_insert_with(|| HashMap::new())
                .entry(name.into())
                .or_insert_with(|| Arc::new(RwLock::new(Role::new(name)))),
        );

        if self.domain_matching_entry.has_matching_fn() {
            let patterns: Vec<(String, String)> = self
                .all_roles
                .keys()
                .filter_map(|x| {
                    if self
                        .domain_matching_entry
                        .get_matching_fn()
                        .map_or(false, |f| x != domain && f(x, domain))
                    {
                        return Some((x.to_owned(), domain.to_owned()));
                    }
                    if self
                        .domain_matching_entry
                        .get_matching_fn()
                        .map_or(false, |f| x != domain && f(domain, x))
                    {
                        return Some((domain.to_owned(), x.to_owned()));
                    }

                    None
                })
                .collect();

            patterns.iter().for_each(|(d, p)| {
                self.domain_matching_entry.add_matched_pattern(&d, p);
            });
        }

        role
    }

    fn has_role(&self, name: &str, domain: Option<&str>) -> bool {
        let mut patterns = vec![domain.unwrap_or(DEFAULT_DOMAIN).to_owned()];
        patterns.extend(self.domain_matching_entry.get_patterns(domain));

        patterns.iter().any(|pattern| {
            self.all_roles
                .get(pattern)
                .map_or(false, |roles| roles.contains_key(name))
        })
    }
}

impl RoleManager for DefaultRoleManager {
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) {
        let role1 = self.create_role(name1, domain);
        let role2 = self.create_role(name2, domain);

        role1.write().unwrap().add_role(Arc::clone(&role2));
    }

    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<()> {
        if !self.has_role(name1, domain) || !self.has_role(name2, domain) {
            return Err(RbacError::NotFound(format!("{} OR {}", name1, name2)).into());
        }

        let role1 = self.create_role(name1, domain);
        let role2 = self.create_role(name2, domain);

        role1.write().unwrap().delete_role(role2);

        Ok(())
    }

    fn has_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> bool {
        if name1 == name2 {
            return true;
        }

        if !self.has_role(name1, domain) || !self.has_role(name2, domain) {
            return false;
        }

        if self
            .create_role(name1, domain)
            .write()
            .unwrap()
            .has_role(name2, self.max_hierarchy_level)
        {
            return true;
        }

        self.domain_matching_entry
            .get_patterns(domain)
            .iter()
            .any(|pattern| {
                self.create_role(name1, Some(pattern))
                    .write()
                    .unwrap()
                    .has_role(name2, self.max_hierarchy_level)
            })
    }

    fn get_roles(&mut self, name: &str, domain: Option<&str>) -> Vec<String> {
        if !self.has_role(name, domain) {
            return vec![];
        }

        let mut roles = HashSet::new();
        let mut patterns = vec![domain.unwrap_or(DEFAULT_DOMAIN).to_owned()];
        patterns.extend(self.domain_matching_entry.get_patterns(domain));

        patterns.iter().for_each(|pattern| {
            roles.extend(
                self.create_role(name, Some(pattern))
                    .read()
                    .unwrap()
                    .get_roles(),
            );
        });

        roles.into_iter().collect()
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let mut users = HashSet::new();
        let mut patterns = vec![domain.unwrap_or(DEFAULT_DOMAIN).to_owned()];
        patterns.extend(self.domain_matching_entry.get_patterns(domain));

        patterns.iter().for_each(|pattern| {
            users.extend(self.all_roles.get(pattern).map_or(vec![], |roles| {
                roles
                    .values()
                    .filter_map(|role| {
                        let role = role.read().unwrap();
                        if role.has_direct_role(name) {
                            Some(role.name.to_owned())
                        } else {
                            None
                        }
                    })
                    .collect()
            }))
        });

        users.into_iter().collect()
    }

    fn clear(&mut self) {
        self.all_roles.clear();
    }
}

#[derive(Clone, Debug)]
pub struct Role {
    name: String,
    roles: Vec<Arc<RwLock<Role>>>,
}

impl Role {
    fn new<N: Into<String>>(name: N) -> Self {
        Role {
            name: name.into(),
            roles: vec![],
        }
    }

    fn add_role(&mut self, other_role: Arc<RwLock<Role>>) {
        // drop lock after going out of the scope
        {
            let other_role_locked = other_role.read().unwrap();
            if self
                .roles
                .iter()
                .any(|role| role.read().unwrap().name == other_role_locked.name)
            {
                return;
            }
        }

        self.roles.push(other_role);
    }

    fn delete_role(&mut self, other_role: Arc<RwLock<Role>>) {
        let other_role_locked = other_role.read().unwrap();
        self.roles
            .retain(|x| x.read().unwrap().name != other_role_locked.name)
    }

    fn has_role(&self, name: &str, hierarchy_level: usize) -> bool {
        if self.name == name {
            return true;
        }

        if hierarchy_level == 0 {
            return false;
        }

        for role in self.roles.iter() {
            if role.read().unwrap().has_role(name, hierarchy_level - 1) {
                return true;
            }
        }

        false
    }

    fn get_roles(&self) -> Vec<String> {
        self.roles
            .iter()
            .map(|role| role.read().unwrap().name.to_owned())
            .collect()
    }

    fn has_direct_role(&self, name: &str) -> bool {
        self.roles
            .iter()
            .any(|role| role.read().unwrap().name == name)
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

    use crate::model::function_map::key_match;

    #[test]
    fn test_pattern_domain_get_roles() {
        let mut rm = DefaultRoleManager::new(3);
        rm.set_domain_matching_fn(key_match);

        rm.add_link("u1", "g1", Some("domain1"));
        rm.add_link("u2", "g1", Some("domain1"));

        rm.add_link("u3", "g2", Some("domain2"));
        rm.add_link("u4", "g2", Some("domain2"));

        rm.add_link("g1", "g3", Some("*"));
        rm.add_link("g2", "g3", Some("*"));
        // assert_eq!(true, rm.has_link("u1", "g3", Some("domain1")));

        println!(
            "{:?}",
            rm.domain_matching_entry.get_patterns(Some("domain1"))
        );
        println!("{:#?}", rm.all_roles.get("*").unwrap());
        assert_eq!(
            vec!["g1", "g3"],
            sort_unstable(rm.get_roles("u1", Some("domain1")))
        );
        // println!("{:?}", rm.domain_matching_entry.matched_patterns);
        //
        // println!(
        //     "{:?}",
        //     rm.domain_matching_entry.get_patterns(Some("domain1"))
        // );
        assert_eq!(
            vec!["g1", "g3"],
            sort_unstable(rm.get_roles("u2", Some("domain1")))
        );
        assert_eq!(
            vec!["g2", "g3"],
            sort_unstable(rm.get_users("u3", Some("domain2")))
        );
        assert_eq!(
            vec!["g2", "g3"],
            sort_unstable(rm.get_users("u4", Some("domain2")))
        );
    }
}
