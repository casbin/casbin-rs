use crate::{
    error::RbacError,
    rbac::{MatchingFn, RoleManager},
    Result,
};

#[cfg(feature = "cached")]
use crate::cache::{Cache, DefaultCache};

use parking_lot::RwLock;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[cfg(feature = "cached")]
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

const DEFAULT_DOMAIN: &str = "DEFAULT";

pub struct DefaultRoleManager {
    all_domains: HashMap<String, HashMap<String, Arc<RwLock<Role>>>>,
    #[cfg(feature = "cached")]
    cache: DefaultCache<u64, bool>,
    max_hierarchy_level: usize,
    role_matching_fn: Option<MatchingFn>,
    domain_matching_fn: Option<MatchingFn>,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            all_domains: HashMap::new(),
            max_hierarchy_level,
            #[cfg(feature = "cached")]
            cache: DefaultCache::new(50),
            role_matching_fn: None,
            domain_matching_fn: None,
        }
    }

    fn create_role(
        &mut self,
        name: &str,
        domain: Option<&str>,
    ) -> Arc<RwLock<Role>> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        let mut created = false;

        let role = Arc::clone(
            self.all_domains
                .entry(domain.into())
                .or_insert_with(HashMap::new)
                .entry(name.into())
                .or_insert_with(|| {
                    created = true;
                    Arc::new(RwLock::new(Role::new(name)))
                }),
        );

        if let (Some(role_matching_fn), Some(roles), true) =
            (self.role_matching_fn, self.all_domains.get(domain), created)
        {
            let mut added = false;
            for (key, value) in roles {
                if key != name
                    && role_matching_fn(name, key)
                    && role.write().add_role(Arc::clone(value))
                {
                    added = true;
                }
            }
            if added {
                #[cfg(feature = "cached")]
                self.cache.clear();
            }
        }

        role
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

    fn create_temp_role(&mut self, name: &str, domain: Option<&str>) -> Role {
        let mut cloned_role = self.create_role(name, domain).read().clone();

        let matched_domains = self.matched_domains(domain);
        for domain in matched_domains
            .iter()
            .filter(|x| Some(x.as_str()) != domain)
        {
            for direct_role in
                &self.create_role(name, Some(domain)).read().roles
            {
                cloned_role.add_role(Arc::clone(direct_role));
            }
        }

        cloned_role
    }

    fn has_role(&self, name: &str, domain: Option<&str>) -> bool {
        let matched_domains = self.matched_domains(domain);
        !matched_domains.is_empty()
            && matched_domains.iter().any(|domain| {
                self.all_domains.get(domain).map_or(false, |roles| {
                    if roles.contains_key(name) {
                        return true;
                    }

                    if let Some(role_matching_fn) = self.role_matching_fn {
                        return roles
                            .keys()
                            .any(|key| role_matching_fn(name, key));
                    }

                    false
                })
            })
    }
}

impl RoleManager for DefaultRoleManager {
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) {
        if name1 == name2 {
            return;
        }

        let role1 = self.create_role(name1, domain);
        let role2 = self.create_role(name2, domain);

        if !role1.write().add_role(role2) {
            #[cfg(feature = "cached")]
            self.cache.clear();
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
        if !self.has_role(name1, domain) || !self.has_role(name2, domain) {
            return Err(
                RbacError::NotFound(format!("{} OR {}", name1, name2)).into()
            );
        }

        let role1 = self.create_role(name1, domain);
        let role2 = self.create_role(name2, domain);

        role1.write().delete_role(role2);

        #[cfg(feature = "cached")]
        self.cache.clear();

        Ok(())
    }

    fn has_link(
        &mut self,
        name1: &str,
        name2: &str,
        domain: Option<&str>,
    ) -> bool {
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
            return res.into_owned();
        }

        let has_roles =
            self.has_role(name1, domain) && self.has_role(name2, domain);

        let res = has_roles
            && if self.domain_matching_fn.is_some() {
                self.create_temp_role(name1, domain)
                    .has_role(name2, self.max_hierarchy_level)
            } else {
                self.create_role(name1, domain)
                    .read()
                    .has_role(name2, self.max_hierarchy_level)
            };

        #[cfg(feature = "cached")]
        self.cache.set(cache_key, res);

        res
    }

    fn get_roles(&mut self, name: &str, domain: Option<&str>) -> Vec<String> {
        if !self.has_role(name, domain) {
            return vec![];
        }

        self.create_temp_role(name, domain).get_roles()
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let matched_domains = self.matched_domains(domain);

        let res = matched_domains.iter().fold(HashSet::new(), |mut acc, x| {
            let users = self.all_domains.get(x).map_or(vec![], |roles| {
                roles
                    .values()
                    .filter_map(|role| {
                        let role = role.read();
                        if role.has_direct_role(name) {
                            Some(role.name.to_owned())
                        } else {
                            None
                        }
                    })
                    .collect()
            });
            acc.extend(users);
            acc
        });

        res.into_iter().collect()
    }

    fn clear(&mut self) {
        self.all_domains.clear();
        #[cfg(feature = "cached")]
        self.cache.clear();
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

    fn add_role(&mut self, other_role: Arc<RwLock<Role>>) -> bool {
        let not_exists = !self
            .roles
            .iter()
            .any(|role| Arc::ptr_eq(role, &other_role));

        if not_exists {
            self.roles.push(other_role);
        }

        not_exists
    }

    fn delete_role(&mut self, other_role: Arc<RwLock<Role>>) {
        let other_role_locked = other_role.read();

        self.roles
            .retain(|x| x.read().name != other_role_locked.name)
    }

    fn has_role(&self, name: &str, hierarchy_level: usize) -> bool {
        if self.name == name {
            return true;
        }

        if hierarchy_level == 0 {
            return false;
        }

        for role in self.roles.iter() {
            if role.read().has_role(name, hierarchy_level - 1) {
                return true;
            }
        }

        false
    }

    fn get_roles(&self) -> Vec<String> {
        self.roles
            .iter()
            .map(|role| role.read().name.to_owned())
            .collect()
    }

    fn has_direct_role(&self, name: &str) -> bool {
        self.roles.iter().any(|role| role.read().name == name)
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

        assert!(rm.has_role("u1", Some("domain2")));
    }
}
