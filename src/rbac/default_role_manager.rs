use crate::{error::RbacError, rbac::RoleManager, Result};

#[cfg(feature = "cached")]
use crate::cache::{Cache, DefaultCache};

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

const DEFAULT_DOMAIN: &str = "DEFAULT";

pub struct DefaultRoleManager {
    all_domains: HashMap<String, HashMap<String, Arc<RwLock<Role>>>>,
    #[cfg(feature = "cached")]
    cache: DefaultCache<(String, String, Option<String>), bool>,
    max_hierarchy_level: usize,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            all_domains: HashMap::new(),
            max_hierarchy_level,
            #[cfg(feature = "cached")]
            cache: DefaultCache::new(50),
        }
    }

    fn create_role(
        &mut self,
        name: &str,
        domain: Option<&str>,
    ) -> Arc<RwLock<Role>> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        Arc::clone(
            self.all_domains
                .entry(domain.into())
                .or_insert_with(HashMap::new)
                .entry(name.into())
                .or_insert_with(|| Arc::new(RwLock::new(Role::new(name)))),
        )
    }

    fn has_role(&self, name: &str, domain: Option<&str>) -> bool {
        self.all_domains
            .get(domain.unwrap_or(DEFAULT_DOMAIN))
            .map_or(false, |roles| roles.contains_key(name))
    }
}

impl RoleManager for DefaultRoleManager {
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) {
        let role1 = self.create_role(name1, domain);
        let role2 = self.create_role(name2, domain);

        role1.write().unwrap().add_role(role2);

        #[cfg(feature = "cached")]
        self.cache.clear();
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

        role1.write().unwrap().delete_role(role2);

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
        let cache_key = (
            name1.to_owned(),
            name2.to_owned(),
            domain.map(|x| x.to_owned()),
        );

        #[cfg(feature = "cached")]
        if let Some(res) = self.cache.get(&cache_key) {
            return res.into_owned();
        }

        #[allow(clippy::let_and_return)]
        let res = self.has_role(name1, domain)
            && self.has_role(name2, domain)
            && self
                .create_role(name1, domain)
                .read()
                .unwrap()
                .has_role(name2, self.max_hierarchy_level);

        #[cfg(feature = "cached")]
        self.cache.set(cache_key, res);

        res
    }

    fn get_roles(&mut self, name: &str, domain: Option<&str>) -> Vec<String> {
        if !self.has_role(name, domain) {
            return vec![];
        }

        self.create_role(name, domain).read().unwrap().get_roles()
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        self.all_domains
            .get(domain.unwrap_or(DEFAULT_DOMAIN))
            .map_or(vec![], |roles| {
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
            })
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

    fn add_role(&mut self, other_role: Arc<RwLock<Role>>) {
        if self.roles.iter().any(|role| {
            role.read().unwrap().name == other_role.read().unwrap().name
        }) {
            return;
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
}
