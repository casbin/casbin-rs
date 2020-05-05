use crate::{error::RbacError, rbac::RoleManager, Result};

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct DefaultRoleManager {
    all_roles: HashMap<String, Arc<RwLock<Role>>>,
    max_hierarchy_level: usize,
    matching_fn: Option<fn(String, String) -> bool>,
}

impl Default for DefaultRoleManager {
    fn default() -> Self {
        DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level: 0,
            matching_fn: None,
        }
    }
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level,
            matching_fn: None,
        }
    }

    fn create_role(&mut self, name: &str) -> Arc<RwLock<Role>> {
        let role = Arc::clone(
            self.all_roles
                .entry(name.to_owned())
                .or_insert_with(|| Arc::new(RwLock::new(Role::new(name.to_owned())))),
        );

        if let Some(matching_fn) = self.matching_fn {
            for (_, r) in &mut self.all_roles.iter().filter(|(k, r)| {
                k.as_str() != name
                    && matching_fn(name.to_owned(), (*k).to_owned())
                    && !r.read().unwrap().has_direct_role(name)
            }) {
                role.write().unwrap().add_role(Arc::clone(r));
            }
        }

        role
    }

    fn has_role(&self, name: &str) -> bool {
        if let Some(matching_fn) = self.matching_fn {
            self.all_roles
                .iter()
                .any(|(r, _)| matching_fn(name.to_owned(), r.to_owned()))
        } else {
            self.all_roles.contains_key(name)
        }
    }
}

impl RoleManager for DefaultRoleManager {
    fn add_matching_fn(&mut self, matching_fn: fn(String, String) -> bool) {
        self.matching_fn = Some(matching_fn);
    }

    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if let Some(domain) = domain {
            name1 = format!("{}::{}", domain, name1);
            name2 = format!("{}::{}", domain, name2);
        }
        let role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);

        role1.write().unwrap().add_role(Arc::clone(&role2));
        if role2.read().unwrap().has_direct_role(&name1) {
            role2.write().unwrap().delete_role(role1);
        }
    }

    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<()> {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if let Some(domain) = domain {
            name1 = format!("{}::{}", domain, name1);
            name2 = format!("{}::{}", domain, name2);
        }
        if !self.has_role(&name1) || !self.has_role(&name2) {
            return Err(RbacError::NotFound(format!("{} OR {}", name1, name2)).into());
        }
        let role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);
        role1.write().unwrap().delete_role(role2);
        Ok(())
    }

    fn has_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> bool {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if let Some(domain) = domain {
            name1 = format!("{}::{}", domain, name1);
            name2 = format!("{}::{}", domain, name2);
        }
        if name1 == name2 {
            return true;
        }
        if !self.has_role(&name1) || !self.has_role(&name2) {
            return false;
        }
        self.create_role(&name1)
            .write()
            .unwrap()
            .has_role(&name2, self.max_hierarchy_level)
    }

    fn get_roles(&mut self, name: &str, domain: Option<&str>) -> Vec<String> {
        let mut name = name.to_owned();
        if let Some(domain) = domain {
            name = format!("{}::{}", domain, name);
        }
        if !self.has_role(&name) {
            return vec![];
        }
        let role = self.create_role(&name);

        if let Some(domain) = domain {
            role.read()
                .unwrap()
                .get_roles()
                .iter()
                .map(|x| x[domain.len() + 2..].to_string())
                .collect()
        } else {
            role.read().unwrap().get_roles()
        }
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let mut name = name.to_owned();
        if let Some(domain) = domain {
            name = format!("{}::{}", domain, name);
        }
        if !self.has_role(&name) {
            return vec![];
        }

        let mut names: Vec<String> = vec![];
        for role in self.all_roles.values() {
            if role.read().unwrap().has_direct_role(&name) {
                names.push(role.read().unwrap().name.clone());
            }
        }

        if let Some(domain) = domain {
            return names
                .iter()
                .map(|x| x[domain.len() + 2..].to_string())
                .collect();
        }
        names
    }

    fn clear(&mut self) {
        self.all_roles.clear();
    }

    fn print_roles(&self) {
        #[cfg(feature = "logging")]
        {
            println!("{:?}", self.all_roles);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Role {
    name: String,
    roles: Vec<Arc<RwLock<Role>>>,
}

impl Role {
    fn new(name: String) -> Self {
        Role {
            name,
            roles: vec![],
        }
    }

    fn add_role(&mut self, other_role: Arc<RwLock<Role>>) {
        if self
            .roles
            .iter()
            .any(|role| role.read().unwrap().name == other_role.read().unwrap().name)
        {
            return;
        }
        self.roles.push(other_role);
    }

    fn delete_role(&mut self, other_role: Arc<RwLock<Role>>) {
        if let Some(pos) = self
            .roles
            .iter()
            .position(|x| x.read().unwrap().name == other_role.read().unwrap().name)
        {
            self.roles.remove(pos);
        }
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
            .map(|role| role.read().unwrap().name.clone())
            .collect()
    }

    fn has_direct_role(&self, name: &str) -> bool {
        for role in self.roles.iter() {
            if role.read().unwrap().name == name {
                return true;
            }
        }
        false
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
        assert_eq!(vec!["g2", "g3"], rm.get_roles("u4", None));
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
