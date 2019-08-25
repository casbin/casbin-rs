use crate::rbac::RoleManager;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

type MatchingFunc = fn(&str, &str) -> bool;

#[derive(Clone)]
pub struct DefaultRoleManager {
    pub all_roles: HashMap<String, Rc<RefCell<Role>>>,
    pub max_hierarchy_level: usize,
    pub has_pattern: bool,
    pub matching_func: Option<MatchingFunc>,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level,
            has_pattern: false,
            matching_func: None,
        }
    }

    fn create_role(&mut self, name: &str) -> Rc<RefCell<Role>> {
        self.all_roles
            .entry(name.to_owned())
            .or_insert_with(|| Rc::new(RefCell::new(Role::new(name.to_owned()))))
            .clone()
    }

    fn has_role(&self, name: &str) -> bool {
        self.all_roles.contains_key(name)
    }
}

impl RoleManager for DefaultRoleManager {
    fn clone_box(&self) -> Box<dyn RoleManager> {
        Box::new(self.clone())
    }

    fn add_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>) {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if domain.len() == 1 {
            name1 = format!("{}::{}", domain[0], name1);
            name2 = format!("{}::{}", domain[0], name2);
        } else if domain.len() > 1 {
            panic!("error domain length");
        }
        let role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);
        role1.borrow_mut().add_role(role2);
    }

    fn delete_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>) {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if domain.len() == 1 {
            name1 = format!("{}::{}", domain[0], name1);
            name2 = format!("{}::{}", domain[0], name2);
        } else if domain.len() > 1 {
            panic!("error domain length");
        }
        if !self.has_role(&name1) || !self.has_role(&name2) {
            panic!("name12 error");
        }
        let role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);
        role1.borrow_mut().delete_role(role2);
    }

    fn has_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> bool {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if let Some(domain_val) = domain {
            name1 = format!("{}::{}", domain_val, name1);
            name2 = format!("{}::{}", domain_val, name2);
        }
        if name1 == name2 {
            return true;
        }
        if !self.has_role(&name1) || !self.has_role(&name2) {
            return false;
        }
        self.create_role(&name1)
            .borrow()
            .has_role(&name2, self.max_hierarchy_level)
    }

    fn get_roles(&mut self, name: &str, domain: Option<&str>) -> Vec<String> {
        let mut name = name.to_owned();
        if let Some(domain_val) = domain {
            name = format!("{}::{}", domain_val, name);
        }
        if !self.has_role(&name) {
            return vec![];
        }
        let role = self.create_role(&name);

        if let Some(domain_val) = domain {
            role.borrow()
                .get_roles()
                .iter()
                .map(|x| x[domain_val.len() + 2..].to_string())
                .collect()
        } else {
            role.borrow().get_roles()
        }
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let mut name = name.to_owned();
        if let Some(domain_val) = domain {
            name = format!("{}::{}", domain_val, name);
        }
        if !self.has_role(&name) {
            return vec![];
        }

        let mut names: Vec<String> = vec![];
        for (_key, role) in self.all_roles.iter() {
            if role.borrow().has_direct_role(&name) {
                names.push(role.borrow().name.clone());
            }
        }
        if let Some(domain_val) = domain {
            return names
                .iter()
                .map(|x| x[domain_val.len() + 2..].to_string())
                .collect();
        }
        names
    }

    fn print_roles(&self) {
        println!("current role manager roles: {:?}", self.all_roles.clone());
    }

    fn clear(&mut self) {
        self.all_roles = HashMap::new();
    }
}

#[derive(Clone, Debug)]
pub struct Role {
    name: String,
    roles: Vec<Rc<RefCell<Role>>>,
}

impl Role {
    fn new(name: String) -> Self {
        Role {
            name,
            roles: vec![],
        }
    }

    fn add_role(&mut self, other_role: Rc<RefCell<Role>>) {
        if self
            .roles
            .iter()
            .any(|role| role.borrow().name == other_role.borrow().name)
        {
            return;
        }
        self.roles.push(other_role);
    }

    fn delete_role(&mut self, other_role: Rc<RefCell<Role>>) {
        if let Some(pos) = self
            .roles
            .iter()
            .position(|x| x.borrow().name == other_role.borrow().name)
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
            if role.borrow().has_role(name, hierarchy_level - 1) {
                return true;
            }
        }
        false
    }

    fn get_roles(&self) -> Vec<String> {
        self.roles
            .iter()
            .map(|role| role.borrow().name.clone())
            .collect()
    }

    fn has_direct_role(&self, name: &str) -> bool {
        for role in self.roles.iter() {
            if role.borrow().name == name {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", vec![]);
        rm.add_link("u2", "g1", vec![]);
        rm.add_link("u3", "g2", vec![]);
        rm.add_link("u4", "g2", vec![]);
        rm.add_link("u4", "g3", vec![]);
        rm.add_link("g1", "g3", vec![]);

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
        rm.delete_link("g1", "g3", vec![]);
        rm.delete_link("u4", "g2", vec![]);
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
        rm.add_link("u1", "g1", vec![]);
        rm.add_link("u2", "g1", vec![]);
        rm.add_link("u3", "g2", vec![]);
        rm.add_link("u4", "g2", vec![]);
        rm.add_link("u4", "g3", vec![]);
        rm.add_link("g1", "g3", vec![]);

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
        rm.add_link("u1", "g1", vec!["domain1"]);
        rm.add_link("u2", "g1", vec!["domain1"]);
        rm.add_link("u3", "admin", vec!["domain2"]);
        rm.add_link("u4", "admin", vec!["domain2"]);
        rm.add_link("u4", "admin", vec!["domain1"]);
        rm.add_link("g1", "admin", vec!["domain1"]);

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

        rm.delete_link("g1", "admin", vec!["domain1"]);
        rm.delete_link("u4", "admin", vec!["domain2"]);

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
}
