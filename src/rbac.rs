pub trait RoleManager {
    fn clone_box(&self) -> Box<dyn RoleManager>;
    fn clear(&mut self);
    fn add_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>);
    fn delete_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>);
    fn has_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>) -> bool;
    fn get_roles(&self, name: &str, domain: Vec<&str>) -> Vec<&str>;
    fn get_users(&self, name: &str, domain: Vec<&str>) -> Vec<&str>;
    fn print_roles(&self);
}

impl Clone for Box<dyn RoleManager> {
    fn clone(&self) -> Self {
        (*self).clone_box()
    }
}

use std::collections::HashMap;

type MatchingFunc = fn(&str, &str) -> bool;

#[derive(Clone)]
pub struct DefaultRoleManager {
    pub all_roles: HashMap<String, Role>,
    pub max_hierarchy_level: usize,
    pub has_pattern: bool,
    pub matching_func: Option<MatchingFunc>,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        return DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level,
            has_pattern: false,
            matching_func: None,
        };
    }

    fn create_role(&mut self, name: &str) -> Role {
        return self
            .all_roles
            .entry(name.to_owned())
            .or_insert(Role::new(name.to_owned()))
            .clone();
    }

    fn has_role(&self, name: &str) -> bool {
        if let Some(_role) = self.all_roles.get(name) {
            return true;
        }
        return false;
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
        let mut role1 = self.create_role(name1.as_str());
        let role2 = self.create_role(name2.as_str());
        role1.add_role(role2);
        // role1 is updated and should be updated into all_roles
        if let Some(old_role) = self.all_roles.get_mut(&role1.name) {
            *old_role = role1.clone();
        }
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
        let mut role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);
        role1.delete_role(role2);
        // role1 is updated and should be updated into all_roles
        if let Some(old_role) = self.all_roles.get_mut(&role1.name) {
            *old_role = role1.clone();
        }
    }

    fn has_link(&mut self, name1: &str, name2: &str, _domain: Vec<&str>) -> bool {
        if name1 == name2 {
            return true;
        }
        if !self.has_role(name1) || !self.has_role(name2) {
            return false;
        }
        let role1 = self.create_role(name1);
        return role1.has_role(name2, self.max_hierarchy_level);
    }

    fn get_roles(&self, name: &str, domain: Vec<&str>) -> Vec<&str> {
        return vec![];
    }

    fn get_users(&self, name: &str, domain: Vec<&str>) -> Vec<&str> {
        return vec![];
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
    pub name: String,
    pub roles: Vec<Role>,
}

impl Role {
    pub fn new(name: String) -> Self {
        return Role {
            name,
            roles: vec![],
        };
    }

    pub fn add_role(&mut self, other_role: Role) {
        for role in self.roles.iter() {
            if role.name == other_role.name {
                return;
            }
        }
        self.roles.push(other_role.clone());
    }

    fn delete_role(&mut self, other_role: Role) {
        if let Some(pos) = self
            .roles
            .iter()
            .cloned()
            .position(|x| x.name == other_role.name)
        {
            self.roles.remove(pos);
        }
    }

    fn has_role(&self, name: &str, hierarchy_level: usize) -> bool {
        if self.name == name {
            return true;
        }
        if hierarchy_level <= 0 {
            return false;
        }
        for role in self.roles.iter() {
            if role.has_role(name, hierarchy_level - 1) {
                return true;
            }
        }
        return false;
    }
}
