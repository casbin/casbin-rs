use crate::Result;

pub trait RoleManager: Send + Sync {
    fn clear(&mut self);
    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>);
    fn delete_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> Result<()>;
    fn has_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> bool;
    fn get_roles(&mut self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String>;
}
