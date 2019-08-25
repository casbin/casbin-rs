use objekt_clonable::*;

#[clonable]
pub trait RoleManager: Clone {
    //fn clone_box(&self) -> Box<dyn RoleManager>;
    fn clear(&mut self);
    fn add_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>);
    fn delete_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>);
    fn has_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) -> bool;
    fn get_roles(&mut self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn print_roles(&self);
}

// impl Clone for Box<dyn RoleManager> {
//     fn clone(&self) -> Self {
//         (*self).clone_box()
//     }
// }
