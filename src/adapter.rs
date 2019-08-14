pub mod file_adapter;
pub mod memory_adapter;

pub use file_adapter::FileAdapter;
pub use memory_adapter::MemoryAdapter;

use crate::model::Model;

pub trait Adapter {
    fn load_policy(&self, m: &mut Model);
    fn save_policy(&self, m: &mut Model);
    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool;
    fn remove_policy(&self, sec: String, ptype: String, rule: Vec<String>);
    fn remove_filtered_policy(
        &self,
        sec: String,
        ptype: String,
        field_index: usize,
        field_values: Option<Vec<String>>,
    );
}
