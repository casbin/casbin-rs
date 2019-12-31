pub mod file_adapter;
pub mod memory_adapter;

pub use file_adapter::FileAdapter;
pub use memory_adapter::MemoryAdapter;

use crate::errors::RuntimeError;
use crate::model::Model;

pub trait Adapter {
    fn load_policy(&self, m: &mut Model) -> Result<(), RuntimeError>;
    fn save_policy(&self, m: &mut Model) -> Result<(), RuntimeError>;
    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>)
        -> Result<bool, RuntimeError>;
    fn remove_policy(&self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool, RuntimeError>;
    fn remove_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool, RuntimeError>;
}
