pub mod file_adapter;
pub mod memory_adapter;

pub use file_adapter::FileAdapter;
pub use memory_adapter::MemoryAdapter;

use crate::model::Model;
use crate::Result;

pub trait Adapter: Send + Sync {
    fn load_policy(&self, m: &mut Model) -> Result<()>;
    fn save_policy(&self, m: &mut Model) -> Result<()>;
    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool>;
    fn remove_policy(&self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool>;
    fn remove_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
}
