use async_trait::async_trait;

pub mod file_adapter;
pub mod memory_adapter;

pub use file_adapter::FileAdapter;
pub use memory_adapter::MemoryAdapter;

use crate::model::Model;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterType {
    File,
    Memory,
    // relates to TODO in `Enforcer::new`
    Filter,
    Diesel,
}

#[async_trait]
pub trait Adapter: Send + Sync {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()>;
    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()>;
    async fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool>;
    async fn add_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<&str>>)
        -> Result<bool>;
    async fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool>;
    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<&str>>,
    ) -> Result<bool>;
    async fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
    fn adapter_type(&self) -> AdapterType;
}
