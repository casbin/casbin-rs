use async_trait::async_trait;

#[cfg(not(target_arch = "wasm32"))]
pub mod file_adapter;
pub mod memory_adapter;
pub mod null_adapter;

#[cfg(not(target_arch = "wasm32"))]
pub use file_adapter::FileAdapter;
pub use memory_adapter::MemoryAdapter;
pub use null_adapter::NullAdapter;

use crate::{model::Model, Result};

#[derive(Clone)]
pub struct Filter<'a> {
    pub p: Vec<&'a str>,
    pub g: Vec<&'a str>,
}

#[async_trait]
pub trait Adapter: Send + Sync {
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()>;
    async fn load_filtered_policy<'a>(
        &mut self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<()>;
    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()>;
    async fn clear_policy(&mut self) -> Result<()>;
    fn is_filtered(&self) -> bool;
    async fn add_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
}
