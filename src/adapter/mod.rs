use crate::{model::Model, Result};

pub mod file_adapter;
pub mod memory_adapter;
pub mod null_adapter;

pub use file_adapter::FileAdapter;
pub use memory_adapter::MemoryAdapter;
pub use null_adapter::NullAdapter;

use async_trait::async_trait;

#[async_trait]
pub trait Adapter: Send + Sync {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()>;
    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()>;
    async fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool>;
    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool>;
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

#[cfg(feature = "filtered-adapter")]
#[derive(Clone, Debug)]
pub struct Filter {
    pub p: Vec<String>,
    pub g: Vec<String>,
}

#[cfg(feature = "filtered-adapter")]
#[async_trait]
pub trait FilteredAdapter: Adapter {
    async fn load_filtered_policy(&mut self, m: &mut dyn Model, _f: Option<Filter>) -> Result<()>;

    fn is_filtered(&self) -> bool;
}

#[cfg(feature = "filtered-adapter")]
#[async_trait]
impl<T> FilteredAdapter for T
where
    T: Adapter,
{
    default async fn load_filtered_policy(
        &mut self,
        m: &mut dyn Model,
        _f: Option<Filter>,
    ) -> Result<()> {
        self.load_policy(m).await
    }

    default fn is_filtered(&self) -> bool {
        false
    }
}
