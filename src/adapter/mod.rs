use async_trait::async_trait;

pub mod file_adapter;
pub mod memory_adapter;

pub use file_adapter::FileAdapter;
pub use memory_adapter::MemoryAdapter;

use crate::model::Model;
use crate::Result;

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

#[async_trait]
impl<T: Adapter + ?Sized> Adapter for Box<T> {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        (**self).load_policy(m).await
    }
    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        (**self).save_policy(m).await
    }
    async fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        (**self).add_policy(sec, ptype, rule).await
    }
    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        (**self).add_policies(sec, ptype, rules).await
    }
    async fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        (**self).remove_policy(sec, ptype, rule).await
    }
    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        (**self).remove_policies(sec, ptype, rules).await
    }
    async fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        (**self)
            .remove_filtered_policy(sec, ptype, field_index, field_values)
            .await
    }
}
