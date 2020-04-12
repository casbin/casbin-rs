use crate::{adapter::Adapter, model::Model, Result};

use async_trait::async_trait;

pub struct NullAdapter;

#[async_trait]
impl Adapter for NullAdapter {
    async fn load_policy(&self, _m: &mut dyn Model) -> Result<()> {
        Ok(())
    }

    async fn save_policy(&mut self, _m: &mut dyn Model) -> Result<()> {
        Ok(())
    }

    async fn add_policy(&mut self, _sec: &str, _ptype: &str, _rule: Vec<String>) -> Result<bool> {
        Ok(true)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }
}
