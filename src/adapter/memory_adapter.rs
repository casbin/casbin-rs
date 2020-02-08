use crate::adapter::Adapter;
use crate::model::Model;
use crate::Result;

use std::collections::HashSet;

use async_trait::async_trait;

#[derive(Default)]
pub struct MemoryAdapter {
    pub policy: HashSet<Vec<String>>,
}

#[async_trait]
impl Adapter for MemoryAdapter {
    async fn load_policy(&self, m: &mut Model) -> Result<()> {
        for line in self.policy.iter() {
            let sec = line[0].clone();
            let ptype = line[1].clone();
            let rule = line[1..].to_vec().clone();
            if let Some(t1) = m.model.get_mut(&sec) {
                if let Some(t2) = t1.get_mut(&ptype) {
                    t2.policy.insert(rule);
                }
            }
        }
        Ok(())
    }

    async fn save_policy(&self, _m: &mut Model) -> Result<()> {
        unimplemented!();
    }

    async fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        let mut line: Vec<String> = rule.into_iter().map(String::from).collect();
        line.insert(0, ptype.to_owned());
        line.insert(0, sec.to_owned());
        if self.policy.insert(line) {
            return Ok(true);
        }
        Ok(false)
    }

    async fn remove_policy(&self, _sec: &str, _ptype: &str, _rule: Vec<&str>) -> Result<bool> {
        Ok(true)
    }

    async fn remove_filtered_policy(
        &self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<&str>,
    ) -> Result<bool> {
        Ok(true)
    }
}
