// policy data store in memory
use crate::adapter::Adapter;
use crate::model::Model;

use std::collections::HashSet;

#[derive(Default)]
pub struct MemoryAdapter {
    pub policy: HashSet<Vec<String>>,
}

impl Adapter for MemoryAdapter {
    fn load_policy(&self, m: &mut Model) {
        for line in self.policy.iter() {
            let sec = line[0].clone();
            let ptype = line[1].clone();
            let rule = line[1..].to_vec().clone();
            if let Some(t1) = m.model.get_mut(&sec) {
                if let Some(t2) = t1.get_mut(&ptype) {
                    t2.policy.push(rule);
                }
            }
        }
    }

    fn save_policy(&self, m: &mut Model) {
        panic!("to be done");
    }

    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        let mut line: Vec<String> = rule.into_iter().map(String::from).collect();
        line.insert(0, ptype.to_owned());
        line.insert(0, sec.to_owned());
        if self.policy.insert(line) {
            return true;
        }
        return false;
    }

    fn remove_policy(&self, _sec: String, _ptype: String, _rule: Vec<String>) {
        panic!("to be done");
    }
    fn remove_filtered_policy(
        &self,
        _sec: String,
        _ptype: String,
        _field_index: usize,
        _field_values: Option<Vec<String>>,
    ) {
        panic!("to be done");
    }
}
