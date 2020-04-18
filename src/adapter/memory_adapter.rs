use crate::{
    adapter::{Adapter, Filter},
    model::Model,
    Result,
};

use async_trait::async_trait;
use indexmap::IndexSet;

#[derive(Default)]
pub struct MemoryAdapter {
    policy: IndexSet<Vec<String>>,
    is_filtered: bool,
}

#[async_trait]
impl Adapter for MemoryAdapter {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        for line in self.policy.iter() {
            let sec = line[0].clone();
            let ptype = line[1].clone();
            let rule = line[1..].to_vec().clone();
            if let Some(t1) = m.get_mut_model().get_mut(&sec) {
                if let Some(t2) = t1.get_mut(&ptype) {
                    t2.get_mut_policy().insert(rule);
                }
            }
        }
        Ok(())
    }

    async fn load_filtered_policy(&mut self, m: &mut dyn Model, f: Filter) -> Result<()> {
        for line in self.policy.iter() {
            let sec = line[0].clone();
            let ptype = line[1].clone();
            let rule = line[1..].to_vec().clone();
            let mut is_filtered = false;

            if &sec == "p" {
                for (i, r) in f.p.iter().enumerate() {
                    if !r.is_empty() && r != &rule[i + 1] {
                        is_filtered = true;
                    }
                }
            }
            if &sec == "g" {
                for (i, r) in f.g.iter().enumerate() {
                    if !r.is_empty() && r != &rule[i + 1] {
                        is_filtered = true;
                    }
                }
            }
            if !is_filtered {
                if let Some(t1) = m.get_mut_model().get_mut(&sec) {
                    if let Some(t2) = t1.get_mut(&ptype) {
                        t2.get_mut_policy().insert(rule);
                    }
                }
            } else {
                self.is_filtered = true;
            }
        }
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        self.policy.clear();

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                if let Some(sec) = ptype.chars().next().map(|x| x.to_string()) {
                    for policy in ast.get_policy() {
                        let mut rule = policy.clone();
                        rule.insert(0, ptype.clone());
                        rule.insert(0, sec.clone());
                        self.policy.insert(rule);
                    }
                }
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                if let Some(sec) = ptype.chars().next().map(|x| x.to_string()) {
                    for policy in ast.get_policy() {
                        let mut rule = policy.clone();
                        rule.insert(0, ptype.clone());
                        rule.insert(0, sec.clone());
                        self.policy.insert(rule);
                    }
                }
            }
        }

        Ok(())
    }

    async fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let mut line: Vec<String> = rule.into_iter().map(String::from).collect();
        line.insert(0, ptype.to_owned());
        line.insert(0, sec.to_owned());

        Ok(self.policy.insert(line))
    }

    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut all_added = true;
        let mut rules_added = vec![];
        for rule in rules {
            if !self.add_policy(sec, ptype, rule.clone()).await? {
                all_added = false;
                break;
            } else {
                rules_added.push(rule);
            }
        }
        if !all_added && !rules_added.is_empty() {
            for rule in rules_added {
                self.remove_policy(sec, ptype, rule).await?;
            }
        }
        Ok(all_added)
    }

    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut all_removed = true;
        let mut rules_removed = vec![];
        for rule in rules {
            if !self.remove_policy(sec, ptype, rule.clone()).await? {
                all_removed = false;
                break;
            } else {
                rules_removed.push(rule);
            }
        }
        if !all_removed && !rules_removed.is_empty() {
            for rule in rules_removed {
                self.add_policy(sec, ptype, rule).await?;
            }
        }
        Ok(all_removed)
    }

    async fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let mut rule: Vec<String> = rule.into_iter().map(String::from).collect();
        rule.insert(0, ptype.to_owned());
        rule.insert(0, sec.to_owned());

        Ok(self.policy.remove(&rule))
    }

    async fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        let mut tmp = IndexSet::new();
        let mut res = false;
        for rule in &self.policy {
            if sec == rule[0] && ptype == rule[1] {
                let mut matched = true;
                for (i, field_value) in field_values.iter().enumerate() {
                    if !field_value.is_empty() && &rule[field_index + i + 2] != field_value {
                        matched = false;
                        break;
                    }
                }

                if matched {
                    res = true;
                } else {
                    tmp.insert(rule.clone());
                }
            } else {
                tmp.insert(rule.clone());
            }
        }
        self.policy = tmp;

        Ok(res)
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }
}
