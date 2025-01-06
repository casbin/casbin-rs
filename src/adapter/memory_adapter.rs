use crate::{
    adapter::{Adapter, Filter},
    model::Model,
    util::parse_csv_line,
    Result,
};

use async_trait::async_trait;
use hashlink::LinkedHashSet;

use super::StringAdapter;

#[derive(Default)]
pub struct MemoryAdapter {
    policy: LinkedHashSet<Vec<String>>,
    is_filtered: bool,
}

impl From<StringAdapter> for MemoryAdapter {
    fn from(string_adatpter: StringAdapter) -> Self {
        let string_policies = string_adatpter.policy.split("\n");
        let mut memory_adapter = Self {
            policy: LinkedHashSet::new(),
            is_filtered: false,
        };
        for line in string_policies {
            if let Some(tokens) = parse_csv_line(line) {
                let ptype = tokens[0].clone();
                if let Some(sec) =
                    ptype.chars().into_iter().next().map(|x| x.to_string())
                {
                    let mut rule = tokens[1..].to_vec();
                    rule.insert(0, ptype);
                    rule.insert(0, sec);
                    memory_adapter.policy.insert(rule);
                }
            }
        }
        memory_adapter
    }
}

impl MemoryAdapter {
    pub fn from_str(s: impl ToString) -> Self {
        let s = s.to_string();
        let string_adapter = StringAdapter::new(s);
        Self::from(string_adapter)
    }
}

#[async_trait]
impl Adapter for MemoryAdapter {
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        self.is_filtered = false;
        for line in self.policy.iter() {
            let sec = &line[0];
            let ptype = &line[1];
            let rule = line[2..].to_vec().clone();

            if let Some(t1) = m.get_mut_model().get_mut(sec) {
                if let Some(t2) = t1.get_mut(ptype) {
                    t2.get_mut_policy().insert(rule);
                }
            }
        }

        Ok(())
    }

    async fn load_filtered_policy<'a>(
        &mut self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<()> {
        for line in self.policy.iter() {
            let sec = &line[0];
            let ptype = &line[1];
            let rule = line[1..].to_vec().clone();
            let mut is_filtered = false;

            if sec == "p" {
                for (i, r) in f.p.iter().enumerate() {
                    if !r.is_empty() && r != &rule[i + 1] {
                        is_filtered = true;
                    }
                }
            }
            if sec == "g" {
                for (i, r) in f.g.iter().enumerate() {
                    if !r.is_empty() && r != &rule[i + 1] {
                        is_filtered = true;
                    }
                }
            }

            if !is_filtered {
                if let Some(ast_map) = m.get_mut_model().get_mut(sec) {
                    if let Some(ast) = ast_map.get_mut(ptype) {
                        ast.get_mut_policy().insert(rule);
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

    async fn clear_policy(&mut self) -> Result<()> {
        self.policy.clear();
        self.is_filtered = false;
        Ok(())
    }

    async fn add_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        mut rule: Vec<String>,
    ) -> Result<bool> {
        rule.insert(0, ptype.to_owned());
        rule.insert(0, sec.to_owned());

        Ok(self.policy.insert(rule))
    }

    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut all_added = true;
        let rules: Vec<Vec<String>> = rules
            .into_iter()
            .map(|mut rule| {
                rule.insert(0, ptype.to_owned());
                rule.insert(0, sec.to_owned());
                rule
            })
            .collect();

        for rule in &rules {
            if self.policy.contains(rule) {
                all_added = false;
                return Ok(all_added);
            }
        }
        self.policy.extend(rules);

        Ok(all_added)
    }

    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut all_removed = true;
        let rules: Vec<Vec<String>> = rules
            .into_iter()
            .map(|mut rule| {
                rule.insert(0, ptype.to_owned());
                rule.insert(0, sec.to_owned());
                rule
            })
            .collect();

        for rule in &rules {
            if !self.policy.contains(rule) {
                all_removed = false;
                return Ok(all_removed);
            }
        }
        for rule in &rules {
            self.policy.remove(rule);
        }

        Ok(all_removed)
    }

    async fn remove_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        mut rule: Vec<String>,
    ) -> Result<bool> {
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
        if field_values.is_empty() {
            return Ok(false);
        }

        let mut tmp = LinkedHashSet::new();
        let mut res = false;
        for rule in &self.policy {
            if sec == rule[0] && ptype == rule[1] {
                let mut matched = true;
                for (i, field_value) in field_values.iter().enumerate() {
                    if !field_value.is_empty()
                        && &rule[field_index + i + 2] != field_value
                    {
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

#[cfg(test)]
mod test {
    use hashlink::LinkedHashSet;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use crate::{
        adapter::StringAdapter, Adapter, CoreApi, DefaultModel, Enforcer,
        Filter, MemoryAdapter,
    };

    #[cfg_attr(
        all(not(target_arch = "wasm32"), feature = "runtime-async-std"),
        async_std::test
    )]
    #[cfg_attr(
        all(not(target_arch = "wasm32"), feature = "runtime-tokio"),
        tokio::test
    )]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_load_policy() {
        let policy = "p, alice, data1, read\np, bob, data2, write";
        let mut adapter = MemoryAdapter::from_str(policy);
        let mut model = DefaultModel::from_str(include_str!(
            "../../examples/rbac_model.conf"
        ))
        .await
        .unwrap();

        adapter.load_policy(&mut model).await.unwrap();
        let enforcer = Enforcer::new(model, adapter).await.unwrap();

        assert!(enforcer.enforce(("alice", "data1", "read")).unwrap());
        assert!(enforcer.enforce(("bob", "data2", "write")).unwrap());
        assert!(!enforcer.enforce(("alice", "data2", "read")).unwrap());
    }

    #[cfg_attr(
        all(not(target_arch = "wasm32"), feature = "runtime-async-std"),
        async_std::test
    )]
    #[cfg_attr(
        all(not(target_arch = "wasm32"), feature = "runtime-tokio"),
        tokio::test
    )]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_save_policy() {
        let policy = "p, alice, data1, read\np, bob, data2, write";
        let mut adapter = MemoryAdapter::from_str(policy);
        let mut model = DefaultModel::from_str(include_str!(
            "../../examples/rbac_model.conf"
        ))
        .await
        .unwrap();

        adapter.load_policy(&mut model).await.unwrap();
        adapter.save_policy(&mut model).await.unwrap();

        let mut expected = LinkedHashSet::new();
        expected.insert(
            vec!["p", "p", "alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        );
        expected.insert(
            vec!["p", "p", "bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        );

        assert_eq!(adapter.policy, expected);
    }

    #[cfg_attr(
        all(not(target_arch = "wasm32"), feature = "runtime-async-std"),
        async_std::test
    )]
    #[cfg_attr(
        all(not(target_arch = "wasm32"), feature = "runtime-tokio"),
        tokio::test
    )]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_compare_string_adapter() {
        let policy = "p, alice, data1, read\np, bob, data2, write";
        let mut string_adapter = StringAdapter::new(policy);
        let mut memory_adapter = MemoryAdapter::from_str(policy);
        let mut model = DefaultModel::from_str(include_str!(
            "../../examples/rbac_model.conf"
        ))
        .await
        .unwrap();

        assert_eq!(
            string_adapter.load_policy(&mut model).await.unwrap(),
            memory_adapter.load_policy(&mut model).await.unwrap()
        );

        let filter = Filter {
            p: vec!["alice"],
            g: vec![],
        };

        assert_eq!(
            string_adapter
                .load_filtered_policy(&mut model, filter.clone())
                .await
                .unwrap(),
            memory_adapter
                .load_filtered_policy(&mut model, filter)
                .await
                .unwrap(),
        );

        assert_eq!(string_adapter.is_filtered(), memory_adapter.is_filtered());

        let string_enforcer =
            Enforcer::new(model.clone(), string_adapter).await.unwrap();
        let memory_enforcer =
            Enforcer::new(model.clone(), memory_adapter).await.unwrap();

        assert_eq!(
            string_enforcer.enforce(("alice", "data1", "read")).unwrap(),
            memory_enforcer.enforce(("alice", "data1", "read")).unwrap()
        );
    }
}
