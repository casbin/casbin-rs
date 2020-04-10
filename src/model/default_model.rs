use crate::{
    config::Config,
    error::ModelError,
    model::{Assertion, AssertionMap, Model},
    rbac::RoleManager,
    util::*,
    Result,
};

use indexmap::IndexSet;

#[cfg(feature = "runtime-async-std")]
use async_std::path::Path;

#[cfg(feature = "runtime-tokio")]
use std::path::Path;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Clone, Default)]
pub struct DefaultModel {
    pub(crate) model: HashMap<String, AssertionMap>,
}

impl DefaultModel {
    pub async fn from_file<P: AsRef<Path>>(p: P) -> Result<DefaultModel> {
        let cfg = Config::from_file(p).await?;

        let mut model = DefaultModel::default();

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;

        model.load_section(&cfg, "g")?;

        Ok(model)
    }

    pub async fn from_str(&mut self, s: &str) -> Result<DefaultModel> {
        let cfg = Config::from_str(s).await?;

        let mut model = DefaultModel::default();

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;

        model.load_section(&cfg, "g")?;

        Ok(model)
    }

    fn load_section(&mut self, cfg: &Config, sec: &str) -> Result<()> {
        let mut i = 1;

        loop {
            if !self.load_assertion(cfg, sec, &format!("{}{}", sec, self.get_key_suffix(i)))? {
                break Ok(());
            } else {
                i += 1;
            }
        }
    }

    fn load_assertion(&mut self, cfg: &Config, sec: &str, key: &str) -> Result<bool> {
        let sec_name = match sec {
            "r" => "request_definition",
            "p" => "policy_definition",
            "g" => "role_definition",
            "e" => "policy_effect",
            "m" => "matchers",
            _ => {
                return Err(ModelError::Other(format!("Unknown section: `{}`", sec)).into());
            }
        };

        if let Some(val) = cfg.get_str(&format!("{}::{}", sec_name, key)) {
            Ok(self.add_def(sec, key, val))
        } else {
            Ok(false)
        }
    }

    fn get_key_suffix(&self, i: u64) -> String {
        if i == 1 {
            "".to_owned()
        } else {
            i.to_string()
        }
    }
}

impl Model for DefaultModel {
    fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool {
        let mut ast = Assertion::default();
        ast.key = key.to_owned();
        ast.value = remove_comments(value.to_owned());

        if ast.value.is_empty() {
            return false;
        }

        if sec == "r" || sec == "p" {
            ast.tokens = ast
                .value
                .split(',')
                .map(|x| format!("{}_{}", key, x.trim()))
                .collect();
        } else {
            ast.value = escape_g_function(ast.value);
            ast.value = escape_assertion(ast.value);
        }

        if let Some(new_model) = self.model.get_mut(sec) {
            new_model.insert(key.to_owned(), ast);
        } else {
            let mut new_ast_map = HashMap::new();
            new_ast_map.insert(key.to_owned(), ast);
            self.model.insert(sec.to_owned(), new_ast_map);
        }

        true
    }

    #[inline]
    fn get_model(&self) -> &HashMap<String, AssertionMap> {
        &self.model
    }

    #[inline]
    fn get_mut_model(&mut self) -> &mut HashMap<String, AssertionMap> {
        &mut self.model
    }

    fn build_role_links(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()> {
        if let Some(asts) = self.model.get_mut("g") {
            for ast in asts.values_mut() {
                ast.build_role_links(Arc::clone(&rm))?;
            }
        }
        Ok(())
    }

    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                return t2
                    .policy
                    .insert(rule.into_iter().map(String::from).collect());
            }
        }
        false
    }

    fn add_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> bool {
        let mut all_added = true;
        let mut rules_added = vec![];
        for rule in rules {
            if !self.add_policy(sec, ptype, rule.clone()) {
                all_added = false;
                break;
            } else {
                rules_added.push(rule);
            }
        }
        if !all_added && !rules_added.is_empty() {
            for rule in rules_added {
                self.remove_policy(sec, ptype, rule);
            }
        }
        all_added
    }

    fn get_policy(&self, sec: &str, ptype: &str) -> Vec<Vec<String>> {
        if let Some(t1) = self.model.get(sec) {
            if let Some(t2) = t1.get(ptype) {
                return t2.policy.iter().map(|x| x.to_owned()).collect();
            }
        }
        vec![]
    }

    fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        let mut res = vec![];
        if let Some(t1) = self.model.get(sec) {
            if let Some(t2) = t1.get(ptype) {
                for rule in t2.policy.iter() {
                    let mut matched = true;
                    for (i, field_value) in field_values.iter().enumerate() {
                        if !field_value.is_empty() && &rule[field_index + i] != field_value {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res.push(rule.iter().map(String::from).collect());
                    }
                }
            }
        }
        res
    }

    fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        let policy = self.get_policy(sec, ptype);
        for r in policy {
            if r == rule {
                return true;
            }
        }
        false
    }

    fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
    ) -> Vec<String> {
        self.get_policy(sec, ptype)
            .into_iter()
            .fold(IndexSet::new(), |mut acc, x| {
                acc.insert(x[field_index].clone());
                acc
            })
            .into_iter()
            .collect()
    }

    fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                return t2.policy.remove(&rule);
            }
        }
        false
    }

    fn remove_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> bool {
        let mut all_removed = true;
        let mut rules_removed = vec![];
        for rule in rules {
            if !self.remove_policy(sec, ptype, rule.clone()) {
                all_removed = false;
                break;
            } else {
                rules_removed.push(rule);
            }
        }
        if !all_removed && !rules_removed.is_empty() {
            for rule in rules_removed {
                self.add_policy(sec, ptype, rule);
            }
        }
        all_removed
    }

    fn clear_policy(&mut self) {
        if let Some(model_p) = self.model.get_mut("p") {
            for ast in model_p.values_mut() {
                ast.policy.clear();
            }
        }

        if let Some(model_g) = self.model.get_mut("g") {
            for ast in model_g.values_mut() {
                ast.policy.clear();
            }
        }
    }

    fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> bool {
        let mut res = false;
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                let mut tmp: IndexSet<Vec<String>> = IndexSet::new();
                for rule in t2.policy.iter() {
                    let mut matched = true;
                    for (i, field_value) in field_values.iter().enumerate() {
                        if !field_value.is_empty() && &rule[field_index + i] != field_value {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res = true;
                    } else {
                        tmp.insert(rule.clone());
                    }
                }
                t2.policy = tmp;
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_basic_model() {
        let m = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(&vec!["alice", "data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data2", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["bob", "data2", "write"]).await.unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_basic_model_no_policy() {
        let m = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert!(!e.enforce(&vec!["alice", "data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data2", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data2", "write"]).await.unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_basic_model_with_root() {
        let m = DefaultModel::from_file("examples/basic_with_root_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(&vec!["alice", "data1", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["bob", "data2", "write"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data1", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data1", "write"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data2", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data2", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data2", "read"]).await.unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_basic_model_with_root_no_policy() {
        let m = DefaultModel::from_file("examples/basic_with_root_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert!(!e.enforce(&vec!["alice", "data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data2", "write"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data1", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data1", "write"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data2", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["root", "data2", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "data2", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "data2", "read"]).await.unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_basic_model_without_users() {
        let m = DefaultModel::from_file("examples/basic_without_users_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_without_users_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(&vec!["data1", "read"]).await.unwrap());
        assert!(!e.enforce(&vec!["data1", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["data2", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["data2", "write"]).await.unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_basic_model_without_resources() {
        let m = DefaultModel::from_file("examples/basic_without_resources_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_without_resources_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(&vec!["alice", "read"]).await.unwrap());
        assert!(e.enforce(&vec!["bob", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["alice", "write"]).await.unwrap());
        assert!(!e.enforce(&vec!["bob", "read"]).await.unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_with_resource_roles() {
        let m = DefaultModel::from_file("examples/rbac_with_resource_roles_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_resource_roles_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_with_domains() {
        let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "domain1", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "domain1", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "write"])
                .await
                .unwrap()
        );
    }

    use crate::MgmtApi;
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_with_domains_runtime() {
        let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_policy(
            vec!["admin", "domain1", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["admin", "domain1", "data1", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["admin", "domain2", "data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["admin", "domain2", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        e.add_grouping_policy(
            vec!["alice", "admin", "domain1"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["bob", "admin", "domain2"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "domain1", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "domain1", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "write"])
                .await
                .unwrap()
        );

        assert_eq!(
            true,
            e.remove_filtered_policy(
                1,
                vec!["domain1", "data1"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
            .await
            .unwrap()
        );

        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "write"])
                .await
                .unwrap()
        );

        assert_eq!(
            true,
            e.remove_policy(
                vec!["admin", "domain2", "data2", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
            .await
            .unwrap()
        );

        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data2", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "write"])
                .await
                .unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_with_domains_at_runtime_mock_adapter() {
        let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        e.add_policy(
            vec!["admin", "domain3", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["alice", "admin", "domain3"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "domain3", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "domain1", "data1", "read"])
                .await
                .unwrap()
        );

        e.remove_filtered_policy(
            1,
            vec!["domain1", "data1"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "domain1", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "domain2", "data2", "read"])
                .await
                .unwrap()
        );

        e.remove_policy(
            vec!["admin", "domain2", "data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "domain2", "data2", "read"])
                .await
                .unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_with_deny() {
        let m = DefaultModel::from_file("examples/rbac_with_deny_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_with_not_deny() {
        let m = DefaultModel::from_file("examples/rbac_with_not_deny_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_with_custom_data() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        e.add_grouping_policy(
            vec!["bob", "data2_admin", "custom_data"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );

        e.remove_grouping_policy(
            vec!["bob", "data2_admin", "custom_data"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_using_in_op() {
        let m = DefaultModel::from_file("examples/rbac_model_matcher_using_in_op.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["guest", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data3", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data3", "read"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_abac() {
        let m = DefaultModel::from_file("examples/abac_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            false,
            e.enforce(&vec!["alice", r#"{"Owner":"bob"}"#, "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", r#"{"Owner":"alice"}"#, "read"])
                .await
                .unwrap()
        );
    }
}
