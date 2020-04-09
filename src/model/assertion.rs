use crate::error::{ModelError, PolicyError};
use crate::rbac::{DefaultRoleManager, RoleManager};
use crate::Result;

use indexmap::IndexSet;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub(crate) type AssertionMap = HashMap<String, Assertion>;

#[derive(Clone)]
pub struct Assertion {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) tokens: Vec<String>,
    pub(crate) policy: IndexSet<Vec<String>>,
    pub(crate) rm: Arc<RwLock<dyn RoleManager>>,
}

impl Default for Assertion {
    fn default() -> Self {
        Assertion {
            key: String::new(),
            value: String::new(),
            tokens: vec![],
            policy: IndexSet::new(),
            rm: Arc::new(RwLock::new(DefaultRoleManager::new(0))),
        }
    }
}

impl Assertion {
    pub fn get_policy(&self) -> &IndexSet<Vec<String>> {
        &self.policy
    }

    pub fn get_mut_policy(&mut self) -> &mut IndexSet<Vec<String>> {
        &mut self.policy
    }

    pub fn build_role_links(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()> {
        let count = self.value.chars().filter(|&c| c == '_').count();
        for rule in &self.policy {
            if count < 2 {
                return Err(ModelError::P(
                    r#"the number of "_" in role definition should be at least 2"#.to_owned(),
                )
                .into());
            }
            if rule.len() < count {
                return Err(PolicyError::UnmatchPolicyDefinition(count, rule.len()).into());
            }
            if count == 2 {
                rm.write().unwrap().add_link(&rule[0], &rule[1], None);
            } else if count == 3 {
                rm.write()
                    .unwrap()
                    .add_link(&rule[0], &rule[1], Some(&rule[2]));
            } else if count >= 4 {
                return Err(ModelError::P("Multiple domains are not supported".to_owned()).into());
            }
        }
        self.rm = Arc::clone(&rm);
        Ok(())
    }
}
