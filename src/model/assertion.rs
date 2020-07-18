use crate::{
    error::{ModelError, PolicyError},
    rbac::{DefaultRoleManager, RoleManager},
    Result,
};

#[cfg(feature = "incremental")]
use crate::emitter::EventData;

use indexmap::{IndexMap, IndexSet};

use std::sync::{Arc, RwLock};

pub type AssertionMap = IndexMap<String, Assertion>;

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
    #[inline]
    pub fn get_policy(&self) -> &IndexSet<Vec<String>> {
        &self.policy
    }

    #[inline]
    pub fn get_mut_policy(&mut self) -> &mut IndexSet<Vec<String>> {
        &mut self.policy
    }

    pub fn build_role_links(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()> {
        let count = self.value.matches('_').count();
        if count < 2 {
            return Err(ModelError::P(
                r#"the number of "_" in role definition should be at least 2"#.to_owned(),
            )
            .into());
        }
        for rule in &self.policy {
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

    #[cfg(feature = "incremental")]
    pub fn build_incremental_role_links(
        &mut self,
        rm: Arc<RwLock<dyn RoleManager>>,
        d: EventData,
    ) -> Result<()> {
        let count = self.value.matches('_').count();
        if count < 2 {
            return Err(ModelError::P(
                r#"the number of "_" in role definition should be at least 2"#.to_owned(),
            )
            .into());
        }

        if let Some((insert, rules)) = match d {
            EventData::AddPolicy(_, _, rule) => Some((true, vec![rule])),
            EventData::AddPolicies(_, _, rules) => Some((true, rules)),
            EventData::RemovePolicy(_, _, rule) => Some((false, vec![rule])),
            EventData::RemovePolicies(_, _, rules) => Some((false, rules)),
            EventData::RemoveFilteredPolicy(_, _, rules) => Some((false, rules)),
            _ => None,
        } {
            for rule in rules {
                if rule.len() < count {
                    return Err(PolicyError::UnmatchPolicyDefinition(count, rule.len()).into());
                }
                if count == 2 {
                    if insert {
                        rm.write().unwrap().add_link(&rule[0], &rule[1], None);
                    } else {
                        rm.write().unwrap().delete_link(&rule[0], &rule[1], None)?;
                    }
                } else if count == 3 {
                    if insert {
                        rm.write()
                            .unwrap()
                            .add_link(&rule[0], &rule[1], Some(&rule[2]));
                    } else {
                        rm.write()
                            .unwrap()
                            .delete_link(&rule[0], &rule[1], Some(&rule[2]))?;
                    }
                } else if count >= 4 {
                    return Err(
                        ModelError::P("Multiple domains are not supported".to_owned()).into(),
                    );
                }
            }

            self.rm = Arc::clone(&rm);
        }

        Ok(())
    }
}
