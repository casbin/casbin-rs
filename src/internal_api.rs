use crate::cached_enforcer::CachedEnforcer;
use crate::emitter::{Event, CACHED_EMITTER, EMITTER};
use crate::enforcer::Enforcer;
use crate::Result;

use async_trait::async_trait;
use emitbrown::Events;

#[async_trait]
pub trait InternalApi {
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn add_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool>;
    async fn remove_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
}

#[async_trait]
impl InternalApi for Enforcer {
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        if self.auto_save {
            if !self.adapter.add_policy(sec, ptype, rule.clone()).await? {
                return Ok(false);
            }
        }

        let rule_added = self.model.add_policy(sec, ptype, rule);
        if rule_added {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_added)
    }

    async fn add_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if self.auto_save {
            if !self.adapter.add_policies(sec, ptype, rules.clone()).await? {
                return Ok(false);
            }
        }

        let rules_added = self.model.add_policies(sec, ptype, rules);
        if rules_added {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rules_added)
    }

    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        if self.auto_save {
            if !self.adapter.remove_policy(sec, ptype, rule.clone()).await? {
                return Ok(false);
            }
        }

        let rule_removed = self.model.remove_policy(sec, ptype, rule);
        if rule_removed {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_removed)
    }

    async fn remove_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if self.auto_save {
            if !self
                .adapter
                .remove_policies(sec, ptype, rules.clone())
                .await?
            {
                return Ok(false);
            }
        }

        let rules_removed = self.model.remove_policies(sec, ptype, rules);
        if rules_removed {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rules_removed)
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if self.auto_save {
            if !self
                .adapter
                .remove_filtered_policy(sec, ptype, field_index, field_values.clone())
                .await?
            {
                return Ok(false);
            }
        }

        let rules_removed =
            self.model
                .remove_filtered_policy(sec, ptype, field_index, field_values);
        if rules_removed {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rules_removed)
    }
}

#[async_trait]
impl InternalApi for CachedEnforcer {
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        let rule_added = self.enforcer.add_policy_internal(sec, ptype, rule).await?;
        if !rule_added {
            return Ok(false);
        }

        CACHED_EMITTER
            .lock()
            .unwrap()
            .emit(Event::PolicyChange, self);

        Ok(rule_added)
    }

    async fn add_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_added = self
            .enforcer
            .add_policies_internal(sec, ptype, rules)
            .await?;
        if !all_added {
            return Ok(false);
        }

        CACHED_EMITTER
            .lock()
            .unwrap()
            .emit(Event::PolicyChange, self);

        Ok(all_added)
    }

    async fn remove_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_removed = self
            .enforcer
            .remove_policies_internal(sec, ptype, rules)
            .await?;
        if !all_removed {
            return Ok(false);
        }

        CACHED_EMITTER
            .lock()
            .unwrap()
            .emit(Event::PolicyChange, self);

        Ok(all_removed)
    }

    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        let rule_removed = self
            .enforcer
            .remove_policy_internal(sec, ptype, rule)
            .await?;
        if !rule_removed {
            return Ok(false);
        }

        CACHED_EMITTER
            .lock()
            .unwrap()
            .emit(Event::PolicyChange, self);

        Ok(rule_removed)
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        let rule_removed = self
            .enforcer
            .remove_filtered_policy_internal(sec, ptype, field_index, field_values)
            .await?;
        if !rule_removed {
            return Ok(false);
        }

        CACHED_EMITTER
            .lock()
            .unwrap()
            .emit(Event::PolicyChange, self);

        Ok(rule_removed)
    }
}
