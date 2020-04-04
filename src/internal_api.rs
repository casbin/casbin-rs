use crate::cached_enforcer::CachedEnforcer;
use crate::emitter::{Event, CACHED_EMITTER, EMITTER};
use crate::enforcer::Enforcer;
use crate::Result;

use async_trait::async_trait;
use emitbrown::Events;
use log::error;

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
        let rule_added = self.model.add_policy(sec, ptype, rule.clone());
        if !rule_added {
            return Ok(false);
        }

        if self.auto_save {
            if self.adapter.add_policy(sec, ptype, rule).await? {
                EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
            } else {
                error!("policy was added to model but not adapter");
            }

            return Ok(rule_added);
        }

        EMITTER.lock().unwrap().emit(Event::PolicyChange, self);

        Ok(rule_added)
    }

    async fn add_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_added = self.model.add_policies(sec, ptype, rules.clone());
        if !all_added {
            return Ok(false);
        }

        if self.auto_save {
            if self.adapter.add_policies(sec, ptype, rules).await? {
                EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
            } else {
                error!("policies were added to model but not adapter");
            }

            return Ok(all_added);
        }

        EMITTER.lock().unwrap().emit(Event::PolicyChange, self);

        Ok(all_added)
    }

    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        let rule_removed = self.model.remove_policy(sec, ptype, rule.clone());
        if !rule_removed {
            return Ok(false);
        }

        if self.auto_save {
            if self.adapter.remove_policy(sec, ptype, rule).await? {
                EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
            } else {
                error!("policy was added to model but not adapter");
            }

            return Ok(rule_removed);
        }

        EMITTER.lock().unwrap().emit(Event::PolicyChange, self);

        Ok(rule_removed)
    }

    async fn remove_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_removed = self.model.remove_policies(sec, ptype, rules.clone());
        if !all_removed {
            return Ok(false);
        }

        if self.auto_save {
            if self.adapter.remove_policies(sec, ptype, rules).await? {
                EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
            } else {
                error!("policies were added to model but not adapter");
            }

            return Ok(all_removed);
        }

        EMITTER.lock().unwrap().emit(Event::PolicyChange, self);

        Ok(all_removed)
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        let rule_removed =
            self.model
                .remove_filtered_policy(sec, ptype, field_index, field_values.clone());
        if !rule_removed {
            return Ok(false);
        }

        if self.auto_save {
            if self
                .adapter
                .remove_filtered_policy(sec, ptype, field_index, field_values)
                .await?
            {
                EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
            } else {
                error!("policy was added to model but not adapter");
            }

            return Ok(rule_removed);
        }

        EMITTER.lock().unwrap().emit(Event::PolicyChange, self);

        Ok(rule_removed)
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
