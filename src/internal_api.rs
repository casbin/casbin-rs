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
        rule: Vec<&str>,
    ) -> Result<bool>;
    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool>;
    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
}

#[async_trait]
impl InternalApi for Enforcer {
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool> {
        let rule_added = self.model.add_policy(sec, ptype, rule.clone());
        if !rule_added {
            return Ok(false);
        }

        if self.auto_save {
            return self.adapter.add_policy(sec, ptype, rule).await;
        }

        if rule_added {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_added)
    }

    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool> {
        let rule_removed = self.model.remove_policy(sec, ptype, rule.clone());
        if !rule_removed {
            return Ok(false);
        }

        if self.auto_save {
            return self.adapter.remove_policy(sec, ptype, rule).await;
        }

        if rule_removed {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_removed)
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        let rule_removed =
            self.model
                .remove_filtered_policy(sec, ptype, field_index, field_values.clone());

        if !rule_removed {
            return Ok(false);
        }

        if self.auto_save {
            return self
                .adapter
                .remove_filtered_policy(sec, ptype, field_index, field_values)
                .await;
        }

        if rule_removed {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_removed)
    }
}

#[async_trait]
impl InternalApi for CachedEnforcer {
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool> {
        let result = self.enforcer.add_policy_internal(sec, ptype, rule).await;

        if let Ok(true) = result {
            CACHED_EMITTER
                .lock()
                .unwrap()
                .emit(Event::PolicyChange, self);
        }

        result
    }

    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool> {
        let result = self.enforcer.remove_policy_internal(sec, ptype, rule).await;

        if let Ok(true) = result {
            CACHED_EMITTER
                .lock()
                .unwrap()
                .emit(Event::PolicyChange, self);
        }

        result
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        let result = self
            .enforcer
            .remove_filtered_policy_internal(sec, ptype, field_index, field_values)
            .await;

        if let Ok(true) = result {
            CACHED_EMITTER
                .lock()
                .unwrap()
                .emit(Event::PolicyChange, self)
        }

        result
    }
}
