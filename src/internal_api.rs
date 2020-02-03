use crate::cached_enforcer::CachedEnforcer;
use crate::emitter::{Event, CACHED_EMITTER, EMITTER};
use crate::enforcer::Enforcer;
use crate::Result;

use emitbrown::Events;

pub trait InternalApi {
    fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool>;
    fn remove_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool>;
    fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
}

impl InternalApi for Enforcer {
    fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        let rule_added = self.model.add_policy(sec, ptype, rule.clone());
        if !rule_added {
            return Ok(false);
        }

        if self.auto_save {
            return self.adapter.add_policy(sec, ptype, rule);
        }

        if rule_added {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_added)
    }

    fn remove_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        let rule_removed = self.model.remove_policy(sec, ptype, rule.clone());
        if !rule_removed {
            return Ok(false);
        }

        if self.auto_save {
            return self.adapter.remove_policy(sec, ptype, rule);
        }

        if rule_removed {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_removed)
    }

    fn remove_filtered_policy_internal(
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
                .remove_filtered_policy(sec, ptype, field_index, field_values);
        }

        if rule_removed {
            EMITTER.lock().unwrap().emit(Event::PolicyChange, self);
        }

        Ok(rule_removed)
    }
}

impl InternalApi for CachedEnforcer {
    fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        let result = self.enforcer.add_policy_internal(sec, ptype, rule);

        if let Ok(true) = result {
            CACHED_EMITTER
                .lock()
                .unwrap()
                .emit(Event::PolicyChange, self);
        }

        result
    }

    fn remove_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        let result = self.enforcer.remove_policy_internal(sec, ptype, rule);

        if let Ok(true) = result {
            CACHED_EMITTER
                .lock()
                .unwrap()
                .emit(Event::PolicyChange, self);
        }

        result
    }

    fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        let result =
            self.enforcer
                .remove_filtered_policy_internal(sec, ptype, field_index, field_values);

        if let Ok(true) = result {
            CACHED_EMITTER
                .lock()
                .unwrap()
                .emit(Event::PolicyChange, self)
        }

        result
    }
}
