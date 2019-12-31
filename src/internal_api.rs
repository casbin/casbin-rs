use crate::adapter::Adapter;
use crate::enforcer::Enforcer;
use crate::errors::RuntimeError;

pub trait InternalApi {
    fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool, RuntimeError>;
    fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool, RuntimeError>;
    fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool, RuntimeError>;
}

impl<A: Adapter> InternalApi for Enforcer<A> {
    fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool, RuntimeError> {
        let rule_added = self.model.add_policy(sec, ptype, rule.clone());
        if !rule_added {
            return Ok(false);
        }
        if self.auto_save {
            return self.adapter.add_policy(sec, ptype, rule.clone());
        }
        Ok(rule_added)
    }

    fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<&str>,
    ) -> Result<bool, RuntimeError> {
        let rule_removed = self.model.remove_policy(sec, ptype, rule.clone());
        if !rule_removed {
            return Ok(false);
        }
        if self.auto_save {
            return self.adapter.remove_policy(sec, ptype, rule.clone());
        }
        Ok(rule_removed)
    }

    fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool, RuntimeError> {
        let rule_removed =
            self.model
                .remove_filtered_policy(sec, ptype, field_index, field_values.clone());
        if !rule_removed {
            return Ok(false);
        }
        if self.auto_save {
            return self.adapter.remove_filtered_policy(
                sec,
                ptype,
                field_index,
                field_values.clone(),
            );
        }
        Ok(rule_removed)
    }
}
