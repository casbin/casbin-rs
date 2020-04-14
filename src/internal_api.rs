use crate::{
    cached_enforcer::CachedEnforcer,
    core_api::CoreApi,
    emitter::{Event, EventData, EventEmitter},
    enforcer::Enforcer,
    Result,
};

use async_trait::async_trait;

#[async_trait]
pub trait InternalApi: CoreApi + EventEmitter<Event> {
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
    ) -> Result<(bool, Vec<Vec<String>>)>;
}

#[async_trait]
impl InternalApi for Enforcer {
    async fn add_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .add_policy(sec, ptype, rule.clone())
                .await?
        {
            return Ok(false);
        }

        let rule_added = self.get_mut_model().add_policy(sec, ptype, rule.clone());
        if rule_added && self.has_auto_notify_watcher_enabled() {
            self.emit(Event::PolicyChange, Some(EventData::AddPolicy(rule)));
        }

        Ok(rule_added)
    }

    async fn add_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .add_policies(sec, ptype, rules.clone())
                .await?
        {
            return Ok(false);
        }

        let rules_added = self.get_mut_model().add_policies(sec, ptype, rules.clone());
        if rules_added && self.has_auto_notify_watcher_enabled() {
            self.emit(Event::PolicyChange, Some(EventData::AddPolicies(rules)));
        }

        Ok(rules_added)
    }

    async fn remove_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .remove_policy(sec, ptype, rule.clone())
                .await?
        {
            return Ok(false);
        }

        let rule_removed = self.get_mut_model().remove_policy(sec, ptype, rule.clone());
        if rule_removed && self.has_auto_notify_watcher_enabled() {
            self.emit(Event::PolicyChange, Some(EventData::RemovePolicy(rule)));
        }

        Ok(rule_removed)
    }

    async fn remove_policies_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .remove_policies(sec, ptype, rules.clone())
                .await?
        {
            return Ok(false);
        }

        let rules_removed = self
            .get_mut_model()
            .remove_policies(sec, ptype, rules.clone());
        if rules_removed && self.has_auto_notify_watcher_enabled() {
            self.emit(Event::PolicyChange, Some(EventData::RemovePolicies(rules)));
        }

        Ok(rules_removed)
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<(bool, Vec<Vec<String>>)> {
        if self.has_auto_save_enabled()
            && !self
                .get_mut_adapter()
                .remove_filtered_policy(sec, ptype, field_index, field_values.clone())
                .await?
        {
            return Ok((false, vec![]));
        }

        let (rules_removed, rules) =
            self.get_mut_model()
                .remove_filtered_policy(sec, ptype, field_index, field_values);
        if rules_removed && self.has_auto_notify_watcher_enabled() {
            self.emit(
                Event::PolicyChange,
                Some(EventData::RemoveFilteredPolicy(rules.clone())),
            );
        }

        Ok((rules_removed, rules))
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

        self.emit(Event::PolicyChange, None);

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

        self.emit(Event::PolicyChange, None);

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

        self.emit(Event::PolicyChange, None);

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

        self.emit(Event::PolicyChange, None);

        Ok(rule_removed)
    }

    async fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<(bool, Vec<Vec<String>>)> {
        let (rules_removed, rules) = self
            .enforcer
            .remove_filtered_policy_internal(sec, ptype, field_index, field_values)
            .await?;
        if !rules_removed {
            return Ok((false, vec![]));
        }

        self.emit(Event::PolicyChange, None);

        Ok((rules_removed, rules))
    }
}
