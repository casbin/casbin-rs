use crate::adapter::Adapter;
use crate::enforcer::Enforcer;

pub trait InternalApi {
    fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool;
    fn remove_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool;
    fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool;
}

impl<A: Adapter> InternalApi for Enforcer<A> {
    fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        let rule_added = self.model.add_policy(sec, ptype, rule.clone());
        if rule_added == false {
            return false;
        }
        // TODO: check autosave in enforcer
        return self.adapter.add_policy(sec, ptype, rule.clone());
    }

    fn remove_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        let rule_removed = self.model.remove_policy(sec, ptype, rule.clone());
        if rule_removed == false {
            return false;
        }
        // TODO: check autosave in enforcer
        return self.adapter.remove_policy(sec, ptype, rule.clone());
    }

    fn remove_filtered_policy_internal(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool {
        let rule_removed =
            self.model
                .remove_filtered_policy(sec, ptype, field_index, field_values.clone());
        if rule_removed == false {
            return false;
        }
        // TODO: check autosave in enforcer
        return self
            .adapter
            .remove_filtered_policy(sec, ptype, field_index, field_values.clone());
    }
}
