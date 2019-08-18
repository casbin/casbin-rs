use crate::adapter::Adapter;
use crate::enforcer::Enforcer;
use crate::InternalApi;

pub trait MgmtApi {
    fn add_policy(&mut self, params: Vec<&str>) -> bool;
    fn remove_policy(&mut self, params: Vec<&str>) -> bool;
    fn add_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool;
    fn remove_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool;
    fn add_grouping_policy(&mut self, params: Vec<&str>) -> bool;
    fn remove_grouping_policy(&mut self, params: Vec<&str>) -> bool;
    fn add_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool;
    fn remove_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool;
    fn remove_filtered_policy(&mut self, field_index: usize, field_values: Vec<&str>) -> bool;
    fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool;
    fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool;
    fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool;
}

impl<A: Adapter> MgmtApi for Enforcer<A> {
    fn add_policy(&mut self, params: Vec<&str>) -> bool {
        return self.add_named_policy("p", params);
    }

    fn remove_policy(&mut self, params: Vec<&str>) -> bool {
        return self.remove_named_policy("p", params);
    }

    fn add_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool {
        return self.add_policy_internal("p", ptype, params);
    }

    fn remove_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool {
        return self.remove_policy_internal("p", ptype, params);
    }

    fn add_grouping_policy(&mut self, params: Vec<&str>) -> bool {
        return self.add_named_grouping_policy("g", params);
    }

    fn add_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool {
        let rule_added = self.add_policy_internal("g", ptype, params);
        self.build_role_links();
        return rule_added;
    }

    fn remove_grouping_policy(&mut self, params: Vec<&str>) -> bool {
        return self.remove_named_grouping_policy("g", params);
    }

    fn remove_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool {
        let rule_removed = self.remove_policy_internal("g", ptype, params);
        self.build_role_links();
        return rule_removed;
    }

    fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool {
        return self.remove_filtered_named_grouping_policy("g", field_index, field_values);
    }

    fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool {
        let rule_removed =
            self.remove_filtered_policy_internal("g", ptype, field_index, field_values);
        self.build_role_links();
        return rule_removed;
    }

    fn remove_filtered_policy(&mut self, field_index: usize, field_values: Vec<&str>) -> bool {
        return self.remove_filtered_named_policy("p", field_index, field_values);
    }

    fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool {
        return self.remove_filtered_policy_internal("p", ptype, field_index, field_values);
    }
}
