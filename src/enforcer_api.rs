use crate::adapter::Adapter;
use crate::enforcer::Enforcer;

pub trait RbacApi {
    fn add_permission_for_user(&mut self, user: &str, permission: Vec<&str>) -> bool;
    fn add_role_for_user(&mut self, user: &str, role: &str) -> bool;
}

impl<A: Adapter> RbacApi for Enforcer<A> {
    fn add_permission_for_user(&mut self, user: &str, permission: Vec<&str>) -> bool {
        let mut perm = permission;
        perm.insert(0, user);
        return self.add_policy(perm);
    }

    fn add_role_for_user(&mut self, user: &str, role: &str) -> bool {
        return self.add_grouping_policy(vec![user, role]);
    }
}

pub trait MgmtApi {
    fn add_policy(&mut self, params: Vec<&str>) -> bool;
    fn add_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool;
    fn add_grouping_policy(&mut self, params: Vec<&str>) -> bool;
    fn add_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool;
}

impl<A: Adapter> MgmtApi for Enforcer<A> {
    fn add_policy(&mut self, params: Vec<&str>) -> bool {
        return self.add_named_policy("p", params);
    }

    fn add_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool {
        return self.add_policy_internal("p", ptype, params);
    }

    fn add_grouping_policy(&mut self, params: Vec<&str>) -> bool {
        return self.add_named_grouping_policy("g", params);
    }

    fn add_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> bool {
        let rule_added = self.add_policy_internal("g", ptype, params);
        self.build_role_links();
        return rule_added;
    }
}

pub trait InternalApi {
    fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool;
}

impl<A: Adapter> InternalApi for Enforcer<A> {
    fn add_policy_internal(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        let rule_added = self.model.add_policy(sec, ptype, rule.clone());
        if rule_added == false {
            return false;
        }
        return self.adapter.add_policy(sec, ptype, rule.clone());
    }
}
