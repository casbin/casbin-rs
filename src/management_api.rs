use crate::adapter::Adapter;
use crate::enforcer::Enforcer;
use crate::InternalApi;
use crate::Result;

pub trait MgmtApi {
    fn get_policy(&self) -> Vec<Vec<String>>;
    fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>>;
    fn get_filtered_policy(&self, field_index: usize, field_values: Vec<&str>) -> Vec<Vec<String>>;
    fn get_filtered_named_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>>;
    fn has_policy(&self, params: Vec<&str>) -> bool;
    fn has_named_policy(&self, ptype: &str, params: Vec<&str>) -> bool;
    fn add_policy(&mut self, params: Vec<&str>) -> Result<bool>;
    fn remove_policy(&mut self, params: Vec<&str>) -> Result<bool>;
    fn add_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool>;
    fn remove_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool>;
    fn add_grouping_policy(&mut self, params: Vec<&str>) -> Result<bool>;
    fn remove_grouping_policy(&mut self, params: Vec<&str>) -> Result<bool>;
    fn get_grouping_policy(&self) -> Vec<Vec<String>>;
    fn get_named_grouping_policy(&self, ptype: &str) -> Vec<Vec<String>>;
    fn get_filtered_grouping_policy(
        &self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>>;
    fn get_filtered_named_grouping_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>>;
    fn has_grouping_policy(&self, params: Vec<&str>) -> bool;
    fn has_grouping_named_policy(&self, ptype: &str, params: Vec<&str>) -> bool;
    fn add_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool>;
    fn remove_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool>;
    fn remove_filtered_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
    fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
    fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
    fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool>;
    fn get_all_subjects(&self) -> Vec<String>;
    fn get_all_named_subjects(&self, ptype: &str) -> Vec<String>;
    fn get_all_objects(&self) -> Vec<String>;
    fn get_all_named_objects(&self, ptype: &str) -> Vec<String>;
    fn get_all_actions(&self) -> Vec<String>;
    fn get_all_named_actions(&self, ptype: &str) -> Vec<String>;
    fn get_all_roles(&self) -> Vec<String>;
    fn get_all_named_roles(&self, ptype: &str) -> Vec<String>;
}

impl<A: Adapter> MgmtApi for Enforcer<A> {
    fn add_policy(&mut self, params: Vec<&str>) -> Result<bool> {
        self.add_named_policy("p", params)
    }

    fn remove_policy(&mut self, params: Vec<&str>) -> Result<bool> {
        self.remove_named_policy("p", params)
    }

    fn add_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool> {
        self.add_policy_internal("p", ptype, params)
    }

    fn remove_named_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool> {
        self.remove_policy_internal("p", ptype, params)
    }

    fn add_grouping_policy(&mut self, params: Vec<&str>) -> Result<bool> {
        self.add_named_grouping_policy("g", params)
    }

    fn add_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool> {
        let rule_added = self.add_policy_internal("g", ptype, params)?;
        self.build_role_links()?;
        Ok(rule_added)
    }

    fn remove_grouping_policy(&mut self, params: Vec<&str>) -> Result<bool> {
        self.remove_named_grouping_policy("g", params)
    }

    fn remove_named_grouping_policy(&mut self, ptype: &str, params: Vec<&str>) -> Result<bool> {
        let rule_removed = self.remove_policy_internal("g", ptype, params)?;
        self.build_role_links()?;
        Ok(rule_removed)
    }

    fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        self.remove_filtered_named_grouping_policy("g", field_index, field_values)
    }

    fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        let rule_removed =
            self.remove_filtered_policy_internal("g", ptype, field_index, field_values)?;
        self.build_role_links()?;
        Ok(rule_removed)
    }

    fn remove_filtered_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        self.remove_filtered_named_policy("p", field_index, field_values)
    }

    fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        self.remove_filtered_policy_internal("p", ptype, field_index, field_values)
    }

    fn get_policy(&self) -> Vec<Vec<String>> {
        self.get_named_policy("p")
    }

    fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.model.get_policy("p", ptype)
    }

    fn get_filtered_policy(&self, field_index: usize, field_values: Vec<&str>) -> Vec<Vec<String>> {
        self.get_filtered_named_policy("p", field_index, field_values)
    }

    fn get_filtered_named_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>> {
        self.model
            .get_filtered_policy("p", ptype, field_index, field_values)
    }

    fn has_policy(&self, params: Vec<&str>) -> bool {
        self.has_named_policy("p", params)
    }

    fn has_named_policy(&self, ptype: &str, params: Vec<&str>) -> bool {
        self.model.has_policy("p", ptype, params)
    }

    fn get_grouping_policy(&self) -> Vec<Vec<String>> {
        self.get_named_grouping_policy("g")
    }
    fn get_named_grouping_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.model.get_policy("g", ptype)
    }

    fn get_filtered_grouping_policy(
        &self,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>> {
        self.get_filtered_named_grouping_policy("g", field_index, field_values)
    }
    fn get_filtered_named_grouping_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>> {
        self.model
            .get_filtered_policy("g", ptype, field_index, field_values)
    }

    fn has_grouping_policy(&self, params: Vec<&str>) -> bool {
        self.has_grouping_named_policy("g", params)
    }

    fn has_grouping_named_policy(&self, ptype: &str, params: Vec<&str>) -> bool {
        self.model.has_policy("g", ptype, params)
    }

    fn get_all_subjects(&self) -> Vec<String> {
        self.get_all_named_subjects("p")
    }

    fn get_all_named_subjects(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("p", ptype, 0)
    }

    fn get_all_objects(&self) -> Vec<String> {
        self.get_all_named_objects("p")
    }

    fn get_all_named_objects(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("p", ptype, 1)
    }

    fn get_all_actions(&self) -> Vec<String> {
        self.get_all_named_actions("p")
    }

    fn get_all_named_actions(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("p", ptype, 2)
    }

    fn get_all_roles(&self) -> Vec<String> {
        self.get_all_named_roles("g")
    }

    fn get_all_named_roles(&self, ptype: &str) -> Vec<String> {
        self.model.get_values_for_field_in_policy("g", ptype, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::FileAdapter;
    use crate::enforcer::Enforcer;
    use crate::model::Model;
    use crate::RbacApi;

    #[test]
    fn test_modify_grouping_policy_api() {
        let m = Model::from_file("examples/rbac_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter);

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("eve", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("non_exist", None)
        );

        e.remove_grouping_policy(vec!["alice", "data2_admin"])
            .unwrap();
        e.add_grouping_policy(vec!["bob", "data1_admin"]).unwrap();
        e.add_grouping_policy(vec!["eve", "data3_admin"]).unwrap();

        let named_grouping_policy = vec!["alice", "data2_admin"];
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        e.add_named_grouping_policy("g", named_grouping_policy.clone())
            .unwrap();
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        e.remove_named_grouping_policy("g", named_grouping_policy.clone())
            .unwrap();

        e.remove_grouping_policy(vec!["alice", "data2_admin"])
            .unwrap();
        e.add_grouping_policy(vec!["bob", "data1_admin"]).unwrap();
        e.add_grouping_policy(vec!["eve", "data3_admin"]).unwrap();

        assert_eq!(vec!["bob"], e.get_users_for_role("data1_admin", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));

        e.remove_filtered_grouping_policy(0, vec!["bob"]).unwrap();

        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(vec!["data3_admin"], e.get_roles_for_user("eve", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("non_exist", None)
        );

        assert_eq!(
            vec![String::new(); 0],
            e.get_users_for_role("data1_admin", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));
    }

    #[test]
    fn test_modify_policy_api() {
        let m = Model::from_file("examples/rbac_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter);

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            e.get_policy()
        );

        e.remove_policy(vec!["alice", "data1", "read"]).unwrap();
        e.remove_policy(vec!["bob", "data2", "write"]).unwrap();
        e.remove_policy(vec!["alice", "data1", "read"]).unwrap();
        e.add_policy(vec!["eve", "data3", "read"]).unwrap();
        e.add_policy(vec!["eve", "data3", "read"]).unwrap();

        let named_policy = vec!["eve", "data3", "read"];
        e.remove_named_policy("p", named_policy.clone()).unwrap();
        e.add_named_policy("p", named_policy.clone()).unwrap();

        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
                vec!["eve", "data3", "read"],
            ],
            e.get_policy()
        );

        e.remove_filtered_policy(1, vec!["data2"]).unwrap();
        assert_eq!(vec![vec!["eve", "data3", "read"],], e.get_policy());
    }

    #[test]
    fn test_get_policy_api() {
        let m = Model::from_file("examples/rbac_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            e.get_policy()
        );

        assert_eq!(
            vec![vec!["alice", "data1", "read"]],
            e.get_filtered_policy(0, vec!["alice"])
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_filtered_policy(0, vec!["bob"])
        );
        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            e.get_filtered_policy(0, vec!["data2_admin"])
        );
        assert_eq!(
            vec![vec!["alice", "data1", "read"],],
            e.get_filtered_policy(1, vec!["data1"])
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            e.get_filtered_policy(1, vec!["data2"])
        );
        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["data2_admin", "data2", "read"],
            ],
            e.get_filtered_policy(2, vec!["read"])
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "write"],
            ],
            e.get_filtered_policy(2, vec!["write"])
        );
        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            e.get_filtered_policy(0, vec!["data2_admin", "data2"])
        );
        // Note: "" (empty string) in fieldValues means matching all values.
        assert_eq!(
            vec![vec!["data2_admin", "data2", "read"],],
            e.get_filtered_policy(0, vec!["data2_admin", "", "read"])
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "write"],
            ],
            e.get_filtered_policy(1, vec!["data2", "write"])
        );

        assert_eq!(true, e.has_policy(vec!["alice", "data1", "read"]));
        assert_eq!(true, e.has_policy(vec!["bob", "data2", "write"]));
        assert_eq!(false, e.has_policy(vec!["alice", "data2", "read"]));
        assert_eq!(false, e.has_policy(vec!["bob", "data3", "write"]));

        assert_eq!(
            vec![vec!["alice", "data2_admin"]],
            e.get_filtered_grouping_policy(0, vec!["alice"])
        );
        let empty_policy: Vec<Vec<String>> = vec![];
        assert_eq!(empty_policy, e.get_filtered_grouping_policy(0, vec!["bob"]));
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(1, vec!["data1_admin"])
        );
        assert_eq!(
            vec![vec!["alice", "data2_admin"],],
            e.get_filtered_grouping_policy(1, vec!["data2_admin"])
        );
        // Note: "" (empty string) in fieldValues means matching all values.
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(0, vec!["data2_admin"])
        );

        assert_eq!(true, e.has_grouping_policy(vec!["alice", "data2_admin"]));
        assert_eq!(false, e.has_grouping_policy(vec!["bob", "data2_admin"]));
    }

    #[test]
    fn test_get_list() {
        let m = Model::from_file("examples/rbac_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(vec!["alice", "bob", "data2_admin"], e.get_all_subjects());
        assert_eq!(vec!["data1", "data2"], e.get_all_objects());
        assert_eq!(vec!["read", "write"], e.get_all_actions());
        assert_eq!(vec!["data2_admin"], e.get_all_roles());
    }
}
