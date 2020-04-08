use crate::cached_enforcer::CachedEnforcer;
use crate::enforcer::Enforcer;
use crate::CoreApi;
use crate::InternalApi;
use crate::Result;

use async_trait::async_trait;

#[async_trait]
pub trait MgmtApi: InternalApi + CoreApi {
    async fn add_policy(&mut self, params: Vec<String>) -> Result<bool>;
    async fn add_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool>;
    async fn remove_policy(&mut self, params: Vec<String>) -> Result<bool>;
    async fn remove_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool>;
    async fn add_named_policy(&mut self, ptype: &str, params: Vec<String>) -> Result<bool>;
    async fn add_named_policies(&mut self, ptype: &str, paramss: Vec<Vec<String>>) -> Result<bool>;
    async fn remove_named_policy(&mut self, ptype: &str, params: Vec<String>) -> Result<bool>;
    async fn remove_named_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn add_grouping_policy(&mut self, params: Vec<String>) -> Result<bool>;
    async fn add_grouping_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool>;
    async fn remove_grouping_policy(&mut self, params: Vec<String>) -> Result<bool>;
    async fn remove_grouping_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool>;
    async fn add_named_grouping_policy(&mut self, ptype: &str, params: Vec<String>)
        -> Result<bool>;
    async fn add_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool>;
    async fn remove_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn remove_filtered_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
    async fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
    async fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
    async fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
    fn get_policy(&self) -> Vec<Vec<String>>;
    fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>>;
    fn get_filtered_policy(
        &self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;
    fn get_filtered_named_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;
    fn has_policy(&self, params: Vec<String>) -> bool;
    fn has_named_policy(&self, ptype: &str, params: Vec<String>) -> bool;
    fn get_grouping_policy(&self) -> Vec<Vec<String>>;
    fn get_named_grouping_policy(&self, ptype: &str) -> Vec<Vec<String>>;
    fn get_filtered_grouping_policy(
        &self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;
    fn get_filtered_named_grouping_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;
    fn has_grouping_policy(&self, params: Vec<String>) -> bool;
    fn has_grouping_named_policy(&self, ptype: &str, params: Vec<String>) -> bool;
    fn get_all_subjects(&self) -> Vec<String>;
    fn get_all_named_subjects(&self, ptype: &str) -> Vec<String>;
    fn get_all_objects(&self) -> Vec<String>;
    fn get_all_named_objects(&self, ptype: &str) -> Vec<String>;
    fn get_all_actions(&self) -> Vec<String>;
    fn get_all_named_actions(&self, ptype: &str) -> Vec<String>;
    fn get_all_roles(&self) -> Vec<String>;
    fn get_all_named_roles(&self, ptype: &str) -> Vec<String>;
}

#[async_trait]
impl MgmtApi for Enforcer {
    async fn add_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.add_named_policy("p", params).await
    }

    async fn add_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.add_named_policies("p", paramss).await
    }

    async fn remove_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.remove_named_policy("p", params).await
    }

    async fn remove_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.remove_named_policies("p", paramss).await
    }

    async fn add_named_policy(&mut self, ptype: &str, params: Vec<String>) -> Result<bool> {
        self.add_policy_internal("p", ptype, params).await
    }

    async fn add_named_policies(&mut self, ptype: &str, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.add_policies_internal("p", ptype, paramss).await
    }

    async fn remove_named_policy(&mut self, ptype: &str, params: Vec<String>) -> Result<bool> {
        self.remove_policy_internal("p", ptype, params).await
    }

    async fn remove_named_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.remove_policies_internal("p", ptype, paramss).await
    }

    async fn add_grouping_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.add_named_grouping_policy("g", params).await
    }

    async fn add_grouping_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.add_named_grouping_policies("g", paramss).await
    }

    async fn add_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        let rule_added = self.add_policy_internal("g", ptype, params).await?;
        self.build_role_links()?;
        Ok(rule_added)
    }

    async fn add_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_added = self.add_policies_internal("g", ptype, paramss).await?;
        self.build_role_links()?;
        Ok(all_added)
    }

    async fn remove_grouping_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.remove_named_grouping_policy("g", params).await
    }

    async fn remove_grouping_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.remove_named_grouping_policies("g", paramss).await
    }

    async fn remove_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        let rule_removed = self.remove_policy_internal("g", ptype, params).await?;
        self.build_role_links()?;
        Ok(rule_removed)
    }

    async fn remove_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        let all_removed = self.remove_policies_internal("g", ptype, paramss).await?;
        self.build_role_links()?;
        Ok(all_removed)
    }

    async fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.remove_filtered_named_grouping_policy("g", field_index, field_values)
            .await
    }

    async fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        let rule_removed = self
            .remove_filtered_policy_internal("g", ptype, field_index, field_values)
            .await?;
        self.build_role_links()?;
        Ok(rule_removed)
    }

    async fn remove_filtered_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.remove_filtered_named_policy("p", field_index, field_values)
            .await
    }

    async fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.remove_filtered_policy_internal("p", ptype, field_index, field_values)
            .await
    }

    fn get_policy(&self) -> Vec<Vec<String>> {
        self.get_named_policy("p")
    }

    fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.model.get_policy("p", ptype)
    }

    fn get_filtered_policy(
        &self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.get_filtered_named_policy("p", field_index, field_values)
    }

    fn get_filtered_named_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.model
            .get_filtered_policy("p", ptype, field_index, field_values)
    }

    fn has_policy(&self, params: Vec<String>) -> bool {
        self.has_named_policy("p", params)
    }

    fn has_named_policy(&self, ptype: &str, params: Vec<String>) -> bool {
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
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.get_filtered_named_grouping_policy("g", field_index, field_values)
    }
    fn get_filtered_named_grouping_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.model
            .get_filtered_policy("g", ptype, field_index, field_values)
    }

    fn has_grouping_policy(&self, params: Vec<String>) -> bool {
        self.has_grouping_named_policy("g", params)
    }

    fn has_grouping_named_policy(&self, ptype: &str, params: Vec<String>) -> bool {
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

#[async_trait]
impl MgmtApi for CachedEnforcer {
    async fn add_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.enforcer.add_policy(params).await
    }

    async fn add_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.enforcer.add_policies(paramss).await
    }

    async fn remove_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.enforcer.remove_policy(params).await
    }

    async fn remove_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.enforcer.remove_policies(paramss).await
    }

    async fn add_named_policy(&mut self, ptype: &str, params: Vec<String>) -> Result<bool> {
        self.enforcer.add_named_policy(ptype, params).await
    }

    async fn add_named_policies(&mut self, ptype: &str, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.enforcer.add_named_policies(ptype, paramss).await
    }

    async fn remove_named_policy(&mut self, ptype: &str, params: Vec<String>) -> Result<bool> {
        self.enforcer.remove_named_policy(ptype, params).await
    }

    async fn remove_named_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.enforcer.remove_named_policies(ptype, paramss).await
    }

    async fn add_grouping_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.enforcer.add_grouping_policy(params).await
    }

    async fn add_grouping_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.enforcer.add_grouping_policies(paramss).await
    }

    async fn remove_grouping_policy(&mut self, params: Vec<String>) -> Result<bool> {
        self.enforcer.remove_grouping_policy(params).await
    }

    async fn remove_grouping_policies(&mut self, paramss: Vec<Vec<String>>) -> Result<bool> {
        self.enforcer.remove_grouping_policies(paramss).await
    }

    async fn add_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        self.enforcer.add_named_grouping_policy(ptype, params).await
    }

    async fn add_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.enforcer
            .add_named_grouping_policies(ptype, paramss)
            .await
    }

    async fn remove_named_grouping_policy(
        &mut self,
        ptype: &str,
        params: Vec<String>,
    ) -> Result<bool> {
        self.enforcer
            .remove_named_grouping_policy(ptype, params)
            .await
    }

    async fn remove_named_grouping_policies(
        &mut self,
        ptype: &str,
        paramss: Vec<Vec<String>>,
    ) -> Result<bool> {
        self.enforcer
            .remove_named_grouping_policies(ptype, paramss)
            .await
    }

    async fn remove_filtered_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.enforcer
            .remove_filtered_policy(field_index, field_values)
            .await
    }

    async fn remove_filtered_grouping_policy(
        &mut self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.enforcer
            .remove_filtered_grouping_policy(field_index, field_values)
            .await
    }

    async fn remove_filtered_named_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.enforcer
            .remove_filtered_named_policy(ptype, field_index, field_values)
            .await
    }

    async fn remove_filtered_named_grouping_policy(
        &mut self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        self.enforcer
            .remove_filtered_named_grouping_policy(ptype, field_index, field_values)
            .await
    }

    fn get_policy(&self) -> Vec<Vec<String>> {
        self.enforcer.get_policy()
    }

    fn get_named_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.enforcer.get_named_policy(ptype)
    }

    fn get_filtered_policy(
        &self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.enforcer.get_filtered_policy(field_index, field_values)
    }

    fn get_filtered_named_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.enforcer
            .get_filtered_named_policy(ptype, field_index, field_values)
    }

    fn has_policy(&self, params: Vec<String>) -> bool {
        self.enforcer.has_policy(params)
    }

    fn has_named_policy(&self, ptype: &str, params: Vec<String>) -> bool {
        self.enforcer.has_named_policy(ptype, params)
    }

    fn get_grouping_policy(&self) -> Vec<Vec<String>> {
        self.enforcer.get_grouping_policy()
    }

    fn get_named_grouping_policy(&self, ptype: &str) -> Vec<Vec<String>> {
        self.enforcer.get_named_grouping_policy(ptype)
    }

    fn get_filtered_grouping_policy(
        &self,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.enforcer
            .get_filtered_grouping_policy(field_index, field_values)
    }

    fn get_filtered_named_grouping_policy(
        &self,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        self.enforcer
            .get_filtered_named_grouping_policy(ptype, field_index, field_values)
    }

    fn has_grouping_policy(&self, params: Vec<String>) -> bool {
        self.enforcer.has_grouping_policy(params)
    }

    fn has_grouping_named_policy(&self, ptype: &str, params: Vec<String>) -> bool {
        self.enforcer.has_grouping_named_policy(ptype, params)
    }

    fn get_all_subjects(&self) -> Vec<String> {
        self.enforcer.get_all_subjects()
    }

    fn get_all_named_subjects(&self, ptype: &str) -> Vec<String> {
        self.enforcer.get_all_named_subjects(ptype)
    }

    fn get_all_objects(&self) -> Vec<String> {
        self.enforcer.get_all_objects()
    }

    fn get_all_named_objects(&self, ptype: &str) -> Vec<String> {
        self.enforcer.get_all_named_objects(ptype)
    }

    fn get_all_actions(&self) -> Vec<String> {
        self.enforcer.get_all_actions()
    }

    fn get_all_named_actions(&self, ptype: &str) -> Vec<String> {
        self.enforcer.get_all_named_actions(ptype)
    }

    fn get_all_roles(&self) -> Vec<String> {
        self.enforcer.get_all_roles()
    }

    fn get_all_named_roles(&self, ptype: &str) -> Vec<String> {
        self.enforcer.get_all_named_roles(ptype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::FileAdapter;
    use crate::enforcer::Enforcer;
    use crate::model::DefaultModel;
    use crate::RbacApi;

    fn sort_unstable<T: Ord>(mut v: Vec<T>) -> Vec<T> {
        v.sort_unstable();
        v
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_modify_grouping_policy_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("eve", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("non_exist", None)
        );

        e.remove_grouping_policy(
            vec!["alice", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        let named_grouping_policy = vec!["alice".to_string(), "data2_admin".to_string()];
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        e.add_named_grouping_policy("g", named_grouping_policy.clone())
            .await
            .unwrap();
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        e.remove_named_grouping_policy("g", named_grouping_policy.clone())
            .await
            .unwrap();

        e.remove_grouping_policy(
            vec!["alice", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_grouping_policy(
            vec!["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(vec!["bob"], e.get_users_for_role("data1_admin", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));

        e.remove_filtered_grouping_policy(0, vec!["bob"].iter().map(|s| s.to_string()).collect())
            .await
            .unwrap();

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

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_modify_policy_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_policy(
            vec!["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.remove_policy(
            vec!["bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.remove_policy(
            vec!["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_policy(
            vec!["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        let named_policy = vec!["eve".to_string(), "data3".to_string(), "read".to_string()];
        e.remove_named_policy("p", named_policy.clone())
            .await
            .unwrap();
        e.add_named_policy("p", named_policy.clone()).await.unwrap();

        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
                vec!["eve", "data3", "read"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_filtered_policy(1, vec!["data2"].iter().map(|s| s.to_string()).collect())
            .await
            .unwrap();
        assert_eq!(vec![vec!["eve", "data3", "read"],], e.get_policy());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_get_policy_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_policy())
        );

        assert_eq!(
            vec![vec!["alice", "data1", "read"]],
            e.get_filtered_policy(0, vec!["alice"].iter().map(|s| s.to_string()).collect())
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_filtered_policy(0, vec!["bob"].iter().map(|s| s.to_string()).collect())
        );
        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_filtered_policy(
                0,
                vec!["data2_admin"].iter().map(|s| s.to_string()).collect()
            ))
        );
        assert_eq!(
            vec![vec!["alice", "data1", "read"],],
            e.get_filtered_policy(1, vec!["data1"].iter().map(|s| s.to_string()).collect())
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(
                e.get_filtered_policy(1, vec!["data2"].iter().map(|s| s.to_string()).collect())
            )
        );
        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["data2_admin", "data2", "read"],
            ],
            sort_unstable(
                e.get_filtered_policy(2, vec!["read"].iter().map(|s| s.to_string()).collect())
            )
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(
                e.get_filtered_policy(2, vec!["write"].iter().map(|s| s.to_string()).collect())
            )
        );
        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(
                e.get_filtered_policy(
                    0,
                    vec!["data2_admin", "data2"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                )
            )
        );
        // Note: "" (empty string) in fieldValues means matching all values.
        assert_eq!(
            vec![vec!["data2_admin", "data2", "read"],],
            e.get_filtered_policy(
                0,
                vec!["data2_admin", "", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            vec![
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(
                e.get_filtered_policy(
                    1,
                    vec!["data2", "write"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                )
            )
        );

        assert_eq!(
            true,
            e.has_policy(
                vec!["alice", "data1", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            true,
            e.has_policy(
                vec!["bob", "data2", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            false,
            e.has_policy(
                vec!["alice", "data2", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            false,
            e.has_policy(
                vec!["bob", "data3", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );

        assert_eq!(
            vec![vec!["alice", "data2_admin"]],
            e.get_filtered_grouping_policy(
                0,
                vec!["alice"].iter().map(|s| s.to_string()).collect()
            )
        );
        let empty_policy: Vec<Vec<String>> = vec![];
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(0, vec!["bob"].iter().map(|s| s.to_string()).collect())
        );
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(
                1,
                vec!["data1_admin"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            vec![vec!["alice", "data2_admin"],],
            e.get_filtered_grouping_policy(
                1,
                vec!["data2_admin"].iter().map(|s| s.to_string()).collect()
            )
        );
        // Note: "" (empty string) in fieldValues means matching all values.
        assert_eq!(
            empty_policy,
            e.get_filtered_grouping_policy(
                0,
                vec!["data2_admin"].iter().map(|s| s.to_string()).collect()
            )
        );

        assert_eq!(
            true,
            e.has_grouping_policy(
                vec!["alice", "data2_admin"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            false,
            e.has_grouping_policy(
                vec!["bob", "data2_admin"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_get_list() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec!["alice", "bob", "data2_admin"],
            sort_unstable(e.get_all_subjects())
        );
        assert_eq!(vec!["data1", "data2"], sort_unstable(e.get_all_objects()));
        assert_eq!(vec!["read", "write"], sort_unstable(e.get_all_actions()));
        assert_eq!(vec!["data2_admin"], e.get_all_roles());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_modify_policies_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["bob", "data2", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_policies(vec![
            vec!["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            vec!["bob", "data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();
        e.remove_policies(vec![vec!["alice", "data1", "read"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();
        assert_eq!(
            false,
            e.has_policy(
                vec!["alice", "data1", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            false,
            e.has_policy(
                vec!["bob", "data2", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            true,
            e.has_policy(
                vec!["data2_admin", "data2", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            true,
            e.has_policy(
                vec!["data2_admin", "data2", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        e.add_policies(vec![vec!["eve", "data3", "read"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();
        e.add_policies(vec![
            vec!["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            vec!["eve", "data3", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();
        assert_eq!(
            false,
            e.has_policy(
                vec!["alice", "data1", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            false,
            e.has_policy(
                vec!["bob", "data2", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            true,
            e.has_policy(
                vec!["eve", "data3", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            true,
            e.has_policy(
                vec!["data2_admin", "data2", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );
        assert_eq!(
            true,
            e.has_policy(
                vec!["data2_admin", "data2", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
        );

        let named_policy = vec!["eve".to_string(), "data3".to_string(), "read".to_string()];
        e.remove_named_policies("p", vec![named_policy.clone()])
            .await
            .unwrap();
        e.add_named_policies("p", vec![named_policy.clone()])
            .await
            .unwrap();

        assert_eq!(
            vec![
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
                vec!["eve", "data3", "read"],
            ],
            sort_unstable(e.get_policy())
        );

        e.remove_filtered_policy(1, vec!["data2"].iter().map(|s| s.to_string()).collect())
            .await
            .unwrap();
        assert_eq!(vec![vec!["eve", "data3", "read"],], e.get_policy());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_modify_grouping_policies_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("eve", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("non_exist", None)
        );

        e.remove_grouping_policies(vec![vec!["alice", "data2_admin"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();
        e.add_grouping_policies(vec![
            vec!["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            vec!["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec!["data1_admin"], e.get_roles_for_user("bob", None));
        assert_eq!(vec!["data3_admin"], e.get_roles_for_user("eve", None));

        let named_grouping_policy = vec!["alice".to_string(), "data2_admin".to_string()];
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        e.add_named_grouping_policies("g", vec![named_grouping_policy.clone()])
            .await
            .unwrap();
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        e.remove_named_grouping_policies("g", vec![named_grouping_policy.clone()])
            .await
            .unwrap();

        e.remove_grouping_policies(vec![vec!["alice", "data2_admin"]
            .iter()
            .map(|s| s.to_string())
            .collect()])
            .await
            .unwrap();

        e.add_grouping_policies(vec![
            vec!["bob", "data1_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            vec!["eve", "data3_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ])
        .await
        .unwrap();

        assert_eq!(vec!["bob"], e.get_users_for_role("data1_admin", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_users_for_role("data2_admin", None)
        );
        assert_eq!(vec!["eve"], e.get_users_for_role("data3_admin", None));

        e.remove_filtered_grouping_policy(0, vec!["bob"].iter().map(|s| s.to_string()).collect())
            .await
            .unwrap();

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
}
