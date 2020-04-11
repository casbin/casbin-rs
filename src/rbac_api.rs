use crate::{MgmtApi, Result};

use async_trait::async_trait;

use std::collections::HashSet;

#[async_trait]
pub trait RbacApi: MgmtApi {
    async fn add_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool>;
    async fn add_permissions_for_user(
        &mut self,
        user: &str,
        permissions: Vec<Vec<String>>,
    ) -> Result<bool>;
    async fn add_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool>;
    async fn add_roles_for_user(
        &mut self,
        user: &str,
        roles: Vec<String>,
        domain: Option<&str>,
    ) -> Result<bool>;
    async fn delete_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool>;
    async fn delete_roles_for_user(&mut self, user: &str, domain: Option<&str>) -> Result<bool>;
    async fn delete_user(&mut self, name: &str) -> Result<bool>;
    async fn delete_role(&mut self, name: &str) -> Result<bool>;

    async fn delete_permission(&mut self, permission: Vec<String>) -> Result<bool> {
        self.remove_filtered_policy(1, permission).await
    }
    async fn delete_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool>;

    async fn delete_permissions_for_user(&mut self, user: &str) -> Result<bool> {
        self.remove_filtered_policy(0, vec![user].iter().map(|s| (*s).to_string()).collect())
            .await
    }

    fn get_roles_for_user(&mut self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn get_users_for_role(&self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn has_role_for_user(&mut self, name: &str, role: &str, domain: Option<&str>) -> bool;
    fn get_permissions_for_user(&self, user: &str, domain: Option<&str>) -> Vec<Vec<String>>;
    fn has_permission_for_user(&self, user: &str, permission: Vec<String>) -> bool;
    fn get_implicit_roles_for_user(&mut self, name: &str, domain: Option<&str>) -> Vec<String>;
    fn get_implicit_permissions_for_user(
        &mut self,
        name: &str,
        domain: Option<&str>,
    ) -> Vec<Vec<String>>;
    async fn get_implicit_users_for_permission(&mut self, permission: Vec<String>) -> Vec<String>;
}

#[async_trait]
impl<T> RbacApi for T
where
    T: MgmtApi,
{
    async fn add_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool> {
        let mut perm = permission;
        perm.insert(0, user.to_string());
        self.add_policy(perm).await
    }

    async fn add_permissions_for_user(
        &mut self,
        user: &str,
        permissions: Vec<Vec<String>>,
    ) -> Result<bool> {
        let perms = permissions
            .into_iter()
            .map(|mut p| {
                p.insert(0, user.to_string());
                p
            })
            .collect();
        self.add_policies(perms).await
    }

    async fn add_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool> {
        self.add_grouping_policy(if let Some(domain) = domain {
            vec![user, role, domain]
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            vec![user, role].iter().map(|s| (*s).to_string()).collect()
        })
        .await
    }

    async fn add_roles_for_user(
        &mut self,
        user: &str,
        roles: Vec<String>,
        domain: Option<&str>,
    ) -> Result<bool> {
        self.add_grouping_policies(
            roles
                .into_iter()
                .map(|role| {
                    if let Some(domain) = domain {
                        vec![user.to_string(), role, domain.to_string()]
                    } else {
                        vec![user.to_string(), role]
                    }
                })
                .collect(),
        )
        .await
    }

    async fn delete_role_for_user(
        &mut self,
        user: &str,
        role: &str,
        domain: Option<&str>,
    ) -> Result<bool> {
        self.remove_grouping_policy(if let Some(domain) = domain {
            vec![user, role, domain]
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            vec![user, role].iter().map(|s| (*s).to_string()).collect()
        })
        .await
    }

    async fn delete_roles_for_user(&mut self, user: &str, domain: Option<&str>) -> Result<bool> {
        self.remove_filtered_grouping_policy(
            0,
            if let Some(domain) = domain {
                vec![user, "", domain]
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                vec![user].iter().map(|s| (*s).to_string()).collect()
            },
        )
        .await
    }

    fn get_roles_for_user(&mut self, name: &str, domain: Option<&str>) -> Vec<String> {
        let mut roles = vec![];
        if let Some(t1) = self.get_mut_model().get_mut_model().get_mut("g") {
            if let Some(t2) = t1.get_mut("g") {
                roles = t2.rm.write().unwrap().get_roles(name, domain);
            }
        }

        roles
    }

    fn get_users_for_role(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        if let Some(t1) = self.get_model().get_model().get("g") {
            if let Some(t2) = t1.get("g") {
                return t2.rm.read().unwrap().get_users(name, domain);
            }
        }
        return vec![];
    }

    fn has_role_for_user(&mut self, name: &str, role: &str, domain: Option<&str>) -> bool {
        let roles = self.get_roles_for_user(name, domain);
        let mut has_role = false;
        for r in roles {
            if r == role {
                has_role = true;
                break;
            }
        }
        has_role
    }

    async fn delete_user(&mut self, name: &str) -> Result<bool> {
        self.remove_filtered_grouping_policy(
            0,
            vec![name].iter().map(|s| (*s).to_string()).collect(),
        )
        .await
    }

    async fn delete_role(&mut self, name: &str) -> Result<bool> {
        let res1 = self
            .remove_filtered_grouping_policy(
                1,
                vec![name].iter().map(|s| (*s).to_string()).collect(),
            )
            .await?;
        let res2 = self
            .remove_filtered_policy(0, vec![name].iter().map(|s| (*s).to_string()).collect())
            .await?;
        Ok(res1 || res2)
    }

    async fn delete_permission_for_user(
        &mut self,
        user: &str,
        permission: Vec<String>,
    ) -> Result<bool> {
        let mut permission = permission;
        permission.insert(0, user.to_string());
        self.remove_policy(permission).await
    }

    fn get_permissions_for_user(&self, user: &str, domain: Option<&str>) -> Vec<Vec<String>> {
        self.get_filtered_policy(0, {
            if let Some(domain) = domain {
                vec![user, domain]
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                vec![user].iter().map(|s| (*s).to_string()).collect()
            }
        })
    }

    fn has_permission_for_user(&self, user: &str, permission: Vec<String>) -> bool {
        let mut permission = permission;
        permission.insert(0, user.to_string());
        self.has_policy(permission)
    }

    fn get_implicit_roles_for_user(&mut self, name: &str, domain: Option<&str>) -> Vec<String> {
        let mut res: HashSet<String> = HashSet::new();
        let roles = self
            .get_role_manager()
            .write()
            .unwrap()
            .get_roles(name, domain);
        res.extend(roles.clone());

        roles.iter().for_each(|role| {
            res.extend(self.get_implicit_roles_for_user(role, domain));
        });

        res.into_iter().collect()
    }

    fn get_implicit_permissions_for_user(
        &mut self,
        user: &str,
        domain: Option<&str>,
    ) -> Vec<Vec<String>> {
        let mut roles = self.get_implicit_roles_for_user(user, domain);
        roles.insert(0, user.to_owned());

        let mut res = vec![];

        for role in roles.iter() {
            let permissions = self.get_permissions_for_user(role, domain);
            res.extend(permissions);
        }
        res
    }

    async fn get_implicit_users_for_permission(&mut self, permission: Vec<String>) -> Vec<String> {
        let subjects = self.get_all_subjects();
        let roles = self.get_all_roles();

        let users: Vec<String> = subjects
            .iter()
            .filter(|subject| !roles.contains(subject))
            .map(String::from)
            .collect();

        let mut res: Vec<String> = vec![];
        for user in users.iter() {
            let mut req = permission.clone();
            req.insert(0, user.to_string());
            if let Ok(r) = self.enforce(&req).await {
                if r {
                    res.push(user.to_owned());
                }
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    fn sort_unstable<T: Ord>(mut v: Vec<T>) -> Vec<T> {
        v.sort_unstable();
        v
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_role_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("non_exists", None)
        );

        assert_eq!(false, e.has_role_for_user("alice", "data1_admin", None));
        assert_eq!(true, e.has_role_for_user("alice", "data2_admin", None));

        e.add_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        assert_eq!(
            vec!["data2_admin", "data1_admin"],
            e.get_roles_for_user("alice", None)
        );
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.delete_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.delete_roles_for_user("alice", None).await.unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.add_roles_for_user(
            "bob",
            vec!["data1_admin", "data2_admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(
            vec!["data1_admin", "data2_admin"],
            e.get_roles_for_user("bob", None)
        );

        e.delete_roles_for_user("bob", None).await.unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));

        e.add_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        e.delete_user("alice").await.unwrap();
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice", None));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob", None));
        assert_eq!(
            vec![String::new(); 0],
            e.get_roles_for_user("data2_admin", None)
        );

        e.add_role_for_user("alice", "data2_admin", None)
            .await
            .unwrap();
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );

        e.delete_role("data2_admin").await.unwrap();
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data2", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data1", "write"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "data2", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "data2", "write"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_role_api_threads() {
        use std::sync::{Arc, RwLock};
        use std::thread;

        #[cfg(feature = "runtime-async-std")]
        use async_std::task;

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Arc::new(RwLock::new(Enforcer::new(m, adapter).await.unwrap()));
        let ee = e.clone();

        assert_eq!(
            vec!["data2_admin"],
            e.write().unwrap().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("data2_admin", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("non_exists", None)
        );

        assert_eq!(
            false,
            e.write()
                .unwrap()
                .has_role_for_user("alice", "data1_admin", None)
        );
        assert_eq!(
            true,
            e.write()
                .unwrap()
                .has_role_for_user("alice", "data2_admin", None)
        );

        thread::spawn(move || {
            cfg_if::cfg_if! {
                if #[cfg(feature = "runtime-async-std")] {
                    task::block_on(async move {
                        ee.write()
                            .unwrap()
                            .add_role_for_user("alice", "data1_admin", None)
                            .await
                            .unwrap();

                        assert_eq!(
                            vec!["data2_admin", "data1_admin"],
                            ee.write().unwrap().get_roles_for_user("alice", None)
                        );
                        assert_eq!(
                            vec![String::new(); 0],
                            ee.write().unwrap().get_roles_for_user("bob", None)
                        );
                        assert_eq!(
                            vec![String::new(); 0],
                            ee.write().unwrap().get_roles_for_user("data2_admin", None)
                        );

                        ee.write()
                        .unwrap()
                        .add_roles_for_user("bob",vec!["data2_admin"].iter().map(|s| s.to_string()).collect(), None)
                        .await
                        .unwrap();

                        assert_eq!(
                            vec!["data2_admin", "data1_admin"],
                            ee.write().unwrap().get_roles_for_user("alice", None)
                        );
                        assert_eq!(
                            vec!["data2_admin"],
                            ee.write().unwrap().get_roles_for_user("bob", None)
                        );
                        assert_eq!(
                            vec![String::new(); 0],
                            ee.write().unwrap().get_roles_for_user("data2_admin", None)
                        );
                    });
                } else if #[cfg(feature = "runtime-tokio")] {
                    tokio::runtime::Builder::new()
                        .basic_scheduler()
                        .threaded_scheduler()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(async move {
                            ee.write()
                                .unwrap()
                                .add_role_for_user("alice", "data1_admin", None)
                                .await
                                .unwrap();

                            assert_eq!(
                                vec!["data2_admin", "data1_admin"],
                                ee.write().unwrap().get_roles_for_user("alice", None)
                            );
                            assert_eq!(
                                vec![String::new(); 0],
                                ee.write().unwrap().get_roles_for_user("bob", None)
                            );
                            assert_eq!(
                                vec![String::new(); 0],
                                ee.write().unwrap().get_roles_for_user("data2_admin", None)
                            );

                            ee.write()
                            .unwrap()
                            .add_roles_for_user("bob",vec!["data2_admin".to_owned()], None)
                            .await
                            .unwrap();

                            assert_eq!(
                                vec!["data2_admin", "data1_admin"],
                                ee.write().unwrap().get_roles_for_user("alice", None)
                            );
                            assert_eq!(
                                vec!["data2_admin"],
                                ee.write().unwrap().get_roles_for_user("bob", None)
                            );
                            assert_eq!(
                                vec![String::new(); 0],
                                ee.write().unwrap().get_roles_for_user("data2_admin", None)
                            );
                        });
                }
            }
        })
        .join()
        .unwrap();

        e.write()
            .unwrap()
            .delete_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        e.write()
            .unwrap()
            .delete_roles_for_user("bob", None)
            .await
            .unwrap();
        assert_eq!(
            vec!["data2_admin"],
            e.write().unwrap().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("data2_admin", None)
        );

        e.write()
            .unwrap()
            .delete_roles_for_user("alice", None)
            .await
            .unwrap();
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("data2_admin", None)
        );

        e.write()
            .unwrap()
            .add_role_for_user("alice", "data1_admin", None)
            .await
            .unwrap();
        e.write().unwrap().delete_user("alice").await.unwrap();
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("alice", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("bob", None)
        );
        assert_eq!(
            vec![String::new(); 0],
            e.write().unwrap().get_roles_for_user("data2_admin", None)
        );

        e.write()
            .unwrap()
            .add_role_for_user("alice", "data2_admin", None)
            .await
            .unwrap();
        assert_eq!(
            true,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data2", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data2", "write"])
                .await
                .unwrap()
        );

        e.write().unwrap().delete_role("data2_admin").await.unwrap();
        assert_eq!(
            true,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["alice", "data2", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data1", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data1", "write"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data2", "read"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.write()
                .unwrap()
                .enforce(&vec!["bob", "data2", "write"])
                .await
                .unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_permission_api() {
        let m = DefaultModel::from_file("examples/basic_without_resources_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_without_resources_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(true, e.enforce(&vec!["alice", "read"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "write"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "read"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "write"]).await.unwrap());

        assert_eq!(
            vec![vec!["alice", "read"]],
            e.get_permissions_for_user("alice", None)
        );
        assert_eq!(
            vec![vec!["bob", "write"]],
            e.get_permissions_for_user("bob", None)
        );

        assert_eq!(
            true,
            e.has_permission_for_user(
                "alice",
                vec!["read"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            false,
            e.has_permission_for_user(
                "alice",
                vec!["write"].iter().map(|s| s.to_string()).collect()
            )
        );
        assert_eq!(
            false,
            e.has_permission_for_user("bob", vec!["read"].iter().map(|s| s.to_string()).collect())
        );
        assert_eq!(
            true,
            e.has_permission_for_user("bob", vec!["write"].iter().map(|s| s.to_string()).collect())
        );

        e.delete_permission(vec!["read"].iter().map(|s| s.to_string()).collect())
            .await
            .unwrap();

        assert_eq!(false, e.enforce(&vec!["alice", "read"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "write"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "read"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "write"]).await.unwrap());

        e.add_permission_for_user("bob", vec!["read"].iter().map(|s| s.to_string()).collect())
            .await
            .unwrap();
        e.add_permissions_for_user(
            "eve",
            vec![
                vec!["read"].iter().map(|s| s.to_string()).collect(),
                vec!["write"].iter().map(|s| s.to_string()).collect(),
            ],
        )
        .await
        .unwrap();

        assert_eq!(false, e.enforce(&vec!["alice", "read"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "write"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "read"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "write"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["eve", "read"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["eve", "write"]).await.unwrap());

        e.delete_permission_for_user("bob", vec!["read"].iter().map(|s| s.to_string()).collect())
            .await
            .unwrap();

        assert_eq!(false, e.enforce(&vec!["alice", "read"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "write"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "read"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "write"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["eve", "read"]).await.unwrap());
        assert_eq!(true, e.enforce(&vec!["eve", "write"]).await.unwrap());

        e.delete_permissions_for_user("bob").await.unwrap();
        e.delete_permissions_for_user("eve").await.unwrap();

        assert_eq!(false, e.enforce(&vec!["alice", "read"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "write"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "read"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "write"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["eve", "read"]).await.unwrap());
        assert_eq!(false, e.enforce(&vec!["eve", "write"]).await.unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_implicit_role_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_hierarchy_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![vec!["alice", "data1", "read"]],
            e.get_permissions_for_user("alice", None)
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_permissions_for_user("bob", None)
        );

        assert_eq!(
            vec!["admin", "data1_admin", "data2_admin"],
            sort_unstable(e.get_implicit_roles_for_user("alice", None))
        );
        assert_eq!(
            vec![String::new(); 0],
            e.get_implicit_roles_for_user("bob", None)
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_implicit_permission_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_hierarchy_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![vec!["alice", "data1", "read"]],
            e.get_permissions_for_user("alice", None)
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_permissions_for_user("bob", None)
        );

        assert_eq!(
            vec![
                vec!["alice", "data1", "read"],
                vec!["data1_admin", "data1", "read"],
                vec!["data1_admin", "data1", "write"],
                vec!["data2_admin", "data2", "read"],
                vec!["data2_admin", "data2", "write"],
            ],
            sort_unstable(e.get_implicit_permissions_for_user("alice", None))
        );
        assert_eq!(
            vec![vec!["bob", "data2", "write"]],
            e.get_implicit_permissions_for_user("bob", None)
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_implicit_user_api() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_hierarchy_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec!["alice"],
            e.get_implicit_users_for_permission(
                vec!["data1", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
            .await
        );
        assert_eq!(
            vec!["alice"],
            e.get_implicit_users_for_permission(
                vec!["data1", "write"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
            .await
        );
        assert_eq!(
            vec!["alice"],
            e.get_implicit_users_for_permission(
                vec!["data2", "read"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            )
            .await
        );
        assert_eq!(
            vec!["alice", "bob"],
            sort_unstable(
                e.get_implicit_users_for_permission(
                    vec!["data2", "write"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                )
                .await
            )
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_implicit_permission_api_with_domain() {
        let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_hierarchy_with_domains_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert_eq!(
            vec![
                vec!["alice", "domain1", "data2", "read"],
                vec!["role:reader", "domain1", "data1", "read"],
                vec!["role:writer", "domain1", "data1", "write"],
            ],
            sort_unstable(e.get_implicit_permissions_for_user("alice", Some("domain1")))
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_pattern_matching_fn() {
        let mut e = Enforcer::new(
            "examples/rbac_with_pattern_model.conf",
            "examples/rbac_with_pattern_policy.csv",
        )
        .await
        .unwrap();

        use crate::model::key_match2;

        e.add_matching_fn(key_match2).unwrap();

        assert!(e.enforce(&["alice", "/pen/1", "GET"]).await.unwrap());
        assert!(e.enforce(&["alice", "/pen2/1", "GET"]).await.unwrap());
        assert!(e.enforce(&["alice", "/book/1", "GET"]).await.unwrap());
        assert!(e.enforce(&["alice", "/book/2", "GET"]).await.unwrap());
        assert!(e.enforce(&["alice", "/pen/1", "GET"]).await.unwrap());
        assert!(!e.enforce(&["alice", "/pen/2", "GET"]).await.unwrap());
        assert!(!e.enforce(&["bob", "/book/1", "GET"]).await.unwrap());
        assert!(!e.enforce(&["bob", "/book/2", "GET"]).await.unwrap());
        assert!(e.enforce(&["bob", "/pen/1", "GET"]).await.unwrap());
        assert!(e.enforce(&["bob", "/pen/2", "GET"]).await.unwrap());

        assert_eq!(
            vec!["/book/:id", "book_group"],
            sort_unstable(e.get_implicit_roles_for_user("/book/1", None))
        );

        assert_eq!(
            vec!["/pen/:id", "pen_group"],
            sort_unstable(e.get_implicit_roles_for_user("/pen/1", None))
        );
    }
}
