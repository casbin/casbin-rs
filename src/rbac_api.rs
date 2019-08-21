use crate::adapter::Adapter;
use crate::enforcer::Enforcer;
use crate::MgmtApi;

pub trait RbacApi {
    fn add_permission_for_user(&mut self, user: &str, permission: Vec<&str>) -> bool;
    fn add_role_for_user(&mut self, user: &str, role: &str) -> bool;
    fn delete_role_for_user(&mut self, user: &str, role: &str) -> bool;
    fn delete_roles_for_user(&mut self, user: &str) -> bool;
    fn get_roles_for_user(&mut self, name: &str) -> Vec<String>;
    fn get_users_for_role(&self, name: &str) -> Vec<String>;
    fn has_role_for_user(&mut self, name: &str, role: &str) -> bool;
    fn delete_user(&mut self, name: &str) -> bool;
    fn delete_role(&mut self, name: &str) -> bool;
}

impl<A: Adapter> RbacApi for Enforcer<A> {
    fn add_permission_for_user(&mut self, user: &str, permission: Vec<&str>) -> bool {
        let mut perm = permission;
        perm.insert(0, user);
        self.add_policy(perm)
    }

    fn add_role_for_user(&mut self, user: &str, role: &str) -> bool {
        self.add_grouping_policy(vec![user, role])
    }

    fn delete_role_for_user(&mut self, user: &str, role: &str) -> bool {
        self.remove_grouping_policy(vec![user, role])
    }

    fn delete_roles_for_user(&mut self, user: &str) -> bool {
        self.remove_filtered_grouping_policy(0, vec![user])
    }

    fn get_roles_for_user(&mut self, name: &str) -> Vec<String> {
        let mut roles = vec![];
        if let Some(t1) = self.model.model.get_mut("g") {
            if let Some(t2) = t1.get_mut("g") {
                roles = t2.rm.get_roles(name, None);
            }
        }

        roles
    }

    fn get_users_for_role(&self, name: &str) -> Vec<String> {
        self.model
            .model
            .get("g")
            .unwrap()
            .get("g")
            .unwrap()
            .rm
            .get_users(name, None)
    }

    fn has_role_for_user(&mut self, name: &str, role: &str) -> bool {
        let roles = self.get_roles_for_user(name);
        let mut has_role = false;
        for r in roles {
            if r == role {
                has_role = true;
                break;
            }
        }
        has_role
    }

    fn delete_user(&mut self, name: &str) -> bool {
        self.remove_filtered_grouping_policy(0, vec![name])
    }

    fn delete_role(&mut self, name: &str) -> bool {
        let res1 = self.remove_filtered_grouping_policy(1, vec![name]);
        let res2 = self.remove_filtered_policy(0, vec![name]);
        res1 || res2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::FileAdapter;
    use crate::enforcer::Enforcer;
    use crate::model::Model;

    #[test]
    fn test_role_api() {
        let mut m = Model::new();
        m.load_model("examples/rbac_model.conf");

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter);

        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("data2_admin"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("non_exists"));

        assert_eq!(false, e.has_role_for_user("alice", "data1_admin"));
        assert_eq!(true, e.has_role_for_user("alice", "data2_admin"));

        e.add_role_for_user("alice", "data1_admin");
        assert_eq!(
            vec!["data2_admin", "data1_admin"],
            e.get_roles_for_user("alice")
        );
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("data2_admin"));

        e.delete_role_for_user("alice", "data1_admin");
        assert_eq!(vec!["data2_admin"], e.get_roles_for_user("alice"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("data2_admin"));

        e.delete_roles_for_user("alice");
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("data2_admin"));

        e.add_role_for_user("alice", "data1_admin");
        e.delete_user("alice");
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("alice"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("bob"));
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("data2_admin"));

        e.add_role_for_user("alice", "data2_admin");
        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]));
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]));

        e.delete_role("data2_admin");
        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]));
    }
}
