use crate::adapter::Adapter;
use crate::effector::{DefaultEffector, EffectKind, Effector};
use crate::model::Model;
use crate::model::{load_function_map, FunctionMap};
use crate::rbac::{DefaultRoleManager, RoleManager};
use crate::Result;

use rhai::{Engine, RegisterFn, Scope};

pub trait MatchFnClone2: Fn(String, String) -> bool {
    fn clone_box(&self) -> Box<dyn MatchFnClone2>;
}

impl<T> MatchFnClone2 for T
where
    T: 'static + Fn(String, String) -> bool + Clone,
{
    fn clone_box(&self) -> Box<dyn MatchFnClone2> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn MatchFnClone2> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

pub trait MatchFnClone3: Fn(String, String, String) -> bool {
    fn clone_box(&self) -> Box<dyn MatchFnClone3>;
}

impl<T> MatchFnClone3 for T
where
    T: 'static + Fn(String, String, String) -> bool + Clone,
{
    fn clone_box(&self) -> Box<dyn MatchFnClone3> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn MatchFnClone3> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

pub fn generate_gg2_function(rm: Box<dyn RoleManager>) -> Box<dyn MatchFnClone2> {
    let cb = move |name1: String, name2: String| -> bool {
        let mut rm = rm.clone();
        rm.has_link(name1.as_str(), name2.as_str(), None)
    };
    Box::new(cb)
}

pub fn generate_gg3_function(rm: Box<dyn RoleManager>) -> Box<dyn MatchFnClone3> {
    let cb = move |name1: String, name2: String, domain: String| -> bool {
        let mut rm = rm.clone();
        rm.has_link(name1.as_str(), name2.as_str(), Some(domain.as_str()))
    };
    Box::new(cb)
}

pub struct Enforcer<A: Adapter> {
    pub model: Model,
    pub adapter: A,
    pub fm: FunctionMap,
    pub eft: Box<dyn Effector>,
    pub rm: Box<dyn RoleManager>,
    pub auto_save: bool,
    auto_build_role_links: bool,
}

impl<A: Adapter> Enforcer<A> {
    pub fn new(m: Model, a: A) -> Self {
        let m = m;
        let fm = load_function_map();
        let eft = Box::new(DefaultEffector::default());
        let rm = Box::new(DefaultRoleManager::new(10));

        let mut e = Self {
            model: m,
            adapter: a,
            fm,
            eft,
            rm,
            auto_save: true,
            auto_build_role_links: true,
        };
        // TODO: check filtered adapter, match over a implementor?
        e.load_policy().unwrap();
        e
    }

    pub fn enforce(&self, rvals: Vec<&str>) -> bool {
        let mut engine = Engine::new();
        let mut scope: Scope = Vec::new();
        for (i, token) in self
            .model
            .model
            .get("r")
            .unwrap()
            .get("r")
            .unwrap()
            .tokens
            .iter()
            .enumerate()
        {
            // let r_sub = "alice"; or let r_obj = "resource1"; or let r_sub = "GET";
            let scope_exp = format!("let {} = \"{}\";", token.clone(), rvals[i]);
            engine
                .eval_with_scope::<()>(&mut scope, scope_exp.as_str())
                .expect("set rtoken scope failed");
        }

        for (key, func) in self.fm.iter() {
            engine.register_fn(key.as_str(), func.clone());
        }
        if let Some(g_result) = self.model.model.get("g") {
            for (key, ast) in g_result.iter() {
                if key == "g" {
                    let g2 = generate_gg2_function(ast.rm.clone());
                    engine.register_fn("gg2", g2.clone());
                    let g3 = generate_gg3_function(ast.rm.clone());
                    engine.register_fn("gg3", g3.clone());
                } else {
                    let g2 = generate_gg2_function(ast.rm.clone());
                    engine.register_fn("g2", g2.clone());
                }
            }
        }
        let expstring = self
            .model
            .model
            .get("m")
            .unwrap()
            .get("m")
            .unwrap()
            .value
            .clone();
        let mut policy_effects: Vec<EffectKind> = vec![];
        let policy_len = self
            .model
            .model
            .get("p")
            .unwrap()
            .get("p")
            .unwrap()
            .policy
            .len();
        if policy_len != 0 {
            policy_effects = vec![EffectKind::Allow; policy_len];
            if self
                .model
                .model
                .get("r")
                .unwrap()
                .get("r")
                .unwrap()
                .tokens
                .len()
                != rvals.len()
            {
                return false;
            }
            for (i, pvals) in self
                .model
                .model
                .get("p")
                .unwrap()
                .get("p")
                .unwrap()
                .policy
                .iter()
                .enumerate()
            {
                if self
                    .model
                    .model
                    .get("p")
                    .unwrap()
                    .get("p")
                    .unwrap()
                    .tokens
                    .len()
                    != pvals.len()
                {
                    return false;
                }
                for (pi, ptoken) in self
                    .model
                    .model
                    .get("p")
                    .unwrap()
                    .get("p")
                    .unwrap()
                    .tokens
                    .iter()
                    .enumerate()
                {
                    // let p_sub = "alice"; or let p_obj = "resource1"; or let p_sub = "GET";
                    let scope_exp = format!("let {} = \"{}\";", ptoken.clone(), pvals[pi]);
                    engine
                        .eval_with_scope::<()>(&mut scope, scope_exp.as_str())
                        .expect("set ptoken scope failed");
                }

                let eval_result = engine
                    .eval_with_scope::<bool>(&mut scope, expstring.as_str())
                    .expect("eval expression failed");
                if !eval_result {
                    policy_effects[i] = EffectKind::Indeterminate;
                    continue;
                }
                if let Some(j) = self
                    .model
                    .model
                    .get("p")
                    .unwrap()
                    .get("p")
                    .unwrap()
                    .tokens
                    .iter()
                    .position(|x| x == &String::from("p_eft"))
                {
                    let eft = &pvals[j];
                    if eft == "allow" {
                        policy_effects[i] = EffectKind::Allow;
                    } else if eft == "deny" {
                        policy_effects[i] = EffectKind::Deny;
                    } else {
                        policy_effects[i] = EffectKind::Indeterminate;
                    }
                } else {
                    policy_effects[i] = EffectKind::Allow;
                }
                if self.model.model.get("e").unwrap().get("e").unwrap().value
                    == "priority(p_eft) || deny"
                {
                    break;
                }
            }
        } else {
            for token in self
                .model
                .model
                .get("p")
                .unwrap()
                .get("p")
                .unwrap()
                .tokens
                .iter()
            {
                let scope_exp = format!("let {} = \"{}\";", token.clone(), "");
                engine
                    .eval_with_scope::<()>(&mut scope, scope_exp.as_str())
                    .expect("set ptoken in else scope failed");
            }
            let eval_result = engine
                .eval_with_scope::<bool>(&mut scope, expstring.as_str())
                .expect("eval expression failed");
            if eval_result {
                policy_effects.push(EffectKind::Allow);
            } else {
                policy_effects.push(EffectKind::Indeterminate);
            }
        }

        let ee = self
            .model
            .model
            .get("e")
            .unwrap()
            .get("e")
            .unwrap()
            .value
            .clone();
        self.eft.merge_effects(ee, policy_effects, vec![])
    }

    pub fn build_role_links(&mut self) -> Result<()> {
        self.rm.clear();
        self.model.build_role_links(&mut self.rm)?;
        Ok(())
    }

    pub fn load_policy(&mut self) -> Result<()> {
        self.model.clear_policy();
        self.adapter.load_policy(&mut self.model)?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }
        Ok(())
    }

    pub fn clear_policy(&mut self) {
        self.model.clear_policy();
    }

    pub fn enable_auto_save(&mut self, auto_save: bool) {
        self.auto_save = auto_save;
    }

    pub fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool) {
        self.auto_build_role_links = auto_build_role_links;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{FileAdapter, MemoryAdapter};

    #[test]
    fn test_key_match_model_in_memory() {
        let mut m = Model::new();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv");
        let e = Enforcer::new(m, adapter);
        assert_eq!(
            true,
            e.enforce(vec!["alice", "/alice_data/resource1", "GET"])
        );
        assert_eq!(
            true,
            e.enforce(vec!["alice", "/alice_data/resource1", "POST"])
        );
        assert_eq!(
            true,
            e.enforce(vec!["alice", "/alice_data/resource2", "GET"])
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/alice_data/resource2", "POST"])
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource1", "GET"])
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource1", "POST"])
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource2", "GET"])
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource2", "POST"])
        );

        assert_eq!(
            false,
            e.enforce(vec!["bob", "/alice_data/resource1", "GET"])
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "/alice_data/resource1", "POST"])
        );
        assert_eq!(true, e.enforce(vec!["bob", "/alice_data/resource2", "GET"]));
        assert_eq!(
            false,
            e.enforce(vec!["bob", "/alice_data/resource2", "POST"])
        );
        assert_eq!(false, e.enforce(vec!["bob", "/bob_data/resource1", "GET"]));
        assert_eq!(true, e.enforce(vec!["bob", "/bob_data/resource1", "POST"]));
        assert_eq!(false, e.enforce(vec!["bob", "/bob_data/resource2", "GET"]));
        assert_eq!(true, e.enforce(vec!["bob", "/bob_data/resource2", "POST"]));

        assert_eq!(true, e.enforce(vec!["cathy", "/cathy_data", "GET"]));
        assert_eq!(true, e.enforce(vec!["cathy", "/cathy_data", "POST"]));
        assert_eq!(false, e.enforce(vec!["cathy", "/cathy_data", "DELETE"]));
    }

    #[test]
    fn test_key_match_model_in_memory_deny() {
        let mut m = Model::new();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "!some(where (p.eft == deny))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv");
        let e = Enforcer::new(m, adapter);
        assert_eq!(
            true,
            e.enforce(vec!["alice", "/alice_data/resource2", "POST"])
        );
    }

    use crate::RbacApi;
    #[test]
    fn test_rbac_model_in_memory_indeterminate() {
        let mut m = Model::new();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        );

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter);
        e.add_permission_for_user("alice", vec!["data1", "invalid"])
            .unwrap();
        assert_eq!(false, e.enforce(vec!["alice", "data1", "read"]));
    }

    #[test]
    fn test_rbac_model_in_memory() {
        let mut m = Model::new();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        );

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter);
        e.add_permission_for_user("alice", vec!["data1", "read"])
            .unwrap();
        e.add_permission_for_user("bob", vec!["data2", "write"])
            .unwrap();
        e.add_permission_for_user("data2_admin", vec!["data2", "read"])
            .unwrap();
        e.add_permission_for_user("data2_admin", vec!["data2", "write"])
            .unwrap();
        e.add_role_for_user("alice", "data2_admin").unwrap();

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]));
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]));
    }

    #[test]
    fn test_not_used_rbac_model_in_memory() {
        let mut m = Model::new();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        );

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter);
        e.add_permission_for_user("alice", vec!["data1", "read"])
            .unwrap();
        e.add_permission_for_user("bob", vec!["data2", "write"])
            .unwrap();

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]));
    }

    #[test]
    fn test_ip_match_model() {
        let m = Model::new_from_file("examples/ipmatch_model.conf");

        let adapter = FileAdapter::new("examples/ipmatch_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert!(e.enforce(vec!["192.168.2.123", "data1", "read"]));

        assert!(e.enforce(vec!["10.0.0.5", "data2", "write"]));

        assert!(!e.enforce(vec!["192.168.2.123", "data1", "write"]));
        assert!(!e.enforce(vec!["192.168.2.123", "data2", "read"]));
        assert!(!e.enforce(vec!["192.168.2.123", "data2", "write"]));

        assert!(!e.enforce(vec!["192.168.0.123", "data1", "read"]));
        assert!(!e.enforce(vec!["192.168.0.123", "data1", "write"]));
        assert!(!e.enforce(vec!["192.168.0.123", "data2", "read"]));
        assert!(!e.enforce(vec!["192.168.0.123", "data2", "write"]));

        assert!(!e.enforce(vec!["10.0.0.5", "data1", "read"]));
        assert!(!e.enforce(vec!["10.0.0.5", "data1", "write"]));
        assert!(!e.enforce(vec!["10.0.0.5", "data2", "read"]));

        assert!(!e.enforce(vec!["192.168.0.1", "data1", "read"]));
        assert!(!e.enforce(vec!["192.168.0.1", "data1", "write"]));
        assert!(!e.enforce(vec!["192.168.0.1", "data2", "read"]));
        assert!(!e.enforce(vec!["192.168.0.1", "data2", "write"]));
    }

    use crate::MgmtApi;
    #[test]
    fn test_enable_auto_save() {
        let m = Model::new_from_file("examples/basic_model.conf");

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m, adapter);
        e.enable_auto_save(false);
        e.remove_policy(vec!["alice", "data1", "read"]).unwrap();
        e.load_policy().unwrap();

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]));

        e.enable_auto_save(true);
        e.remove_policy(vec!["alice", "data1", "read"]).unwrap();
        e.load_policy().unwrap();
        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]));
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]));
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]));
    }

    #[test]
    fn test_role_links() {
        let m = Model::new_from_file("examples/rbac_model.conf");

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter);
        e.enable_auto_build_role_links(false);
        e.build_role_links().unwrap();
        assert_eq!(false, e.enforce(vec!["user501", "data9", "read"]));
    }

    #[test]
    fn test_get_and_set_model() {
        let m1 = Model::new_from_file("examples/basic_model.conf");
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1);

        assert_eq!(false, e.enforce(vec!["root", "data1", "read"]));

        let m2 = Model::new_from_file("examples/basic_with_root_model.conf");
        let adapter2 = FileAdapter::new("examples/basic_policy.csv");
        let e2 = Enforcer::new(m2, adapter2);

        e.model = e2.model;
        assert_eq!(true, e.enforce(vec!["root", "data1", "read"]));
    }

    #[test]
    fn test_get_and_set_adapter_in_mem() {
        let m1 = Model::new_from_file("examples/basic_model.conf");
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1);

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]));

        let m2 = Model::new_from_file("examples/basic_model.conf");
        let adapter2 = FileAdapter::new("examples/basic_inverse_policy.csv");
        let e2 = Enforcer::new(m2, adapter2);

        e.adapter = e2.adapter;
        e.load_policy().unwrap();
        assert_eq!(false, e.enforce(vec!["alice", "data1", "read"]));
        assert_eq!(true, e.enforce(vec!["alice", "data1", "write"]));
    }
}
