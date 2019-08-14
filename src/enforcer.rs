use crate::adapter::Adapter;
use crate::effector::{DefaultEffector, EffectKind, Effector};
use crate::model::Model;
use crate::model::{load_function_map, FunctionMap};
use crate::rbac::{DefaultRoleManager, RoleManager};

use rhai::{Engine, FnRegister, Scope};

pub trait MatchFnClone: Fn(String, String) -> bool {
    fn clone_box(&self) -> Box<dyn MatchFnClone>;
}

impl<T> MatchFnClone for T
where
    T: 'static + Fn(String, String) -> bool + Clone,
{
    fn clone_box(&self) -> Box<dyn MatchFnClone> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn MatchFnClone> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

// TODO: investigate how to pass variadic parameters to rhai functions
// rbac_with_domains_model.conf takes 3 parameters
pub fn generate_g_function(rm: Box<dyn RoleManager>) -> Box<dyn MatchFnClone> {
    let cb = move |name1: String, name2: String| -> bool {
        let mut rm = rm.clone();
        return rm.has_link(name1.as_str(), name2.as_str(), vec![]);
    };
    return Box::new(cb);
}

pub struct Enforcer<A: Adapter> {
    pub model: Model,
    pub adapter: A,
    pub fm: FunctionMap,
    pub eft: Box<dyn Effector>,
    pub rm: Box<dyn RoleManager>
}

impl<A: Adapter> Enforcer<A> {
    pub fn new(m: Model, a: A) -> Self {
        let mut m = m;
        let fm = load_function_map();
        let eft = Box::new(DefaultEffector::default());
        let rm = Box::new(DefaultRoleManager::new(10));
        a.load_policy(&mut m);
        let e = Self {
            model: m,
            adapter: a,
            fm,
            eft,
            rm,
        };

        return e;
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
                let rm0 = ast.rm.clone();
                let f1 = generate_g_function(rm0);
                engine.register_fn(key.as_str(), f1.clone());
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
        return self.eft.merge_effects(ee, policy_effects, vec![]);
    }

    pub fn build_role_links(&mut self) {
        self.rm.clear();
        self.model.build_role_links(&mut self.rm);
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

    use crate::enforcer_api::RbacApi;
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
        e.add_permission_for_user("alice", vec!["data1", "invalid"]);
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
        e.add_permission_for_user("alice", vec!["data1", "read"]);
        e.add_permission_for_user("bob", vec!["data2", "write"]);
        e.add_permission_for_user("data2_admin", vec!["data2", "read"]);
        e.add_permission_for_user("data2_admin", vec!["data2", "write"]);
        e.add_role_for_user("alice", "data2_admin");

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
        e.add_permission_for_user("alice", vec!["data1", "read"]);
        e.add_permission_for_user("bob", vec!["data2", "write"]);

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
