use crate::adapter::Adapter;
use crate::effector::{DefaultEffector, EffectKind, Effector};
use crate::error::{Error, ModelError};
use crate::model::Model;
use crate::model::{in_match, load_function_map, FunctionMap};
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

/// Enforcer is the main interface for authorization enforcement and policy management.
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
    /// Enforcer::new creates an enforcer via file or DB.
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

    /// Enforce decides whether a "subject" can access a "object" with the operation "action",
    /// input parameters are usually: (sub, obj, act).
    ///
    /// # Examples
    /// ```
    /// use casbin::{Enforcer, Model, FileAdapter};
    ///
    /// let m = Model::from_file("examples/basic_model.conf").unwrap();
    /// let adapter = FileAdapter::new("examples/basic_policy.csv");
    /// let e = Enforcer::new(m, adapter);
    /// assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
    /// ```
    pub fn enforce(&self, rvals: Vec<&str>) -> Result<bool> {
        let mut engine = Engine::new();
        let mut scope: Scope = Vec::new();
        let r = self
            .model
            .model
            .get("r")
            .ok_or_else(|| {
                Error::ModelError(ModelError::R(
                    "Missing request definition in conf file".to_owned(),
                ))
            })?
            .get("r")
            .ok_or_else(|| {
                Error::ModelError(ModelError::R(
                    "Missing request secion in conf file".to_owned(),
                ))
            })?;
        let p = self
            .model
            .model
            .get("p")
            .ok_or_else(|| {
                Error::ModelError(ModelError::P(
                    "Missing policy definition in conf file".to_owned(),
                ))
            })?
            .get("p")
            .ok_or_else(|| {
                Error::ModelError(ModelError::P(
                    "Missing policy section in conf file".to_owned(),
                ))
            })?;
        let m = self
            .model
            .model
            .get("m")
            .ok_or_else(|| {
                Error::ModelError(ModelError::M(
                    "Missing matcher definition in conf file".to_owned(),
                ))
            })?
            .get("m")
            .ok_or_else(|| {
                Error::ModelError(ModelError::M(
                    "Missing matcher section in conf file".to_owned(),
                ))
            })?;
        let e = self
            .model
            .model
            .get("e")
            .ok_or_else(|| {
                Error::ModelError(ModelError::E(
                    "Missing effector definition in conf file".to_owned(),
                ))
            })?
            .get("e")
            .ok_or_else(|| {
                Error::ModelError(ModelError::E(
                    "Missing effector section in conf file".to_owned(),
                ))
            })?;

        for (i, token) in r.tokens.iter().enumerate() {
            let scope_exp = format!("let {} = \"{}\";", token.clone(), rvals[i]);
            engine.eval_with_scope::<()>(&mut scope, scope_exp.as_str())?;
        }

        for (key, func) in self.fm.iter() {
            engine.register_fn(key.as_str(), func.clone());
        }
        engine.register_fn("inMatch", in_match);
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
        let expstring = m.value.clone();
        let mut policy_effects: Vec<EffectKind> = vec![];
        let policy_len = p.policy.len();
        if policy_len != 0 {
            policy_effects = vec![EffectKind::Allow; policy_len];
            if r.tokens.len() != rvals.len() {
                return Ok(false);
            }
            for (i, pvals) in p.policy.iter().enumerate() {
                if p.tokens.len() != pvals.len() {
                    return Ok(false);
                }
                for (pi, ptoken) in p.tokens.iter().enumerate() {
                    // let p_sub = "alice"; or let p_obj = "resource1"; or let p_sub = "GET";
                    let scope_exp = format!("let {} = \"{}\";", ptoken.clone(), pvals[pi]);
                    engine.eval_with_scope::<()>(&mut scope, scope_exp.as_str())?;
                }

                let eval_result = engine.eval_with_scope::<bool>(&mut scope, expstring.as_str())?;
                if !eval_result {
                    policy_effects[i] = EffectKind::Indeterminate;
                    continue;
                }
                if let Some(j) = p.tokens.iter().position(|x| x == &String::from("p_eft")) {
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
            for token in p.tokens.iter() {
                let scope_exp = format!("let {} = \"{}\";", token.clone(), "");
                engine.eval_with_scope::<()>(&mut scope, scope_exp.as_str())?;
            }
            let eval_result = engine.eval_with_scope::<bool>(&mut scope, expstring.as_str())?;
            if eval_result {
                policy_effects.push(EffectKind::Allow);
            } else {
                policy_effects.push(EffectKind::Indeterminate);
            }
        }

        let ee = e.value.clone();

        Ok(self.eft.merge_effects(ee, policy_effects, vec![]))
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
        let mut m = Model::default();
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
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["alice", "/alice_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["alice", "/alice_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/alice_data/resource2", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource1", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "/bob_data/resource2", "POST"])
                .unwrap()
        );

        assert_eq!(
            false,
            e.enforce(vec!["bob", "/alice_data/resource1", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "/alice_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "/alice_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "/alice_data/resource2", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "/bob_data/resource1", "GET"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "/bob_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "/bob_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "/bob_data/resource2", "POST"])
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(vec!["cathy", "/cathy_data", "GET"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["cathy", "/cathy_data", "POST"]).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["cathy", "/cathy_data", "DELETE"]).unwrap()
        );
    }

    #[test]
    fn test_key_match_model_in_memory_deny() {
        let mut m = Model::default();
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
                .unwrap()
        );
    }

    use crate::RbacApi;
    #[test]
    fn test_rbac_model_in_memory_indeterminate() {
        let mut m = Model::default();
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
        assert_eq!(false, e.enforce(vec!["alice", "data1", "read"]).unwrap());
    }

    #[test]
    fn test_rbac_model_in_memory() {
        let mut m = Model::default();
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

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_not_used_rbac_model_in_memory() {
        let mut m = Model::default();
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

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_ip_match_model() {
        let m = Model::from_file("examples/ipmatch_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/ipmatch_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert!(e.enforce(vec!["192.168.2.123", "data1", "read"]).unwrap());

        assert!(e.enforce(vec!["10.0.0.5", "data2", "write"]).unwrap());

        assert!(!e.enforce(vec!["192.168.2.123", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["192.168.2.123", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["192.168.2.123", "data2", "write"]).unwrap());

        assert!(!e.enforce(vec!["192.168.0.123", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["192.168.0.123", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["192.168.0.123", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["192.168.0.123", "data2", "write"]).unwrap());

        assert!(!e.enforce(vec!["10.0.0.5", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["10.0.0.5", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["10.0.0.5", "data2", "read"]).unwrap());

        assert!(!e.enforce(vec!["192.168.0.1", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["192.168.0.1", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["192.168.0.1", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["192.168.0.1", "data2", "write"]).unwrap());
    }

    use crate::MgmtApi;
    #[test]
    fn test_enable_auto_save() {
        let m = Model::from_file("examples/basic_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m, adapter);
        e.enable_auto_save(false);
        e.remove_policy(vec!["alice", "data1", "read"]).unwrap();
        e.load_policy().unwrap();

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());

        e.enable_auto_save(true);
        e.remove_policy(vec!["alice", "data1", "read"]).unwrap();
        e.load_policy().unwrap();
        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_role_links() {
        let m = Model::from_file("examples/rbac_model.conf").unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter);
        e.enable_auto_build_role_links(false);
        e.build_role_links().unwrap();
        assert_eq!(false, e.enforce(vec!["user501", "data9", "read"]).unwrap());
    }

    #[test]
    fn test_get_and_set_model() {
        let m1 = Model::from_file("examples/basic_model.conf").unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1);

        assert_eq!(false, e.enforce(vec!["root", "data1", "read"]).unwrap());

        let m2 = Model::from_file("examples/basic_with_root_model.conf").unwrap();
        let adapter2 = FileAdapter::new("examples/basic_policy.csv");
        let e2 = Enforcer::new(m2, adapter2);

        e.model = e2.model;
        assert_eq!(true, e.enforce(vec!["root", "data1", "read"]).unwrap());
    }

    #[test]
    fn test_get_and_set_adapter_in_mem() {
        let m1 = Model::from_file("examples/basic_model.conf").unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1);

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());

        let m2 = Model::from_file("examples/basic_model.conf").unwrap();
        let adapter2 = FileAdapter::new("examples/basic_inverse_policy.csv");
        let e2 = Enforcer::new(m2, adapter2);

        e.adapter = e2.adapter;
        e.load_policy().unwrap();
        assert_eq!(false, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data1", "write"]).unwrap());
    }
}
