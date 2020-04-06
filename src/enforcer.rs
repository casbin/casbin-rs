use crate::adapter::Adapter;
use crate::convert::{TryIntoAdapter, TryIntoModel};
use crate::effector::{DefaultEffector, EffectKind, Effector};
use crate::emitter::{Event, EMITTER};
use crate::error::{Error, ModelError};
use crate::model::Model;
use crate::model::{in_match, FunctionMap};
use crate::rbac::{DefaultRoleManager, RoleManager};
use crate::watcher::Watcher;
use crate::Result;

use emitbrown::Events;
use rhai::{Array, Engine, RegisterFn, Scope};

use std::sync::{Arc, RwLock};

macro_rules! get_or_err {
    ($this:ident, $key:expr, $err:expr, $msg:expr) => {{
        $this
            .model
            .get_model()
            .get($key)
            .ok_or_else(|| {
                Error::ModelError($err(format!("Missing {} definition in conf file", $msg)))
            })?
            .get($key)
            .ok_or_else(|| {
                Error::ModelError($err(format!("Missing {} section in conf file", $msg)))
            })?
    }};
}

macro_rules! generate_g_function {
    ($rm:ident) => {{
        let cb = move |args: Array| -> bool {
            let args = args
                .into_iter()
                .filter_map(|x| x.downcast_ref::<String>().map(|y| y.to_owned()))
                .collect::<Vec<String>>();

            if args.len() == 3 {
                $rm.write()
                    .unwrap()
                    .has_link(&args[0], &args[1], Some(&args[2]))
            } else if args.len() == 2 {
                $rm.write().unwrap().has_link(&args[0], &args[1], None)
            } else {
                unreachable!()
            }
        };
        Box::new(cb)
    }};
}

/// Enforcer is the main interface for authorization enforcement and policy management.
pub struct Enforcer {
    pub(crate) model: Box<dyn Model>,
    pub(crate) adapter: Box<dyn Adapter>,
    pub(crate) fm: FunctionMap,
    pub(crate) eft: Box<dyn Effector>,
    pub(crate) rm: Arc<RwLock<dyn RoleManager>>,
    pub(crate) enabled: bool,
    pub(crate) auto_save: bool,
    pub(crate) auto_build_role_links: bool,
    pub(crate) watcher: Option<Box<dyn Watcher>>,
}

impl Enforcer {
    /// Enforcer::new creates an enforcer via file or DB.
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<Self> {
        let model = m.try_into_model().await?;
        let adapter = a.try_into_adapter().await?;
        let fm = FunctionMap::default();
        let eft = Box::new(DefaultEffector::default());
        let rm = Arc::new(RwLock::new(DefaultRoleManager::new(10)));

        let mut e = Self {
            model,
            adapter,
            fm,
            eft,
            rm,
            enabled: true,
            auto_save: true,
            auto_build_role_links: true,
            watcher: None,
        };

        EMITTER.lock().unwrap().on(
            Event::PolicyChange,
            Box::new(|e: &mut Enforcer| {
                if let Some(ref mut w) = e.watcher {
                    w.update();
                }
            }),
        );

        // TODO: check filtered adapter, match over a implementor?
        e.load_policy().await?;
        Ok(e)
    }

    pub fn add_function(&mut self, fname: &str, f: fn(String, String) -> bool) {
        self.fm.add_function(fname, f);
    }

    pub fn get_model(&self) -> &dyn Model {
        &*self.model
    }

    pub fn get_mut_model(&mut self) -> &mut dyn Model {
        &mut *self.model
    }

    pub fn get_adapter(&self) -> &dyn Adapter {
        &*self.adapter
    }

    pub fn get_mut_adapter(&mut self) -> &mut dyn Adapter {
        &mut *self.adapter
    }

    pub fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.watcher = Some(w);
    }

    pub async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()> {
        self.model = m.try_into_model().await?;
        self.load_policy().await?;
        Ok(())
    }

    pub async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()> {
        self.adapter = a.try_into_adapter().await?;
        self.load_policy().await?;
        Ok(())
    }

    pub fn set_effector(&mut self, e: Box<dyn Effector>) {
        self.eft = e;
    }

    /// Enforce decides whether a "subject" can access a "object" with the operation "action",
    /// input parameters are usually: (sub, obj, act).
    ///
    /// # Examples
    /// ```
    /// use casbin::prelude::*;
    /// #[cfg(feature = "runtime-async-std")]
    /// #[async_std::main]
    /// async fn main() {
    ///     let e = Enforcer::new("examples/basic_model.conf", "examples/basic_policy.csv").await.unwrap();
    ///     assert_eq!(true, e.enforce(&["alice", "data1", "read"]).unwrap());
    /// }
    ///
    /// #[cfg(feature = "runtime-tokio")]
    /// #[tokio::main]
    /// async fn main() {
    ///     let e = Enforcer::new("examples/basic_model.conf", "examples/basic_policy.csv").await.unwrap();
    ///     assert_eq!(true, e.enforce(&["alice", "data1", "read"]).unwrap());
    /// }
    /// #[cfg(all(not(feature = "runtime-async-std"), not(feature = "runtime-tokio")))]
    /// fn main() {}
    /// ```
    pub fn enforce<S: AsRef<str>>(&self, rvals: &[S]) -> Result<bool> {
        if !self.enabled {
            return Ok(true);
        }

        let mut engine = Engine::new();
        let mut scope: Scope = Scope::new();

        let r_ast = get_or_err!(self, "r", ModelError::R, "request");
        let p_ast = get_or_err!(self, "p", ModelError::P, "policy");
        let m_ast = get_or_err!(self, "m", ModelError::M, "matcher");
        let e_ast = get_or_err!(self, "e", ModelError::E, "effector");

        for (i, token) in r_ast.tokens.iter().enumerate() {
            let scope_exp = format!("let {} = \"{}\";", token, rvals[i].as_ref());
            engine.eval_with_scope::<()>(&mut scope, &scope_exp)?;
        }

        for (key, func) in self.fm.fm.iter() {
            engine.register_fn(key, *func);
        }
        engine.register_fn("inMatch", in_match);

        if let Some(g_result) = self.model.get_model().get("g") {
            for (key, ast) in g_result.iter() {
                let rm = Arc::clone(&ast.rm);
                engine.register_fn(key, generate_g_function!(rm));
            }
        }

        let expstring = &m_ast.value;
        let mut policy_effects: Vec<EffectKind> = vec![];
        let policies = self.model.get_policy("p", "p");
        let policy_len = policies.len();
        if policy_len != 0 {
            policy_effects = vec![EffectKind::Deny; policy_len];
            if r_ast.tokens.len() != rvals.len() {
                return Ok(false);
            }
            for (i, pvals) in policies.iter().enumerate() {
                if p_ast.tokens.len() != pvals.len() {
                    return Ok(false);
                }
                for (pi, ptoken) in p_ast.tokens.iter().enumerate() {
                    // let p_sub = "alice"; or let p_obj = "resource1"; or let p_sub = "GET";
                    let scope_exp = format!("let {} = \"{}\";", ptoken, pvals[pi]);
                    engine.eval_with_scope::<()>(&mut scope, &scope_exp)?;
                }

                let eval_result = engine.eval_with_scope::<bool>(&mut scope, expstring)?;
                if !eval_result {
                    policy_effects[i] = EffectKind::Indeterminate;
                    continue;
                }
                if let Some(j) = p_ast.tokens.iter().position(|x| x == "p_eft") {
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
                if e_ast.value == "priority(p_eft) || deny" {
                    break;
                }
            }
        } else {
            for token in p_ast.tokens.iter() {
                let scope_exp = format!("let {} = \"{}\";", token, "");
                engine.eval_with_scope::<()>(&mut scope, &scope_exp)?;
            }
            let eval_result = engine.eval_with_scope::<bool>(&mut scope, expstring)?;
            if eval_result {
                policy_effects.push(EffectKind::Allow);
            } else {
                policy_effects.push(EffectKind::Indeterminate);
            }
        }

        Ok(self.eft.merge_effects(&e_ast.value, policy_effects))
    }

    pub fn build_role_links(&mut self) -> Result<()> {
        self.rm.write().unwrap().clear();
        self.model.build_role_links(Arc::clone(&self.rm))?;
        Ok(())
    }

    pub async fn load_policy(&mut self) -> Result<()> {
        self.model.clear_policy();
        self.adapter.load_policy(&mut *self.model).await?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }
        Ok(())
    }

    pub async fn save_policy(&mut self) -> Result<()> {
        self.adapter.save_policy(&mut *self.model).await
    }

    pub fn clear_policy(&mut self) {
        self.model.clear_policy();
    }

    pub fn enable_enforce(&mut self, enabled: bool) {
        self.enabled = enabled;
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
    use crate::model::DefaultModel;

    fn is_send<T: Send>() -> bool {
        true
    }

    fn is_sync<T: Sync>() -> bool {
        true
    }

    #[test]
    fn test_send_sync() {
        assert!(is_send::<Enforcer>());
        assert!(is_sync::<Enforcer>());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_enforcer_swap_adapter_type() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let file = FileAdapter::new("examples/basic_policy.csv");
        let mem = MemoryAdapter::default();
        let mut e = Enforcer::new(m, file).await.unwrap();
        // this should fail since FileAdapter has basically no add_policy
        assert!(e
            .adapter
            .add_policy("p", "p", vec!["alice".into(), "data".into(), "read".into()])
            .await
            .unwrap());
        e.set_adapter(mem).await.unwrap();
        // this passes since our MemoryAdapter has a working add_policy method
        assert!(e
            .adapter
            .add_policy("p", "p", vec!["alice".into(), "data".into(), "read".into()])
            .await
            .unwrap())
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_key_match_model_in_memory() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource1", "GET"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/alice_data/resource2", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource1", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource2", "POST"])
                .unwrap()
        );

        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/alice_data/resource1", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/alice_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/alice_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/alice_data/resource2", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/bob_data/resource1", "GET"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/bob_data/resource1", "POST"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/bob_data/resource2", "GET"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/bob_data/resource2", "POST"])
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "GET"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "POST"]).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["cathy", "/cathy_data", "DELETE"]).unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_key_match_model_in_memory_deny() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "!some(where (p.eft == deny))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let adapter = FileAdapter::new("examples/keymatch_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource2", "POST"])
                .unwrap()
        );
    }

    use crate::RbacApi;
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_in_memory_indeterminate() {
        let mut m = DefaultModel::default();
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
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_permission_for_user(
            "alice",
            vec!["data1", "invalid"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        assert_eq!(false, e.enforce(&vec!["alice", "data1", "read"]).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_rbac_model_in_memory() {
        let mut m = DefaultModel::default();
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
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_permission_for_user(
            "alice",
            vec!["data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "bob",
            vec!["data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "data2_admin",
            vec!["data2", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "data2_admin",
            vec!["data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_role_for_user("alice", "data2_admin", None)
            .await
            .unwrap();

        assert_eq!(true, e.enforce(&vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(&vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(&vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "data2", "write"]).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_not_used_rbac_model_in_memory() {
        let mut m = DefaultModel::default();
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
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.add_permission_for_user(
            "alice",
            vec!["data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.add_permission_for_user(
            "bob",
            vec!["data2", "write"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(true, e.enforce(&vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "data2", "write"]).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_ip_match_model() {
        let m = DefaultModel::from_file("examples/ipmatch_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/ipmatch_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e.enforce(&vec!["192.168.2.123", "data1", "read"]).unwrap());

        assert!(e.enforce(&vec!["10.0.0.5", "data2", "write"]).unwrap());

        assert!(!e.enforce(&vec!["192.168.2.123", "data1", "write"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.2.123", "data2", "read"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.2.123", "data2", "write"]).unwrap());

        assert!(!e.enforce(&vec!["192.168.0.123", "data1", "read"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.0.123", "data1", "write"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.0.123", "data2", "read"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.0.123", "data2", "write"]).unwrap());

        assert!(!e.enforce(&vec!["10.0.0.5", "data1", "read"]).unwrap());
        assert!(!e.enforce(&vec!["10.0.0.5", "data1", "write"]).unwrap());
        assert!(!e.enforce(&vec!["10.0.0.5", "data2", "read"]).unwrap());

        assert!(!e.enforce(&vec!["192.168.0.1", "data1", "read"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.0.1", "data1", "write"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.0.1", "data2", "read"]).unwrap());
        assert!(!e.enforce(&vec!["192.168.0.1", "data2", "write"]).unwrap());
    }

    use crate::MgmtApi;
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_enable_auto_save() {
        let m = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.enable_auto_save(false);
        e.remove_policy(
            vec!["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.load_policy().await.unwrap();

        assert_eq!(true, e.enforce(&vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "data2", "write"]).unwrap());

        e.enable_auto_save(true);
        e.remove_policy(
            vec!["alice", "data1", "read"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .await
        .unwrap();
        e.load_policy().await.unwrap();
        assert_eq!(true, e.enforce(&vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(&vec!["bob", "data2", "write"]).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_role_links() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.enable_auto_build_role_links(false);
        e.build_role_links().unwrap();
        assert_eq!(false, e.enforce(&vec!["user501", "data9", "read"]).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_get_and_set_model() {
        let m1 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        assert_eq!(false, e.enforce(&vec!["root", "data1", "read"]).unwrap());

        let m2 = DefaultModel::from_file("examples/basic_with_root_model.conf")
            .await
            .unwrap();
        let adapter2 = FileAdapter::new("examples/basic_policy.csv");
        let e2 = Enforcer::new(m2, adapter2).await.unwrap();

        e.model = e2.model;
        assert_eq!(true, e.enforce(&vec!["root", "data1", "read"]).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_get_and_set_adapter_in_mem() {
        let m1 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        assert_eq!(true, e.enforce(&vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(&vec!["alice", "data1", "write"]).unwrap());

        let m2 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter2 = FileAdapter::new("examples/basic_inverse_policy.csv");
        let e2 = Enforcer::new(m2, adapter2).await.unwrap();

        e.adapter = e2.adapter;
        e.load_policy().await.unwrap();
        assert_eq!(false, e.enforce(&vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(true, e.enforce(&vec!["alice", "data1", "write"]).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_keymatch_custom_model() {
        use crate::model::key_match;

        let m1 = DefaultModel::from_file("examples/keymatch_custom_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/keymatch_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        e.add_function("keyMatchCustom", key_match);

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/123", "GET"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource1", "POST"])
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/alice_data/resource2", "GET"])
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/bob_data/resource1", "POST"])
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "GET"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "POST"]).unwrap()
        );
    }
}
