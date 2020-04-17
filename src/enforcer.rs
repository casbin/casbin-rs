use crate::{
    adapter::Adapter,
    convert::{TryIntoAdapter, TryIntoModel},
    core_api::CoreApi,
    effector::{DefaultEffector, EffectKind, Effector},
    emitter::{notify_watcher, Event, EventData, EventEmitter},
    error::{Error, ModelError, PolicyError, RequestError},
    model::{FunctionMap, Model},
    rbac::{DefaultRoleManager, RoleManager},
    watcher::Watcher,
    Result,
};

use async_trait::async_trait;
use rhai::{Array, Engine, RegisterFn, Scope};

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

macro_rules! get_or_err {
    ($this:ident, $key:expr, $err:expr, $msg:expr) => {{
        $this
            .model
            .get_model()
            .get($key)
            .ok_or_else(|| Error::from($err(format!("Missing {} definition in conf file", $msg))))?
            .get($key)
            .ok_or_else(|| Error::from($err(format!("Missing {} section in conf file", $msg))))?
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
                panic!("g function supports at most 3 parameters");
            }
        };
        Box::new(cb)
    }};
}

type EventCallback = fn(&mut Enforcer, Option<EventData>);

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
    pub(crate) auto_notify_watcher: bool,
    pub(crate) watcher: Option<Box<dyn Watcher>>,
    pub(crate) events: HashMap<Event, Vec<EventCallback>>,
    pub(crate) engine: Engine<'static>,
}

impl EventEmitter<Event> for Enforcer {
    fn on(&mut self, e: Event, f: fn(&mut Self, Option<EventData>)) {
        self.events.entry(e).or_insert_with(Vec::new).push(f)
    }

    fn off(&mut self, e: Event) {
        self.events.remove(&e);
    }

    fn emit(&mut self, e: Event, d: Option<EventData>) {
        if let Some(cbs) = self.events.get(&e) {
            for cb in cbs.clone().iter() {
                cb(self, d.clone())
            }
        }
    }
}

#[async_trait]
impl CoreApi for Enforcer {
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<Self> {
        let model = m.try_into_model().await?;
        let adapter = a.try_into_adapter().await?;
        let fm = FunctionMap::default();
        let eft = Box::new(DefaultEffector::default());
        let rm = Arc::new(RwLock::new(DefaultRoleManager::new(10)));
        let mut engine = Engine::new_raw();

        for (key, func) in fm.get_functions() {
            engine.register_fn(key, *func);
        }

        let mut e = Self {
            model,
            adapter,
            fm,
            eft,
            rm,
            enabled: true,
            auto_save: true,
            auto_build_role_links: true,
            auto_notify_watcher: true,
            watcher: None,
            events: HashMap::new(),
            engine,
        };

        e.on(Event::PolicyChange, notify_watcher);

        // TODO: check filtered adapter, match over a implementor?
        e.load_policy().await?;
        Ok(e)
    }

    #[inline]
    fn add_function(&mut self, fname: &str, f: fn(String, String) -> bool) {
        self.fm.add_function(fname, f);
        self.engine.register_fn(fname, f);
    }

    #[inline]
    fn get_model(&self) -> &dyn Model {
        &*self.model
    }

    #[inline]
    fn get_mut_model(&mut self) -> &mut dyn Model {
        &mut *self.model
    }

    #[inline]
    fn get_adapter(&self) -> &dyn Adapter {
        &*self.adapter
    }

    #[inline]
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter {
        &mut *self.adapter
    }

    #[inline]
    fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.watcher = Some(w);
    }

    #[inline]
    fn get_watcher(&self) -> Option<&dyn Watcher> {
        if let Some(ref watcher) = self.watcher {
            Some(&**watcher)
        } else {
            None
        }
    }

    #[inline]
    fn get_mut_watcher(&mut self) -> Option<&mut dyn Watcher> {
        if let Some(ref mut watcher) = self.watcher {
            Some(&mut **watcher)
        } else {
            None
        }
    }

    #[inline]
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>> {
        Arc::clone(&self.rm)
    }

    #[inline]
    fn set_role_manager(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()> {
        self.rm = rm;
        self.build_role_links()
    }

    fn add_matching_fn(&mut self, f: fn(String, String) -> bool) -> Result<()> {
        self.rm.write().unwrap().add_matching_fn(f);
        self.build_role_links()
    }

    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()> {
        self.model = m.try_into_model().await?;
        self.load_policy().await?;
        Ok(())
    }

    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()> {
        self.adapter = a.try_into_adapter().await?;
        self.load_policy().await?;
        Ok(())
    }

    #[inline]
    fn set_effector(&mut self, e: Box<dyn Effector>) {
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
    /// async fn main() -> Result<()> {
    ///     let mut e = Enforcer::new("examples/basic_model.conf", "examples/basic_policy.csv").await?;
    ///     assert_eq!(true, e.enforce(&["alice", "data1", "read"]).await?);
    ///     Ok(())
    /// }
    ///
    /// #[cfg(feature = "runtime-tokio")]
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let mut e = Enforcer::new("examples/basic_model.conf", "examples/basic_policy.csv").await?;
    ///     assert_eq!(true, e.enforce(&["alice", "data1", "read"]).await?);
    ///
    ///     Ok(())
    /// }
    /// #[cfg(all(not(feature = "runtime-async-std"), not(feature = "runtime-tokio")))]
    /// fn main() {}
    /// ```
    async fn enforce<S: AsRef<str> + Send + Sync>(&mut self, rvals: &[S]) -> Result<bool> {
        if !self.enabled {
            return Ok(true);
        }

        let mut scope: Scope = Scope::new();

        let r_ast = get_or_err!(self, "r", ModelError::R, "request");
        let p_ast = get_or_err!(self, "p", ModelError::P, "policy");
        let m_ast = get_or_err!(self, "m", ModelError::M, "matcher");
        let e_ast = get_or_err!(self, "e", ModelError::E, "effector");

        if r_ast.tokens.len() != rvals.len() {
            return Err(
                RequestError::UnmatchRequestDefinition(r_ast.tokens.len(), rvals.len()).into(),
            );
        }

        for (rtoken, rval) in r_ast.tokens.iter().zip(rvals.iter()) {
            if rval.as_ref().starts_with('{') && rval.as_ref().ends_with('}') {
                // if r_sub, r_obj or r_act is a json string, then we need to parse it into an object
                // https://casbin.org/docs/en/abac#how-to-use-abac
                let scope_exp = format!("const {} = #{};", rtoken, rval.as_ref());
                self.engine.eval_with_scope::<()>(&mut scope, &scope_exp)?;
            } else {
                scope.push_constant(rtoken, rval.as_ref().to_owned());
            }
        }

        if let Some(g_result) = self.model.get_model().get("g") {
            for (key, ast) in g_result.iter() {
                let rm = Arc::clone(&ast.rm);
                self.engine.register_fn(key, generate_g_function!(rm));
            }
        }

        let expstring = &m_ast.value;
        let mut policy_effects: Vec<EffectKind> = vec![];
        let policies = self.model.get_policy("p", "p");
        let policy_len = policies.len();
        let scope_size = scope.len();

        if policy_len != 0 {
            policy_effects = vec![EffectKind::Deny; policy_len];
            for (i, pvals) in policies.iter().enumerate() {
                if p_ast.tokens.len() != pvals.len() {
                    return Err(PolicyError::UnmatchPolicyDefinition(
                        p_ast.tokens.len(),
                        pvals.len(),
                    )
                    .into());
                }
                for (ptoken, pval) in p_ast.tokens.iter().zip(pvals.iter()) {
                    scope.push_constant(ptoken, pval.to_owned());
                }

                let eval_result = self.engine.eval_with_scope::<bool>(&mut scope, expstring)?;
                if !eval_result {
                    policy_effects[i] = EffectKind::Indeterminate;
                    scope.rewind(scope_size);
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
                scope.rewind(scope_size);
                if e_ast.value == "priority(p_eft) || deny" {
                    break;
                }
            }
        } else {
            for token in p_ast.tokens.iter() {
                scope.push_constant(token, String::new());
            }
            let eval_result = self.engine.eval_with_scope::<bool>(&mut scope, expstring)?;
            if eval_result {
                policy_effects.push(EffectKind::Allow);
            } else {
                policy_effects.push(EffectKind::Indeterminate);
            }
        }

        Ok(self.eft.merge_effects(&e_ast.value, policy_effects))
    }

    fn build_role_links(&mut self) -> Result<()> {
        self.rm.write().unwrap().clear();
        self.model.build_role_links(Arc::clone(&self.rm))?;
        Ok(())
    }

    async fn load_policy(&mut self) -> Result<()> {
        self.model.clear_policy();
        self.adapter.load_policy(&mut *self.model).await?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }
        Ok(())
    }

    async fn save_policy(&mut self) -> Result<()> {
        self.adapter.save_policy(&mut *self.model).await?;

        let mut policies = self.get_model().get_policy("p", "p");
        if let Some(ast_map) = self.get_model().get_model().get("g") {
            for (ptype, ast) in ast_map {
                policies.extend(
                    ast.get_policy()
                        .clone()
                        .into_iter()
                        .map(|mut x| {
                            x.insert(0, ptype.clone());
                            x
                        })
                        .collect::<Vec<Vec<String>>>(),
                );
            }
        }

        self.emit(Event::PolicyChange, Some(EventData::SavePolicy(policies)));
        Ok(())
    }

    #[inline]
    fn clear_policy(&mut self) {
        self.model.clear_policy();
    }

    #[inline]
    fn enable_enforce(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    #[inline]
    fn enable_auto_save(&mut self, auto_save: bool) {
        self.auto_save = auto_save;
    }

    #[inline]
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool) {
        self.auto_build_role_links = auto_build_role_links;
    }

    #[inline]
    fn enable_auto_notify_watcher(&mut self, auto_notify_watcher: bool) {
        if !auto_notify_watcher {
            self.off(Event::PolicyChange);
        } else {
            self.on(Event::PolicyChange, notify_watcher);
        }
        self.auto_notify_watcher = auto_notify_watcher;
    }

    #[inline]
    fn has_auto_save_enabled(&self) -> bool {
        self.auto_save
    }

    #[inline]
    fn has_auto_notify_watcher_enabled(&self) -> bool {
        self.auto_notify_watcher
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

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
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource1", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource1", "POST"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource2", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/alice_data/resource2", "POST"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource1", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource1", "POST"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource2", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "/bob_data/resource2", "POST"])
                .await
                .unwrap()
        );

        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/alice_data/resource1", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/alice_data/resource1", "POST"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/alice_data/resource2", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/alice_data/resource2", "POST"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/bob_data/resource1", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/bob_data/resource1", "POST"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["bob", "/bob_data/resource2", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/bob_data/resource2", "POST"])
                .await
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "POST"])
                .await
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["cathy", "/cathy_data", "DELETE"])
                .await
                .unwrap()
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
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource2", "POST"])
                .await
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
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
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
    async fn test_ip_match_model() {
        let m = DefaultModel::from_file("examples/ipmatch_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/ipmatch_policy.csv");
        let mut e = Enforcer::new(m, adapter).await.unwrap();

        assert!(e
            .enforce(&vec!["192.168.2.123", "data1", "read"])
            .await
            .unwrap());

        assert!(e
            .enforce(&vec!["10.0.0.5", "data2", "write"])
            .await
            .unwrap());

        assert!(!e
            .enforce(&vec!["192.168.2.123", "data1", "write"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.2.123", "data2", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.2.123", "data2", "write"])
            .await
            .unwrap());

        assert!(!e
            .enforce(&vec!["192.168.0.123", "data1", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.0.123", "data1", "write"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.0.123", "data2", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.0.123", "data2", "write"])
            .await
            .unwrap());

        assert!(!e.enforce(&vec!["10.0.0.5", "data1", "read"]).await.unwrap());
        assert!(!e
            .enforce(&vec!["10.0.0.5", "data1", "write"])
            .await
            .unwrap());
        assert!(!e.enforce(&vec!["10.0.0.5", "data2", "read"]).await.unwrap());

        assert!(!e
            .enforce(&vec!["192.168.0.1", "data1", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.0.1", "data1", "write"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.0.1", "data2", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&vec!["192.168.0.1", "data2", "write"])
            .await
            .unwrap());
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
    async fn test_role_links() {
        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter).await.unwrap();
        e.enable_auto_build_role_links(false);
        e.build_role_links().unwrap();
        assert_eq!(
            false,
            e.enforce(&vec!["user501", "data9", "read"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_get_and_set_model() {
        let m1 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        assert_eq!(
            false,
            e.enforce(&vec!["root", "data1", "read"]).await.unwrap()
        );

        let m2 = DefaultModel::from_file("examples/basic_with_root_model.conf")
            .await
            .unwrap();
        let adapter2 = FileAdapter::new("examples/basic_policy.csv");
        let e2 = Enforcer::new(m2, adapter2).await.unwrap();

        e.model = e2.model;
        assert_eq!(
            true,
            e.enforce(&vec!["root", "data1", "read"]).await.unwrap()
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_get_and_set_adapter_in_mem() {
        let m1 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter1 = FileAdapter::new("examples/basic_policy.csv");
        let mut e = Enforcer::new(m1, adapter1).await.unwrap();

        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );

        let m2 = DefaultModel::from_file("examples/basic_model.conf")
            .await
            .unwrap();
        let adapter2 = FileAdapter::new("examples/basic_inverse_policy.csv");
        let e2 = Enforcer::new(m2, adapter2).await.unwrap();

        e.adapter = e2.adapter;
        e.load_policy().await.unwrap();
        assert_eq!(
            false,
            e.enforce(&vec!["alice", "data1", "read"]).await.unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "data1", "write"]).await.unwrap()
        );
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
            e.enforce(&vec!["alice", "/alice_data/123", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["alice", "/alice_data/resource1", "POST"])
                .await
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/alice_data/resource2", "GET"])
                .await
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["bob", "/bob_data/resource1", "POST"])
                .await
                .unwrap()
        );

        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "GET"])
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(&vec!["cathy", "/cathy_data", "POST"])
                .await
                .unwrap()
        );
    }
}
