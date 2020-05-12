use crate::{
    adapter::{Adapter, Filter},
    convert::{TryIntoAdapter, TryIntoModel},
    core_api::CoreApi,
    effector::{DefaultEffector, EffectKind, Effector},
    emitter::{Event, EventData, EventEmitter},
    error::{Error, ModelError, PolicyError, RequestError},
    management_api::MgmtApi,
    model::{FunctionMap, Model},
    rbac::{DefaultRoleManager, RoleManager},
    util::{escape_eval, ESC_E},
    Result,
};

#[cfg(any(feature = "logging", feature = "watcher"))]
use crate::emitter::notify_logger_and_watcher;

#[cfg(feature = "watcher")]
use crate::watcher::Watcher;

#[cfg(feature = "logging")]
use crate::{DefaultLogger, Logger};

use async_trait::async_trait;
use rhai::{
    def_package,
    packages::{ArithmeticPackage, BasicArrayPackage, BasicMapPackage, LogicPackage, Package},
    Array, Engine, RegisterFn, Scope,
};

def_package!(rhai:CasbinPackage:"Package for Casbin", lib, {
    ArithmeticPackage::init(lib);
    LogicPackage::init(lib);
    BasicArrayPackage::init(lib);
    BasicMapPackage::init(lib);
});

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

type EventCallback = fn(&mut Enforcer, EventData);

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
    #[cfg(feature = "watcher")]
    pub(crate) auto_notify_watcher: bool,
    #[cfg(feature = "watcher")]
    pub(crate) watcher: Option<Box<dyn Watcher>>,
    pub(crate) events: HashMap<Event, Vec<EventCallback>>,
    pub(crate) engine: Engine,
    #[cfg(feature = "logging")]
    pub(crate) logger: Box<dyn Logger>,
}

impl EventEmitter<Event> for Enforcer {
    fn on(&mut self, e: Event, f: fn(&mut Self, EventData)) {
        self.events.entry(e).or_insert_with(Vec::new).push(f)
    }

    fn off(&mut self, e: Event) {
        self.events.remove(&e);
    }

    fn emit(&mut self, e: Event, d: EventData) {
        if let Some(cbs) = self.events.get(&e) {
            for cb in cbs.clone().iter() {
                cb(self, d.clone())
            }
        }
    }
}

impl Enforcer {
    async fn private_enforce<S: AsRef<str> + Send + Sync>(&self, rvals: &[S]) -> Result<bool> {
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

        let policies = p_ast.get_policy();
        let policy_len = policies.len();
        let mut eft_stream = self
            .eft
            .new_stream(&e_ast.value, if policy_len > 0 { policy_len } else { 1 });
        let scope_size = scope.len();

        if policy_len != 0 {
            for (i, pvals) in policies.iter().enumerate() {
                if i != 0 {
                    scope.rewind(scope_size);
                }

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

                let mut expstring = m_ast.value.to_owned();
                if ESC_E.is_match(&expstring) {
                    expstring = escape_eval(expstring, &scope);
                }

                let eval_result = self
                    .engine
                    .eval_with_scope::<bool>(&mut scope, &expstring)?;
                let mut eft = if !eval_result {
                    EffectKind::Indeterminate
                } else {
                    EffectKind::Allow
                };
                match p_ast.tokens.iter().position(|x| x == "p_eft") {
                    Some(j) if eft == EffectKind::Allow => {
                        let p_eft = &pvals[j];
                        if p_eft == "deny" {
                            eft = EffectKind::Deny;
                        } else if p_eft != "allow" {
                            eft = EffectKind::Indeterminate;
                        };
                    }
                    _ => {}
                }
                if eft_stream.push_effect(eft) {
                    break;
                }
            }
        } else {
            for token in p_ast.tokens.iter() {
                scope.push_constant(token, String::new());
            }
            let eval_result = self
                .engine
                .eval_with_scope::<bool>(&mut scope, &m_ast.value)?;
            let eft = if eval_result {
                EffectKind::Allow
            } else {
                EffectKind::Indeterminate
            };
            eft_stream.push_effect(eft);
        }
        Ok(eft_stream.current())
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

        engine.load_package(CasbinPackage::new().get());

        for (key, func) in fm.get_functions() {
            engine.register_fn(key, *func);
        }

        let mut e = {
            #[cfg(feature = "logging")]
            {
                let logger = Box::new(DefaultLogger::default());
                Self {
                    model,
                    adapter,
                    fm,
                    eft,
                    rm,
                    enabled: true,
                    auto_save: true,
                    auto_build_role_links: true,
                    #[cfg(feature = "watcher")]
                    auto_notify_watcher: true,
                    #[cfg(feature = "watcher")]
                    watcher: None,
                    events: HashMap::new(),
                    engine,
                    logger,
                }
            }

            #[cfg(not(feature = "logging"))]
            {
                Self {
                    model,
                    adapter,
                    fm,
                    eft,
                    rm,
                    enabled: true,
                    auto_save: true,
                    auto_build_role_links: true,
                    #[cfg(feature = "watcher")]
                    auto_notify_watcher: true,
                    #[cfg(feature = "watcher")]
                    watcher: None,
                    events: HashMap::new(),
                    engine,
                }
            }
        };

        #[cfg(any(feature = "logging", feature = "watcher"))]
        {
            e.on(Event::PolicyChange, notify_logger_and_watcher);
        }

        e.load_policy().await?;

        if let Some(ast_map) = e.model.get_model().get("g") {
            for (key, _) in ast_map.iter() {
                let rm = Arc::clone(&e.rm);
                e.engine.register_fn(key, generate_g_function!(rm));
            }
        }

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

    #[cfg(feature = "watcher")]
    #[inline]
    fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.watcher = Some(w);
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn get_logger(&self) -> &dyn Logger {
        &*self.logger
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn set_logger(&mut self, l: Box<dyn Logger>) {
        self.logger = l;
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn get_watcher(&self) -> Option<&dyn Watcher> {
        if let Some(ref watcher) = self.watcher {
            Some(&**watcher)
        } else {
            None
        }
    }

    #[cfg(feature = "watcher")]
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
        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        if let Some(ast_map) = self.model.get_model().get("g") {
            for (key, _) in ast_map.iter() {
                let rm = Arc::clone(&self.rm);
                self.engine.register_fn(key, generate_g_function!(rm));
            }
        }

        Ok(())
    }

    fn add_matching_fn(&mut self, f: fn(String, String) -> bool) -> Result<()> {
        self.rm.write().unwrap().add_matching_fn(f);
        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        Ok(())
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
    async fn enforce<S: AsRef<str> + Send + Sync>(&self, rvals: &[S]) -> Result<bool> {
        let res = self.private_enforce(rvals).await?;

        #[cfg(feature = "logging")]
        {
            self.logger.print_enforce_log(
                rvals.iter().map(|x| String::from(x.as_ref())).collect(),
                res,
                false,
            );
        }

        Ok(res)
    }

    async fn enforce_mut<S: AsRef<str> + Send + Sync>(&mut self, rvals: &[S]) -> Result<bool> {
        self.enforce(rvals).await
    }

    fn build_role_links(&mut self) -> Result<()> {
        self.rm.write().unwrap().clear();
        self.model.build_role_links(Arc::clone(&self.rm))?;
        Ok(())
    }

    #[cfg(feature = "incremental")]
    fn build_incremental_role_links(&mut self, d: EventData) -> Result<()> {
        self.model
            .build_incremental_role_links(Arc::clone(&self.rm), d)?;
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

    async fn load_filtered_policy(&mut self, f: Filter) -> Result<()> {
        self.model.clear_policy();
        self.adapter
            .load_filtered_policy(&mut *self.model, f)
            .await?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }
        Ok(())
    }

    #[inline]
    fn is_filtered(&self) -> bool {
        self.adapter.is_filtered()
    }

    async fn save_policy(&mut self) -> Result<()> {
        if self.is_filtered() {
            panic!("cannot save filtered policy");
        }

        self.adapter.save_policy(&mut *self.model).await?;

        let mut policies = self.get_all_policy();
        let gpolicies = self.get_all_grouping_policy();

        policies.extend(gpolicies);

        #[cfg(any(feature = "logging", feature = "watcher"))]
        {
            self.emit(Event::PolicyChange, EventData::SavePolicy(policies));
        }
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

    #[cfg(feature = "logging")]
    #[inline]
    fn enable_log(&mut self, enabled: bool) {
        self.logger.enable_log(enabled);
    }

    #[inline]
    fn enable_auto_save(&mut self, auto_save: bool) {
        self.auto_save = auto_save;
    }

    #[inline]
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool) {
        self.auto_build_role_links = auto_build_role_links;
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn enable_auto_notify_watcher(&mut self, auto_notify_watcher: bool) {
        if !auto_notify_watcher {
            self.off(Event::PolicyChange);
        } else {
            self.on(Event::PolicyChange, notify_logger_and_watcher);
        }
        self.auto_notify_watcher = auto_notify_watcher;
    }

    #[inline]
    fn has_auto_save_enabled(&self) -> bool {
        self.auto_save
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn has_auto_notify_watcher_enabled(&self) -> bool {
        self.auto_notify_watcher
    }

    #[inline]
    fn has_auto_build_role_links_enabled(&self) -> bool {
        self.auto_build_role_links
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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
                .await
                .unwrap()
        );
    }

    use crate::RbacApi;
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(feature = "ip")]
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_ip_match_model() {
        let m = DefaultModel::from_file("examples/ipmatch_model.conf")
            .await
            .unwrap();

        let adapter = FileAdapter::new("examples/ipmatch_policy.csv");
        let e = Enforcer::new(m, adapter).await.unwrap();

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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_filtered_file_adapter() {
        let mut e = Enforcer::new(
            "examples/rbac_with_domains_model.conf",
            "examples/rbac_with_domains_policy.csv",
        )
        .await
        .unwrap();

        let filter = Filter {
            p: vec!["", "domain1"],
            g: vec!["", "", "domain1"],
        };

        e.load_filtered_policy(filter).await.unwrap();
        assert_eq!(
            e.enforce(&["alice", "domain1", "data1", "read"])
                .await
                .unwrap(),
            true
        );
        assert!(e
            .enforce(&["alice", "domain1", "data1", "write"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["alice", "domain1", "data2", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["alice", "domain1", "data2", "write"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["bob", "domain2", "data2", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["bob", "domain2", "data2", "write"])
            .await
            .unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_set_role_manager() {
        let mut e = Enforcer::new(
            "examples/rbac_with_domains_model.conf",
            "examples/rbac_with_domains_policy.csv",
        )
        .await
        .unwrap();

        let new_rm = Arc::new(RwLock::new(DefaultRoleManager::new(10)));

        e.set_role_manager(new_rm).unwrap();

        assert!(e
            .enforce(&["alice", "domain1", "data1", "read"])
            .await
            .unwrap(),);
        assert!(e
            .enforce(&["alice", "domain1", "data1", "write"])
            .await
            .unwrap());
        assert!(e
            .enforce(&["bob", "domain2", "data2", "read"])
            .await
            .unwrap());
        assert!(e
            .enforce(&["bob", "domain2", "data2", "write"])
            .await
            .unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(
        all(feature = "runtime-async-std", not(target_arch = "wasm32")),
        async_std::test
    )]
    #[cfg_attr(
        all(feature = "runtime-tokio", not(target_arch = "wasm32")),
        tokio::test
    )]
    async fn test_policy_abac() {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub_rule, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act",
        );

        let a = MemoryAdapter::default();

        let mut e = Enforcer::new(m, a).await.unwrap();

        e.add_policy(
            vec!["r.sub.age > 18", "/data1", "read"]
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
        )
        .await
        .unwrap();

        assert_eq!(
            e.enforce(&[r#"{"name": "alice", "age": 16}"#, "/data1", "read"])
                .await
                .unwrap(),
            false
        );
        assert_eq!(
            e.enforce(&[r#"{"name": "bob", "age": 19}"#, "/data1", "read"])
                .await
                .unwrap(),
            true
        );
    }
}
