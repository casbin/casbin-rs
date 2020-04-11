use crate::{
    adapter::Adapter,
    cache::{Cache, DefaultCache},
    cached_api::CachedApi,
    convert::{TryIntoAdapter, TryIntoModel},
    core_api::CoreApi,
    effector::Effector,
    emitter::{Event, CACHED_EMITTER},
    enforcer::Enforcer,
    model::Model,
    rbac::RoleManager,
    watcher::Watcher,
    Result,
};

#[cfg(feature = "runtime-async-std")]
use async_std::task;
use async_trait::async_trait;
use emitbrown::Events;

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

pub struct CachedEnforcer {
    pub(crate) enforcer: Enforcer,
    pub(crate) cache: Box<dyn Cache<Vec<String>, bool>>,
}

#[async_trait]
impl CoreApi for CachedEnforcer {
    #[cfg(feature = "runtime-async-std")]
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<CachedEnforcer> {
        let cached_enforcer = CachedEnforcer {
            enforcer: Enforcer::new(m, a).await?,
            cache: Box::new(DefaultCache::new(1000)) as Box<dyn Cache<Vec<String>, bool>>,
        };

        CACHED_EMITTER.lock().unwrap().on(
            Event::PolicyChange,
            // Todo: Move to async closure when it's stable
            // https://github.com/rust-lang/rfcs/blob/master/text/2394-async_await.md
            Box::new(|ce: &mut CachedEnforcer| {
                task::block_on(async {
                    ce.cache.clear().await;
                });
            }),
        );

        Ok(cached_enforcer)
    }

    #[cfg(feature = "runtime-tokio")]
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<CachedEnforcer> {
        let cached_enforcer = CachedEnforcer {
            enforcer: Enforcer::new(m, a).await?,
            cache: Box::new(DefaultCache::new(1000)) as Box<dyn Cache<Vec<String>, bool>>,
        };

        CACHED_EMITTER.lock().unwrap().on(
            Event::PolicyChange,
            // Todo: Move to async closure when it's stable
            // https://github.com/rust-lang/rfcs/blob/master/text/2394-async_await.md
            Box::new(|ce: &mut CachedEnforcer| {
                tokio::runtime::Builder::new()
                    .basic_scheduler()
                    .threaded_scheduler()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        ce.cache.clear().await;
                    });
            }),
        );

        Ok(cached_enforcer)
    }

    #[inline]
    fn add_function(&mut self, fname: &str, f: fn(String, String) -> bool) {
        self.enforcer.fm.add_function(fname, f);
    }

    #[inline]
    fn get_model(&self) -> &dyn Model {
        self.enforcer.get_model()
    }

    #[inline]
    fn get_mut_model(&mut self) -> &mut dyn Model {
        self.enforcer.get_mut_model()
    }

    #[inline]
    fn get_adapter(&self) -> &dyn Adapter {
        self.enforcer.get_adapter()
    }

    #[inline]
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter {
        self.enforcer.get_mut_adapter()
    }

    #[inline]
    fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.enforcer.set_watcher(w);
    }

    #[inline]
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>> {
        self.enforcer.get_role_manager()
    }

    #[inline]
    fn set_role_manager(&mut self, rm: Arc<RwLock<dyn RoleManager>>) {
        self.enforcer.set_role_manager(rm);
    }

    #[inline]
    fn add_matching_fn(&mut self, f: fn(String, String) -> bool) -> Result<()> {
        self.enforcer.add_matching_fn(f)
    }

    #[inline]
    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()> {
        self.enforcer.set_model(m).await
    }

    #[inline]
    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()> {
        self.enforcer.set_adapter(a).await
    }

    #[inline]
    fn set_effector(&mut self, e: Box<dyn Effector>) {
        self.enforcer.set_effector(e);
    }

    async fn enforce<S: AsRef<str> + Send + Sync>(&mut self, rvals: &[S]) -> Result<bool> {
        let key: Vec<String> = rvals.iter().map(|x| String::from(x.as_ref())).collect();

        if let Some(result) = self.cache.get(&key).await {
            Ok(*result)
        } else {
            let result = self.enforcer.enforce(rvals).await?;
            self.cache.set(key, result).await;
            Ok(result)
        }
    }

    #[inline]
    fn build_role_links(&mut self) -> Result<()> {
        self.enforcer.build_role_links()
    }

    #[inline]
    async fn load_policy(&mut self) -> Result<()> {
        self.enforcer.load_policy().await
    }

    #[inline]
    async fn save_policy(&mut self) -> Result<()> {
        self.enforcer.save_policy().await
    }

    #[inline]
    fn clear_policy(&mut self) {
        self.enforcer.clear_policy();
    }

    #[inline]
    fn enable_enforce(&mut self, enabled: bool) {
        self.enforcer.enable_enforce(enabled);
    }

    #[inline]
    fn enable_auto_save(&mut self, auto_save: bool) {
        self.enforcer.enable_auto_save(auto_save);
    }

    #[inline]
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool) {
        self.enforcer
            .enable_auto_build_role_links(auto_build_role_links);
    }

    #[inline]
    fn has_auto_save_enabled(&self) -> bool {
        self.enforcer.has_auto_save_enabled()
    }
}

impl CachedApi for CachedEnforcer {
    fn set_cache(&mut self, cache: Box<dyn Cache<Vec<String>, bool>>) {
        self.cache = cache;
    }

    fn set_ttl(&mut self, ttl: Duration) {
        self.cache.set_ttl(ttl);
    }

    fn set_capacity(&mut self, cap: usize) {
        self.cache.set_capacity(cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_send<T: Send>() -> bool {
        true
    }

    fn is_sync<T: Sync>() -> bool {
        true
    }

    #[test]
    fn test_send_sync() {
        assert!(is_send::<CachedEnforcer>());
        assert!(is_sync::<CachedEnforcer>());
    }
}
