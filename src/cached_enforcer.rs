use crate::{
    adapter::{Adapter, Filter},
    cache::{Cache, DefaultCache},
    cached_api::CachedApi,
    convert::{TryIntoAdapter, TryIntoModel},
    core_api::CoreApi,
    effector::Effector,
    emitter::{clear_cache, Event, EventData, EventEmitter},
    enforcer::Enforcer,
    model::Model,
    rbac::RoleManager,
    Result,
};

#[cfg(any(feature = "logging", feature = "watcher"))]
use crate::emitter::notify_logger_and_watcher;

#[cfg(feature = "watcher")]
use crate::watcher::Watcher;

#[cfg(feature = "logging")]
use crate::logger::Logger;

#[cfg(feature = "explain")]
use crate::{error::ModelError, get_or_err};

use async_trait::async_trait;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

type EventCallback = fn(&mut CachedEnforcer, EventData);

pub struct CachedEnforcer {
    pub(crate) enforcer: Enforcer,
    pub(crate) cache: Box<dyn Cache<Vec<String>, bool>>,
    pub(crate) events: HashMap<Event, Vec<EventCallback>>,
}

impl EventEmitter<Event> for CachedEnforcer {
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

impl CachedEnforcer {
    pub(crate) fn private_enforce<S: AsRef<str> + Send + Sync>(
        &mut self,
        rvals: &[S],
    ) -> Result<(bool, bool, Option<Vec<usize>>)> {
        let cache_key: Vec<String> = rvals.iter().map(|x| String::from(x.as_ref())).collect();
        Ok(if let Some(result) = self.cache.get(&cache_key) {
            (*result, true, None)
        } else {
            let (result, idxs) = self.enforcer.private_enforce(rvals)?;
            self.cache.set(cache_key.clone(), result);
            (result, false, idxs)
        })
    }
}

#[async_trait]
impl CoreApi for CachedEnforcer {
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<CachedEnforcer> {
        let enforcer = Enforcer::new(m, a).await?;
        let cache = Box::new(DefaultCache::new(1000));

        let mut cached_enforcer = CachedEnforcer {
            enforcer,
            cache,
            events: HashMap::new(),
        };

        cached_enforcer.on(Event::ClearCache, clear_cache);
        #[cfg(any(feature = "logging", feature = "watcher"))]
        {
            cached_enforcer.on(Event::PolicyChange, notify_logger_and_watcher);
        }

        Ok(cached_enforcer)
    }

    #[inline]
    fn add_function(&mut self, fname: &str, f: fn(ImmutableString, ImmutableString) -> bool) {
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

    #[cfg(feature = "watcher")]
    #[inline]
    fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.enforcer.set_watcher(w);
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn get_watcher(&self) -> Option<&dyn Watcher> {
        self.enforcer.get_watcher()
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn get_mut_watcher(&mut self) -> Option<&mut dyn Watcher> {
        self.enforcer.get_mut_watcher()
    }
    #[inline]
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>> {
        self.enforcer.get_role_manager()
    }

    #[inline]
    fn set_role_manager(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()> {
        self.enforcer.set_role_manager(rm)
    }

    #[inline]
    fn add_matching_fn(&mut self, f: fn(&str, &str) -> bool) -> Result<()> {
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

    #[cfg(feature = "logging")]
    #[inline]
    fn get_logger(&self) -> &dyn Logger {
        self.enforcer.get_logger()
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn set_logger(&mut self, l: Box<dyn Logger>) {
        self.enforcer.set_logger(l);
    }

    #[inline]
    fn set_effector(&mut self, e: Box<dyn Effector>) {
        self.enforcer.set_effector(e);
    }

    fn enforce_mut<S: AsRef<str> + Send + Sync>(&mut self, rvals: &[S]) -> Result<bool> {
        #[allow(unused_variables)]
        let (authorized, cached, idxs) = self.private_enforce(rvals)?;
        #[cfg(feature = "logging")]
        {
            self.enforcer.get_logger().print_enforce_log(
                rvals.iter().map(|x| String::from(x.as_ref())).collect(),
                authorized,
                cached,
            );

            #[cfg(feature = "explain")]
            {
                if let Some(idxs) = idxs {
                    let all_rules = get_or_err!(self, "p", ModelError::P, "policy").get_policy();
                    let rules: Vec<&Vec<String>> = idxs
                        .into_iter()
                        .filter_map(|y| all_rules.get_index(y))
                        .collect();
                    self.enforcer.get_logger().print_expl_log(rules);
                }
            }
        }

        Ok(authorized)
    }

    /// CachedEnforcer should use `enforce_mut` instead so that
    /// enforce result can be saved to cache
    fn enforce<S: AsRef<str> + Send + Sync>(&self, rvals: &[S]) -> Result<bool> {
        self.enforcer.enforce(rvals)
    }

    #[inline]
    fn build_role_links(&mut self) -> Result<()> {
        self.enforcer.build_role_links()
    }

    #[cfg(feature = "incremental")]
    #[inline]
    fn build_incremental_role_links(&mut self, d: EventData) -> Result<()> {
        self.enforcer.build_incremental_role_links(d)
    }

    #[inline]
    async fn load_policy(&mut self) -> Result<()> {
        self.enforcer.load_policy().await
    }

    #[inline]
    async fn load_filtered_policy(&mut self, f: Filter) -> Result<()> {
        self.enforcer.load_filtered_policy(f).await
    }

    #[inline]
    fn is_filtered(&self) -> bool {
        self.enforcer.is_filtered()
    }

    #[inline]
    async fn save_policy(&mut self) -> Result<()> {
        self.enforcer.save_policy().await
    }

    #[inline]
    fn clear_policy(&mut self) {
        self.enforcer.clear_policy();
    }

    #[cfg(feature = "logging")]
    #[inline]
    fn enable_log(&mut self, enabled: bool) {
        self.enforcer.enable_log(enabled);
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

    #[cfg(feature = "watcher")]
    #[inline]
    fn enable_auto_notify_watcher(&mut self, auto_notify_watcher: bool) {
        self.enforcer
            .enable_auto_notify_watcher(auto_notify_watcher);
    }

    #[inline]
    fn has_auto_save_enabled(&self) -> bool {
        self.enforcer.has_auto_save_enabled()
    }

    #[cfg(feature = "watcher")]
    #[inline]
    fn has_auto_notify_watcher_enabled(&self) -> bool {
        self.enforcer.has_auto_notify_watcher_enabled()
    }

    #[inline]
    fn has_auto_build_role_links_enabled(&self) -> bool {
        self.enforcer.has_auto_build_role_links_enabled()
    }
}

impl CachedApi for CachedEnforcer {
    fn get_mut_cache(&mut self) -> &mut dyn Cache<Vec<String>, bool> {
        &mut *self.cache
    }

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
