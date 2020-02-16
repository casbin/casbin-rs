use crate::adapter::Adapter;
use crate::emitter::{Event, CACHED_EMITTER};
use crate::enforcer::Enforcer;
use crate::model::Model;
use crate::Result;

use emitbrown::Events;
use ttl_cache::TtlCache;

use std::ops::{Deref, DerefMut};
use std::time::Duration;

pub struct CachedEnforcer {
    pub(crate) ttl: Duration,
    pub(crate) max_cached_items: usize,
    pub(crate) enforcer: Enforcer,
    pub(crate) cache: Option<TtlCache<Vec<String>, bool>>,
}

impl CachedEnforcer {
    pub async fn new(m: Box<dyn Model>, a: Box<dyn Adapter>) -> Result<CachedEnforcer> {
        let cached_enforcer = CachedEnforcer {
            ttl: Duration::from_secs(120),
            max_cached_items: 1000,
            enforcer: Enforcer::new(m, a).await?,
            cache: None,
        };

        CACHED_EMITTER.lock().unwrap().on(
            Event::PolicyChange,
            Box::new(|ce: &mut CachedEnforcer| {
                if let Some(ref mut cache) = ce.cache {
                    cache.clear();
                }
            }),
        );

        Ok(cached_enforcer)
    }

    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
    }

    pub fn set_max_cached_items(&mut self, max_cached_items: usize) {
        self.max_cached_items = max_cached_items;
    }

    pub fn enable_cache(&mut self) {
        if self.cache.is_none() {
            self.cache = Some(TtlCache::new(self.max_cached_items));
        }
    }

    pub fn disable_cache(&mut self) {
        if self.cache.is_some() {
            self.cache = None;
        }
    }

    pub fn enforce(&mut self, rvals: Vec<&str>) -> Result<bool> {
        if let Some(ref mut cache) = self.cache {
            let key: Vec<String> = rvals.iter().map(|&x| String::from(x)).collect();

            if let Some(result) = cache.get(&key) {
                Ok(*result)
            } else {
                let result = self.enforcer.enforce(rvals)?;
                cache.insert(key, result, self.ttl);
                Ok(result)
            }
        } else {
            self.enforcer.enforce(rvals)
        }
    }
}

impl Deref for CachedEnforcer {
    type Target = Enforcer;

    fn deref(&self) -> &Self::Target {
        &self.enforcer
    }
}

impl DerefMut for CachedEnforcer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.enforcer
    }
}
