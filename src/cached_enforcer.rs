use crate::cache::{Cache, DefaultCache};
use crate::convert::{TryIntoAdapter, TryIntoModel};
use crate::emitter::{Event, CACHED_EMITTER};
use crate::enforcer::Enforcer;
use crate::Result;

#[cfg(feature = "runtime-async-std")]
use async_std::task;

use emitbrown::Events;

use std::ops::{Deref, DerefMut};
use std::time::Duration;

pub struct CachedEnforcer {
    pub(crate) enforcer: Enforcer,
    pub(crate) cache: Box<dyn Cache<Vec<String>, bool>>,
}

impl CachedEnforcer {
    #[cfg(feature = "runtime-async-std")]
    pub async fn new(m: Box<dyn Model>, a: Box<dyn Adapter>) -> Result<CachedEnforcer> {
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
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<CachedEnforcer> {
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

    pub fn set_cache(&mut self, cache: Box<dyn Cache<Vec<String>, bool>>) {
        self.cache = cache;
    }

    pub fn set_ttl(&mut self, ttl: Duration) {
        self.cache.set_ttl(ttl);
    }

    pub fn set_capacity(&mut self, cap: usize) {
        self.cache.set_capacity(cap);
    }

    pub async fn enforce<S: AsRef<str>>(&mut self, rvals: &[S]) -> Result<bool> {
        let key: Vec<String> = rvals.iter().map(|x| String::from(x.as_ref())).collect();

        if let Some(result) = self.cache.get(&key).await {
            Ok(*result)
        } else {
            let result = self.enforcer.enforce(&rvals)?;
            self.cache.set(key, result).await;
            Ok(result)
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
