use crate::{cached_api::CachedApi, core_api::CoreApi};

use std::hash::Hash;

#[derive(Hash, PartialEq, Eq)]
pub enum Event {
    PolicyChange,
}

pub fn notify_watcher<T: CoreApi>(e: &mut T, d: Option<EventData>) {
    if let Some(w) = e.get_mut_watcher() {
        w.update(d);
    }
}

pub fn clear_cache<T: CoreApi + CachedApi>(ce: &mut T, _d: Option<EventData>) {
    #[cfg(feature = "runtime-tokio")]
    {
        tokio::runtime::Builder::new()
            .basic_scheduler()
            .threaded_scheduler()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { ce.get_mut_cache().clear().await });
    }

    #[cfg(feature = "runtime-async-std")]
    {
        async_std::task::block_on(async { ce.get_mut_cache().clear().await });
    }
}

pub trait EventKey: Hash + PartialEq + Eq + Send + Sync {}
impl<T> EventKey for T where T: Hash + PartialEq + Eq + Send + Sync {}

#[derive(Clone)]
pub enum EventData {
    AddPolicy(Vec<String>),
    AddPolicies(Vec<Vec<String>>),
    RemovePolicy(Vec<String>),
    RemovePolicies(Vec<Vec<String>>),
    RemoveFilteredPolicy,
}

pub trait EventEmitter<K>
where
    K: EventKey,
{
    fn on(&mut self, e: K, f: fn(&mut Self, Option<EventData>));
    fn off(&mut self, e: K);
    fn emit(&mut self, e: K, d: Option<EventData>);
}
