#[cfg(any(feature = "watcher", feature = "cached"))]
use crate::core_api::CoreApi;

#[cfg(feature = "cached")]
use crate::cached_api::CachedApi;

use std::{fmt, hash::Hash};

#[derive(Hash, PartialEq, Eq)]
pub enum Event {
    PolicyChange,
    ClearCache,
}

pub trait EventKey: Hash + PartialEq + Eq + Send + Sync {}
impl<T> EventKey for T where T: Hash + PartialEq + Eq + Send + Sync {}

#[derive(Clone)]
pub enum EventData {
    AddPolicy(Vec<String>),
    AddPolicies(Vec<Vec<String>>),
    RemovePolicy(Vec<String>),
    RemovePolicies(Vec<Vec<String>>),
    RemoveFilteredPolicy(Vec<Vec<String>>),
    SavePolicy(Vec<Vec<String>>),
    ClearCache,
}

impl fmt::Display for EventData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EventData::*;
        match *self {
            AddPolicy(ref p) => write!(f, "Event: AddPolicy, Data: {:?}", p.join(", ")),
            AddPolicies(ref p) => write!(f, "Event: AddPolicies, Added: {}", p.len()),
            RemovePolicy(ref p) => write!(f, "Event: RemovePolicy, Data: {:?}", p.join(", ")),
            RemovePolicies(ref p) => write!(f, "Event: RemovePolicies, Removed: {}", p.len()),
            RemoveFilteredPolicy(ref p) => {
                write!(f, "Event: RemoveFilteredPolicy, Removed: {}", p.len())
            }
            SavePolicy(ref p) => write!(f, "Event: SavePolicy, Saved: {}", p.len()),
            ClearCache => write!(f, "Event: ClearCache, Data: ClearCache"),
        }
    }
}

pub trait EventEmitter<K>
where
    K: EventKey,
{
    fn on(&mut self, e: K, f: fn(&mut Self, EventData));
    fn off(&mut self, e: K);
    fn emit(&mut self, e: K, d: EventData);
}

#[cfg(feature = "watcher")]
pub(crate) fn notify_watcher<T: CoreApi>(e: &mut T, d: EventData) {
    #[cfg(feature = "logging")]
    {
        e.get_logger().print_mgmt_log(&d);
    }

    if let Some(w) = e.get_mut_watcher() {
        w.update(d);
    }
}

#[cfg(feature = "cached")]
#[allow(unused_variables)]
pub(crate) fn clear_cache<T: CoreApi + CachedApi>(ce: &mut T, d: EventData) {
    #[cfg(feature = "logging")]
    {
        ce.get_logger().print_mgmt_log(&d);
    }

    ce.get_mut_cache().clear();
}
