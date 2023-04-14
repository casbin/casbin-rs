use async_trait::async_trait;

use std::hash::Hash;

pub mod default_cache;

pub use default_cache::DefaultCache;

#[async_trait]
pub trait Cache<K, V>: Send + Sync
where
    K: Eq + Hash,
    V: Clone,
{
    fn get(&self, k: &K) -> Option<V>;
    fn has(&self, k: &K) -> bool;
    fn set(&self, k: K, v: V);
    fn clear(&self);
}
