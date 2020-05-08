use async_trait::async_trait;

use std::{hash::Hash, time::Duration};

pub mod default_cache;

pub use default_cache::DefaultCache;

#[async_trait]
pub trait Cache<K, V>: Send + Sync
where
    K: Eq + Hash,
{
    fn set_capacity(&mut self, c: usize);
    fn set_ttl(&mut self, t: Duration);
    fn get(&self, k: &K) -> Option<&V>;
    fn has(&self, k: &K) -> bool;
    fn set(&mut self, k: K, v: V);
    fn clear(&mut self);
}
