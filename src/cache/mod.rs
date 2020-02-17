use async_trait::async_trait;

use std::hash::Hash;
use std::time::Duration;

pub mod default_cache;

pub use default_cache::DefaultCache;

#[async_trait]
pub trait Cache<K, V>: Send + Sync
where
    K: Eq + Hash,
{
    fn set_capacity(&mut self, c: usize);
    fn set_ttl(&mut self, t: Duration);
    async fn get(&self, k: &K) -> Option<&V>;
    async fn has(&self, k: &K) -> bool;
    async fn set(&mut self, k: K, v: V);
    async fn clear(&mut self);
}
