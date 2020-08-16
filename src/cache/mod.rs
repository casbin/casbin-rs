use async_trait::async_trait;

use std::{borrow::Cow, hash::Hash};

pub mod default_cache;

pub use default_cache::DefaultCache;

#[async_trait]
pub trait Cache<K, V>: Send + Sync
where
    K: Eq + Hash,
    V: Clone,
{
    fn set_capacity(&mut self, c: usize);
    fn get(&mut self, k: &K) -> Option<Cow<'_, V>>;
    fn has(&mut self, k: &K) -> bool;
    fn set(&mut self, k: K, v: V);
    fn clear(&mut self);
}
