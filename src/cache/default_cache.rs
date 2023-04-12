use crate::cache::Cache;
use mini_moka::sync::Cache as MokaCache;
use std::hash::Hash;

pub struct DefaultCache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
{
    cache: MokaCache<K, V>,
}

impl<K, V> DefaultCache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
{
    pub fn new(cap: usize) -> DefaultCache<K, V> {
        DefaultCache {
            cache: MokaCache::new(cap as u64),
        }
    }
}

impl<K, V> Cache<K, V> for DefaultCache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
{
    fn get(&self, k: &K) -> Option<V> {
        self.cache.get(k)
    }

    fn has(&self, k: &K) -> bool {
        self.cache.contains_key(k)
    }

    fn set(&self, k: K, v: V) {
        self.cache.insert(k, v);
    }

    fn clear(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(all(test, feature = "cached"))]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get() {
        let cache = DefaultCache::new(1);

        cache.set(vec!["alice", "/data1", "read"], false);
        assert!(cache.get(&vec!["alice", "/data1", "read"]) == Some(false));
    }

    #[test]
    fn test_has_and_clear() {
        let cache = DefaultCache::new(1);

        cache.set(vec!["alice", "/data1", "read"], false);
        assert!(cache.has(&vec!["alice", "/data1", "read"]));
        cache.clear();
        assert!(!cache.has(&vec!["alice", "/data1", "read"]));
    }
}
