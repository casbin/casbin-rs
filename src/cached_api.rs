use crate::cache::Cache;

use std::time::Duration;

pub trait CachedApi: Sized + Send + Sync {
    fn get_mut_cache(&mut self) -> &mut dyn Cache<Vec<String>, bool>;
    fn set_cache(&mut self, cache: Box<dyn Cache<Vec<String>, bool>>);
    fn set_ttl(&mut self, ttl: Duration);
    fn set_capacity(&mut self, cap: usize);
}
