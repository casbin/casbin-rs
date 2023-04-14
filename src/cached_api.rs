use crate::{cache::Cache, core_api::CoreApi};

use std::hash::Hash;

pub trait CachedApi<K, V>: CoreApi + Send + Sync
where
    K: Eq + Hash,
    V: Clone,
{
    fn get_mut_cache(&mut self) -> &mut dyn Cache<K, V>;
    fn set_cache(&mut self, cache: Box<dyn Cache<K, V>>);
}
