use crate::{cache::Cache, core_api::CoreApi};

pub trait CachedApi: CoreApi + Send + Sync {
    fn get_mut_cache(&mut self) -> &mut dyn Cache<u64, bool>;
    fn set_cache(&mut self, cache: Box<dyn Cache<u64, bool>>);
    fn set_capacity(&mut self, cap: usize);
}
