use crate::{
    adapter::Adapter,
    convert::{TryIntoAdapter, TryIntoModel},
    core_api::CoreApi,
    effector::Effector,
    enforcer::Enforcer,
    model::Model,
    rbac::RoleManager,
    watcher::Watcher,
    Result,
};

use async_trait::async_trait;

use std::sync::{Arc, RwLock};

pub struct SyncedEnforcer(Arc<RwLock<Enforcer>>);

#[async_trait]
impl CoreApi for SyncedEnforcer {
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<Self> {
        let enforcer = Enforcer::new(m, a).await?;

        Ok(SyncedEnforcer(Arc::new(RwLock::new(enforcer))))
    }

    fn add_function(&mut self, fname: &str, f: fn(String, String) -> bool) {
        self.0.write().unwrap().add_function(fname, f)
    }

    #[inline]
    fn get_model(&self) -> &dyn Model {
        self.0.read().unwrap().get_model()
    }

    #[inline]
    fn get_mut_model(&mut self) -> &mut dyn Model {
        self.0.write().unwrap().get_mut_model()
    }

    #[inline]
    fn get_adapter(&self) -> &dyn Adapter {
        self.0.read().unwrap().get_adapter()
    }

    #[inline]
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter {
        self.0.write().unwrap().get_mut_adapter()
    }

    #[inline]
    fn set_watcher(&mut self, w: Box<dyn Watcher>) {
        self.0.write().unwrap().set_watcher(w)
    }

    #[inline]
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>> {
        self.0.read().unwrap().get_role_manager()
    }

    #[inline]
    fn set_role_manager(&mut self, rm: Arc<RwLock<dyn RoleManager>>) {
        self.0.write().unwrap().set_role_manager(rm)
    }

    #[inline]
    fn add_matching_fn(&mut self, f: fn(String, String) -> bool) -> Result<()> {
        self.0.write().unwrap().add_matching_fn(f)
    }

    #[inline]
    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()> {
        self.0.write().unwrap().set_model(m).await
    }

    #[inline]
    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()> {
        self.0.write().unwrap().set_adapter(a).await
    }

    #[inline]
    fn set_effector(&mut self, e: Box<dyn Effector>) {
        self.0.write().unwrap().set_effector(e)
    }

    #[inline]
    async fn enforce<S: AsRef<str> + Send + Sync>(&mut self, rvals: &[S]) -> Result<bool> {
        self.0.write().unwrap().enforce(rvals).await
    }

    #[inline]
    fn build_role_links(&mut self) -> Result<()> {
        self.0.write().unwrap().build_role_links()
    }

    #[inline]
    async fn load_policy(&mut self) -> Result<()> {
        self.0.write().unwrap().load_policy().await
    }

    #[inline]
    async fn save_policy(&mut self) -> Result<()> {
        self.0.write().unwrap().save_policy().await
    }

    #[inline]
    fn clear_policy(&mut self) {
        self.0.write().unwrap().clear_policy()
    }

    #[inline]
    fn enable_enforce(&mut self, enabled: bool) {
        self.0.write().unwrap().enable_enforce(enabled)
    }

    #[inline]
    fn enable_auto_save(&mut self, auto_save: bool) {
        self.0.write().unwrap().enable_auto_save(auto_save)
    }

    #[inline]
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool) {
        self.0
            .write()
            .unwrap()
            .enable_auto_build_role_links(auto_build_role_links)
    }

    #[inline]
    fn has_auto_save_enabled(&self) -> bool {
        self.0.read().unwrap().has_auto_save_enabled()
    }
}
