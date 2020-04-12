use crate::{Adapter, Effector, Model, Result, RoleManager, TryIntoAdapter, TryIntoModel, Watcher};

use async_trait::async_trait;

use std::sync::{Arc, RwLock};

#[async_trait]
pub trait CoreApi: Sized + Send + Sync {
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<Self>;
    fn add_function(&mut self, fname: &str, f: fn(String, String) -> bool);
    fn get_model(&self) -> &dyn Model;
    fn get_mut_model(&mut self) -> &mut dyn Model;
    fn get_adapter(&self) -> &dyn Adapter;
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter;
    fn set_watcher(&mut self, w: Box<dyn Watcher>);
    fn get_watcher(&self) -> Option<&dyn Watcher>;
    fn get_mut_watcher(&mut self) -> Option<&mut dyn Watcher>;
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>>;
    fn set_role_manager(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()>;
    fn add_matching_fn(&mut self, f: fn(String, String) -> bool) -> Result<()>;
    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()>;
    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()>;
    fn set_effector(&mut self, e: Box<dyn Effector>);
    async fn enforce<S: AsRef<str> + Send + Sync>(&mut self, rvals: &[S]) -> Result<bool>;
    fn build_role_links(&mut self) -> Result<()>;
    async fn load_policy(&mut self) -> Result<()>;
    async fn save_policy(&mut self) -> Result<()>;
    fn clear_policy(&mut self);
    fn enable_auto_save(&mut self, auto_save: bool);
    fn enable_enforce(&mut self, enabled: bool);
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool);
    fn has_auto_save_enabled(&self) -> bool;
}
