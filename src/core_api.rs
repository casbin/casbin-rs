use crate::{Adapter, Effector, Filter, Model, Result, RoleManager, TryIntoAdapter, TryIntoModel};

#[cfg(feature = "watcher")]
use crate::Watcher;

#[cfg(feature = "logging")]
use crate::Logger;

#[cfg(feature = "incremental")]
use crate::emitter::EventData;

use async_trait::async_trait;

use std::sync::{Arc, RwLock};

#[async_trait]
pub trait CoreApi: Send + Sync {
    async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Result<Self>
    where
        Self: Sized;
    fn add_function(&mut self, fname: &str, f: fn(String, String) -> bool);
    fn get_model(&self) -> &dyn Model;
    fn get_mut_model(&mut self) -> &mut dyn Model;
    fn get_adapter(&self) -> &dyn Adapter;
    fn get_mut_adapter(&mut self) -> &mut dyn Adapter;
    #[cfg(feature = "watcher")]
    fn set_watcher(&mut self, w: Box<dyn Watcher>);
    #[cfg(feature = "watcher")]
    fn get_watcher(&self) -> Option<&dyn Watcher>;
    #[cfg(feature = "watcher")]
    fn get_mut_watcher(&mut self) -> Option<&mut dyn Watcher>;
    fn get_role_manager(&self) -> Arc<RwLock<dyn RoleManager>>;
    fn set_role_manager(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()>;
    #[cfg(feature = "logging")]
    fn get_logger(&self) -> &dyn Logger;
    #[cfg(feature = "logging")]
    fn set_logger(&mut self, logger: Box<dyn Logger>);
    fn add_matching_fn(&mut self, f: fn(&str, &str) -> bool) -> Result<()>;
    async fn set_model<M: TryIntoModel>(&mut self, m: M) -> Result<()>;
    async fn set_adapter<A: TryIntoAdapter>(&mut self, a: A) -> Result<()>;
    fn set_effector(&mut self, e: Box<dyn Effector>);
    fn enforce<S: AsRef<str> + Send + Sync>(&self, rvals: &[S]) -> Result<bool>;
    fn enforce_mut<S: AsRef<str> + Send + Sync>(&mut self, rvals: &[S]) -> Result<bool>;
    fn build_role_links(&mut self) -> Result<()>;
    #[cfg(feature = "incremental")]
    fn build_incremental_role_links(&mut self, d: EventData) -> Result<()>;
    async fn load_policy(&mut self) -> Result<()>;
    async fn load_filtered_policy(&mut self, f: Filter) -> Result<()>;
    fn is_filtered(&self) -> bool;
    async fn save_policy(&mut self) -> Result<()>;
    fn clear_policy(&mut self);
    #[cfg(feature = "logging")]
    fn enable_log(&mut self, enabled: bool);
    fn enable_auto_save(&mut self, auto_save: bool);
    fn enable_enforce(&mut self, enabled: bool);
    fn enable_auto_build_role_links(&mut self, auto_build_role_links: bool);
    #[cfg(feature = "watcher")]
    fn enable_auto_notify_watcher(&mut self, auto_notify_watcher: bool);
    fn has_auto_save_enabled(&self) -> bool;
    #[cfg(feature = "watcher")]
    fn has_auto_notify_watcher_enabled(&self) -> bool;
    fn has_auto_build_role_links_enabled(&self) -> bool;
}
