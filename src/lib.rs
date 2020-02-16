mod adapter;
mod cache;
mod cached_enforcer;
mod config;
mod effector;
mod emitter;
mod enforcer;
mod internal_api;
mod management_api;
mod model;
mod rbac;
mod rbac_api;
mod util;
mod watcher;

pub mod error;
pub mod prelude;

pub use adapter::{Adapter, FileAdapter};
pub use cache::Cache;
pub use cached_enforcer::CachedEnforcer;
pub use enforcer::Enforcer;
pub use internal_api::InternalApi;
pub use management_api::MgmtApi;
pub use model::{DefaultModel, Model};
pub use rbac_api::RbacApi;
pub use watcher::Watcher;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
