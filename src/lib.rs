mod adapter;
mod cache;
mod cached_api;
mod cached_enforcer;
mod config;
mod convert;
mod core_api;
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

pub use adapter::{Adapter, FileAdapter, MemoryAdapter, NullAdapter};
pub use cache::{Cache, DefaultCache};
pub use cached_api::CachedApi;
pub use cached_enforcer::CachedEnforcer;
pub use convert::{TryIntoAdapter, TryIntoModel};
pub use core_api::CoreApi;
pub use effector::{DefaultEffector, EffectKind, Effector};
pub use emitter::{Event, EventData, EventEmitter, EventKey};
pub use enforcer::Enforcer;
pub use error::Error;
pub use internal_api::InternalApi;
pub use management_api::MgmtApi;
pub use model::{DefaultModel, Model};
pub use rbac::{DefaultRoleManager, RoleManager};
pub use rbac_api::RbacApi;
pub use watcher::Watcher;

pub type Result<T> = std::result::Result<T, Error>;
