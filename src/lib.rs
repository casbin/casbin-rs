#[cfg(all(not(feature = "logging"), feature = "explain"))]
compile_error!(
    "'logging' feature must be enabled along with 'explain' feature"
);

mod adapter;
#[cfg(feature = "cached")]
mod cache;
#[cfg(feature = "cached")]
mod cached_api;
#[cfg(feature = "cached")]
mod cached_enforcer;
mod config;
mod convert;
mod core_api;
mod effector;
mod emitter;
mod enforcer;
mod internal_api;
#[cfg(feature = "logging")]
mod logger;
mod macros;
mod management_api;
mod model;
mod rbac;
mod rbac_api;
mod util;
#[cfg(feature = "watcher")]
mod watcher;

pub mod error;
pub mod frontend;
pub mod prelude;

#[cfg(not(target_arch = "wasm32"))]
pub use adapter::FileAdapter;
pub use adapter::{Adapter, Filter, MemoryAdapter, NullAdapter};

#[cfg(feature = "cached")]
pub use cache::{Cache, DefaultCache};
#[cfg(feature = "cached")]
pub use cached_api::CachedApi;
#[cfg(feature = "cached")]
pub use cached_enforcer::CachedEnforcer;
pub use convert::{EnforceArgs, TryIntoAdapter, TryIntoModel};
pub use core_api::{CoreApi, IEnforcer};
pub use effector::{
    DefaultEffectStream, DefaultEffector, EffectKind, Effector, EffectorStream,
};
pub use emitter::{Event, EventData, EventEmitter, EventKey};
pub use enforcer::EnforceContext;
pub use enforcer::Enforcer;
pub use error::Error;
pub use internal_api::InternalApi;
#[cfg(feature = "logging")]
pub use logger::{DefaultLogger, Logger};
pub use management_api::MgmtApi;
pub use model::{function_map, Assertion, DefaultModel, Model};
pub use rbac::{DefaultRoleManager, MatchingFn, RoleManager};
pub use rbac_api::RbacApi;
#[cfg(feature = "watcher")]
pub use watcher::Watcher;

pub type Result<T> = std::result::Result<T, Error>;

// re-exports
pub mod rhai {
    pub use rhai::*;
}
