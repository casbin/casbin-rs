mod adapter;
mod config;
mod effector;
mod enforcer;
mod internal_api;
mod management_api;
mod model;
mod rbac;
mod rbac_api;

pub mod error;
pub mod prelude;

pub use adapter::{Adapter, FileAdapter};
pub use enforcer::Enforcer;
pub use internal_api::InternalApi;
pub use management_api::MgmtApi;
pub use model::Model;
pub use rbac_api::RbacApi;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
