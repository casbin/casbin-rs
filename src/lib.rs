pub mod adapter;
pub mod config;
pub mod effector;
pub mod enforcer;
pub mod errors;
pub mod internal_api;
pub mod management_api;
pub mod model;
pub mod rbac;
mod rbac_api;

pub use internal_api::InternalApi;
pub use management_api::MgmtApi;
pub use rbac_api::RbacApi;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
