use rhai::EvalAltResult;

use std::error::Error as StdError;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Error as IoError;

/// ModelError represents any type of errors in model.conf
#[derive(Debug)]
pub enum ModelError {
    R(String),
    P(String),
    E(String),
    M(String),
    Other(String),
}
impl Display for ModelError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        use ModelError::*;

        match self {
            R(msg) => write!(f, "Invalid request definition: {}", msg),
            P(msg) => write!(f, "Invalid policy definition: {}", msg),
            E(msg) => write!(f, "Unsupported effect: {}", msg),
            M(msg) => write!(f, "Invalid matcher: {}", msg),
            Other(msg) => write!(f, "Invalid section: {}", msg),
        }
    }
}
impl StdError for ModelError {}

/// PolicyError represents any type of errors in policy
#[derive(Debug)]
pub enum PolicyError {
    UnmatchPolicyDefinition,
}
impl Display for PolicyError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        use PolicyError::*;
        match self {
            UnmatchPolicyDefinition => write!(f, "Policy doesn't match its definition"),
        }
    }
}
impl StdError for PolicyError {}

/// RBAC error
#[derive(Debug)]
pub enum RbacError {
    NotFound(String),
}
impl Display for RbacError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        use RbacError::*;
        match self {
            NotFound(msg) => write!(f, r#"Role "{}" not found"#, msg),
        }
    }
}
impl StdError for RbacError {}

/// General casbin error
#[derive(Debug)]
pub enum Error {
    IoError(IoError),

    ModelError(ModelError),

    PolicyError(PolicyError),

    RbacError(RbacError),

    RhaiError(EvalAltResult),
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        use Error::*;

        match self {
            IoError(i_err) => i_err.fmt(f),
            ModelError(m_err) => m_err.fmt(f),
            PolicyError(p_err) => p_err.fmt(f),
            RbacError(r_err) => r_err.fmt(f),
            RhaiError(e_err) => e_err.fmt(f),
        }
    }
}
impl StdError for Error {}
