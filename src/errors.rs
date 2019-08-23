use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone)]
pub struct CasbinError {
    msg: &'static str,
}

impl CasbinError {
    pub fn new(msg: &'static str) -> Self {
        CasbinError { msg }
    }
}

impl Display for CasbinError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "casbin error, msg={}", self.msg)
    }
}

impl Error for CasbinError {}
