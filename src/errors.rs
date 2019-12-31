use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone)]
pub enum ParseError {
    RoleDefinitionNumber,
    GroupingPolicyNumber,
    DomainLength,
}

impl Error for ParseError {}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let description = match self {
            ParseError::RoleDefinitionNumber => {
                String::from("the number of \"_\" in role definition should be at least 2")
            }
            ParseError::GroupingPolicyNumber => {
                String::from("grouping policy elements do not meet role definition")
            }
            ParseError::DomainLength => String::from("domain can at most contains 1 string"),
        };
        write!(f, "{}", description)
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    IoError(String),
    ParseError(ParseError),
    AdapterError(String), // for third-party adapters
    RoleNotExists,
    PolicyFilePathEmpty,
}

impl Error for RuntimeError {}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let description = match self {
            RuntimeError::RoleNotExists => String::from("name1 or name2 doesn't exists"),
            RuntimeError::PolicyFilePathEmpty => {
                String::from("save policy failed, file path is empty")
            }
            RuntimeError::IoError(s) => s.to_owned(),
            RuntimeError::ParseError(s) => s.to_string(),
            RuntimeError::AdapterError(s) => s.to_owned(),
        };
        write!(f, "{}", description)
    }
}

impl From<std::io::Error> for RuntimeError {
    fn from(error: std::io::Error) -> Self {
        RuntimeError::IoError(error.to_string())
    }
}

impl From<ParseError> for RuntimeError {
    fn from(error: ParseError) -> Self {
        RuntimeError::ParseError(error)
    }
}
