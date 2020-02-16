use crate::rbac::RoleManager;
use crate::Result;

// use async_trait::async_trait;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

mod assertion;
mod default_model;
mod function_map;

pub(crate) use assertion::{Assertion, AssertionMap};
pub use default_model::DefaultModel;
pub(crate) use function_map::*;

// #[async_trait]
pub trait Model: Send + Sync {
    fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool;
    fn get_model(&self) -> &HashMap<String, AssertionMap>;
    fn get_mut_model(&mut self) -> &mut HashMap<String, AssertionMap>;
    fn build_role_links(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()>;
    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool;
    fn add_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<&str>>) -> bool;
    fn get_policy(&self, sec: &str, ptype: &str) -> Vec<Vec<String>>;
    fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>>;
    fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool;
    fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
    ) -> Vec<String>;
    fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool;
    fn remove_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<&str>>) -> bool;
    fn clear_policy(&mut self);
    fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool;
}
