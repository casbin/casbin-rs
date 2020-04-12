use crate::{rbac::RoleManager, Result};

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

mod assertion;
mod default_model;
mod function_map;

pub(crate) use assertion::{Assertion, AssertionMap};
pub use default_model::DefaultModel;
pub use function_map::*;

pub trait Model: Send + Sync {
    fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool;
    fn get_model(&self) -> &HashMap<String, AssertionMap>;
    fn get_mut_model(&mut self) -> &mut HashMap<String, AssertionMap>;
    fn build_role_links(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()>;
    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool;
    fn add_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> bool;
    fn get_policy(&self, sec: &str, ptype: &str) -> Vec<Vec<String>>;
    fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>>;
    fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> bool;
    fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
    ) -> Vec<String>;
    fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool;
    fn remove_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> bool;
    fn clear_policy(&mut self);
    fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> bool;
}

impl<T: Model + ?Sized> Model for Box<T> {
    fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool {
        (**self).add_def(sec, key, value)
    }
    fn get_model(&self) -> &HashMap<String, AssertionMap> {
        (**self).get_model()
    }
    fn get_mut_model(&mut self) -> &mut HashMap<String, AssertionMap> {
        (**self).get_mut_model()
    }
    fn build_role_links(&mut self, rm: Arc<RwLock<dyn RoleManager>>) -> Result<()> {
        (**self).build_role_links(rm)
    }
    fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        (**self).add_policy(sec, ptype, rule)
    }
    fn add_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> bool {
        (**self).add_policies(sec, ptype, rules)
    }
    fn get_policy(&self, sec: &str, ptype: &str) -> Vec<Vec<String>> {
        (**self).get_policy(sec, ptype)
    }
    fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Vec<Vec<String>> {
        (**self).get_filtered_policy(sec, ptype, field_index, field_values)
    }
    fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        (**self).has_policy(sec, ptype, rule)
    }
    fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
    ) -> Vec<String> {
        (**self).get_values_for_field_in_policy(sec, ptype, field_index)
    }
    fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> bool {
        (**self).remove_policy(sec, ptype, rule)
    }
    fn remove_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> bool {
        (**self).remove_policies(sec, ptype, rules)
    }
    fn clear_policy(&mut self) {
        (**self).clear_policy()
    }
    fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> bool {
        (**self).remove_filtered_policy(sec, ptype, field_index, field_values)
    }
}
