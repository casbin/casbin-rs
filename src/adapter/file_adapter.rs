use crate::adapter::Adapter;
use crate::error::{Error, ModelError};
use crate::model::Model;
use crate::Result;

use std::convert::AsRef;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;

pub struct FileAdapter<P: AsRef<Path>> {
    pub file_path: P,
}

type LoadPolicyFileHandler = fn(String, &mut Model);

impl<P: AsRef<Path>> FileAdapter<P> {
    pub fn new(p: P) -> Self {
        FileAdapter { file_path: p }
    }

    pub fn load_policy_file(&self, m: &mut Model, handler: LoadPolicyFileHandler) -> Result<()> {
        let f = File::open(&self.file_path)?;
        let f = BufReader::new(f);
        for line in f.lines() {
            handler(line?, m);
        }
        Ok(())
    }

    pub fn save_policy_file(&self, text: String) -> Result<()> {
        let mut file = File::create(&self.file_path)?;
        file.write_all(text.as_bytes())?;
        Ok(())
    }
}

impl<P: AsRef<Path> + Send + Sync> Adapter for FileAdapter<P> {
    fn load_policy(&self, m: &mut Model) -> Result<()> {
        self.load_policy_file(m, load_policy_line)?;
        Ok(())
    }

    fn save_policy(&self, m: &mut Model) -> Result<()> {
        if self.file_path.as_ref().as_os_str().is_empty() {
            return Err(Error::IoError(IoError::new(
                ErrorKind::Other,
                "save policy failed, file path is empty",
            ))
            .into());
        }

        let mut tmp = String::new();
        let ast_map1 = m.get_model().get("p").ok_or_else(|| {
            Error::ModelError(ModelError::P(
                "Missing policy definition in conf file".to_owned(),
            ))
        })?;
        for (ptype, ast) in ast_map1 {
            for rule in ast.get_policy() {
                let s1 = format!("{}, {}\n", ptype, rule.join(","));
                tmp += s1.as_str();
            }
        }

        if let Some(ast_map2) = m.get_model().get("g") {
            for (ptype, ast) in ast_map2 {
                for rule in ast.get_policy() {
                    let s1 = format!("{}, {}\n", ptype, rule.join(","));
                    tmp += s1.as_str();
                }
            }
        }

        self.save_policy_file(tmp)?;
        Ok(())
    }

    fn add_policy(&mut self, _sec: &str, _ptype: &str, _rule: Vec<&str>) -> Result<bool> {
        // this api shouldn't implement, just for convinent
        Ok(true)
    }

    fn remove_policy(&self, _sec: &str, _ptype: &str, _rule: Vec<&str>) -> Result<bool> {
        // this api shouldn't implement, just for convinent
        Ok(true)
    }

    fn remove_filtered_policy(
        &self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<&str>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convinent
        Ok(true)
    }
}

fn load_policy_line(line: String, m: &mut Model) {
    if line.is_empty() || line.starts_with('#') {
        return;
    }
    let tokens: Vec<String> = line.split(',').map(|x| x.trim().to_string()).collect();
    let key = tokens[0].clone();

    if let Some(sec) = key.chars().next().map(|x| x.to_string()) {
        if let Some(t1) = m.model.get_mut(&sec) {
            if let Some(t2) = t1.get_mut(&key) {
                t2.policy.insert(tokens[1..].to_vec());
            }
        }
    }
}
