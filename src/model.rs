use crate::config::Config;
use crate::error::{Error, ModelError, PolicyError};
use crate::rbac::{DefaultRoleManager, RoleManager};
use crate::Result;

use ip_network::IpNetwork;
use regex::Regex;
use rhai::Any;

use std::collections::HashMap;
use std::convert::AsRef;
use std::net::IpAddr;
use std::path::Path;

fn escape_assertion(s: String) -> String {
    let re = Regex::new(r#"(r|p)\."#).unwrap();
    re.replace_all(&s, "${1}_").to_string()
}

fn escape_g_function(s: String) -> String {
    let re = Regex::new(r#"(g\d*)\(((?:\s*[r|p]\.\w+\s*,\s*){1,2}\s*[r|p]\.\w+\s*)\)"#).unwrap();
    re.replace_all(&s, "${1}([${2}])").to_string()
}

fn escape_in_operator(s: String) -> String {
    let re =
        Regex::new(r#"((?:r\d*|p\d*)\.(?:[^\s]+))\s+in\s+(?:\[|\()([^\)\]]*)(?:\]|\))"#).unwrap();

    re.replace_all(&s, "inMatch($1, [$2])").replace("'", r#"""#)
}

pub(crate) type AssertionMap = HashMap<String, Assertion>;

#[derive(Clone)]
pub struct Assertion {
    pub key: String,
    pub value: String,
    pub tokens: Vec<String>,
    pub policy: Vec<Vec<String>>,
    pub rm: Box<dyn RoleManager>,
}

impl Assertion {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Assertion {
            key: String::new(),
            value: String::new(),
            tokens: vec![],
            policy: vec![],
            rm: Box::new(DefaultRoleManager::new(0)),
        }
    }

    #[allow(clippy::borrowed_box)]
    pub fn build_role_links(&mut self, rm: &mut Box<dyn RoleManager>) -> Result<()> {
        let count = self.value.chars().filter(|&c| c == '_').count();
        for rule in &self.policy {
            if count < 2 {
                return Err(Error::ModelError(ModelError::P(
                    r#"the number of "_" in role definition should be at least 2"#.to_owned(),
                ))
                .into());
            }
            if rule.len() < count {
                return Err(Error::PolicyError(PolicyError::UnmatchPolicyDefinition).into());
            }
            if count == 2 {
                rm.add_link(&rule[0], &rule[1], None);
            } else if count == 3 {
                rm.add_link(&rule[0], &rule[1], Some(&rule[2]));
            } else if count >= 4 {
                return Err(Error::ModelError(ModelError::P(
                    "Multiple domains are not supported".to_owned(),
                ))
                .into());
            }
        }
        self.rm = rm.clone();
        // self.rm.print_roles();
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct Model {
    pub(crate) model: HashMap<String, AssertionMap>,
}

impl Model {
    pub fn from_file<P: AsRef<Path>>(p: P) -> Result<Self> {
        let cfg = Config::from_file(p)?;

        let mut model = Model::default();

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;

        model.load_section(&cfg, "g")?;

        Ok(model)
    }

    pub fn from_str(&mut self, s: &str) -> Result<Self> {
        let cfg = Config::from_str(s)?;

        let mut model = Model::default();

        model.load_section(&cfg, "r")?;
        model.load_section(&cfg, "p")?;
        model.load_section(&cfg, "e")?;
        model.load_section(&cfg, "m")?;

        model.load_section(&cfg, "g")?;

        Ok(model)
    }

    pub fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool {
        let mut ast = Assertion::new();
        ast.key = key.to_owned();
        ast.value = value.to_owned();

        if ast.value.is_empty() {
            return false;
        }

        if sec == "r" || sec == "p" {
            ast.tokens = ast
                .value
                .split(',')
                .map(|x| format!("{}_{}", key, x.trim()))
                .collect();
        } else {
            ast.value = escape_in_operator(ast.value);
            ast.value = escape_g_function(ast.value);
            ast.value = escape_assertion(ast.value);
        }

        if let Some(new_model) = self.model.get_mut(sec) {
            new_model.insert(key.to_owned(), ast);
        } else {
            let mut new_ast_map = HashMap::new();
            new_ast_map.insert(key.to_owned(), ast);
            self.model.insert(sec.to_owned(), new_ast_map);
        }

        true
    }

    fn load_section(&mut self, cfg: &Config, sec: &str) -> Result<()> {
        let mut i = 1;

        loop {
            if !self.load_assersion(cfg, sec, &format!("{}{}", sec, self.get_key_suffix(i)))? {
                break Ok(());
            } else {
                i += 1;
            }
        }
    }

    fn load_assersion(&mut self, cfg: &Config, sec: &str, key: &str) -> Result<bool> {
        let sec_name = match sec {
            "r" => "request_definition",
            "p" => "policy_definition",
            "g" => "role_definition",
            "e" => "policy_effect",
            "m" => "matchers",
            _ => {
                return Err(Error::ModelError(ModelError::Other(sec.to_owned())).into());
            }
        };

        if let Some(val) = cfg.get_str(&format!("{}::{}", sec_name, key)) {
            Ok(self.add_def(sec, key, val))
        } else {
            Ok(false)
        }
    }

    fn get_key_suffix(&self, i: u64) -> String {
        if i == 1 {
            "".to_owned()
        } else {
            i.to_string()
        }
    }

    #[allow(clippy::borrowed_box)]
    pub fn build_role_links(&mut self, rm: &mut Box<dyn RoleManager>) -> Result<()> {
        if let Some(asts) = self.model.get_mut("g") {
            for (_key, ast) in asts.iter_mut() {
                ast.build_role_links(rm)?;
            }
        }
        Ok(())
    }

    pub fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                t2.policy.push(rule.into_iter().map(String::from).collect());
                t2.policy.dedup(); // avoid re-add, policy rules should be unique
                return true;
            }
        }
        false
    }

    pub fn get_policy(&self, sec: &str, ptype: &str) -> Vec<Vec<String>> {
        if let Some(t1) = self.model.get(sec) {
            if let Some(t2) = t1.get(ptype) {
                return t2.policy.clone();
            }
        }
        vec![]
    }

    pub fn get_filtered_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Vec<Vec<String>> {
        let mut res = vec![];
        if let Some(t1) = self.model.get(sec) {
            if let Some(t2) = t1.get(ptype) {
                for rule in t2.policy.iter() {
                    let mut matched = true;
                    for (i, field_value) in field_values.iter().enumerate() {
                        if field_value != &"" && &rule[field_index + i] != field_value {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res.push(rule.iter().map(String::from).collect());
                    }
                }
            }
        }
        res
    }

    pub fn has_policy(&self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        let policy = self.get_policy(sec, ptype);
        for r in policy {
            if r == rule {
                return true;
            }
        }
        false
    }

    pub fn get_values_for_field_in_policy(
        &self,
        sec: &str,
        ptype: &str,
        field_index: usize,
    ) -> Vec<String> {
        let mut values = vec![];
        let policy = self.get_policy(sec, ptype);
        for rule in policy {
            values.push(rule[field_index].clone());
        }
        values.sort_unstable();
        values.dedup(); // sort and then dedup will remove all duplicates
        values
    }

    pub fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                for (i, r) in t2.policy.iter().enumerate() {
                    if r == &rule {
                        t2.policy.remove(i);
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn clear_policy(&mut self) {
        if let Some(model_p) = self.model.get_mut("p") {
            for (_key, ast) in model_p.iter_mut() {
                ast.policy = vec![];
            }
        }
        if let Some(model_g) = self.model.get_mut("g") {
            for (_key, ast) in model_g.iter_mut() {
                ast.policy = vec![];
            }
        }
    }

    pub fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool {
        let mut res = false;
        let mut tmp: Vec<Vec<String>> = vec![];
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                for (_, rule) in t2.policy.iter().enumerate() {
                    let mut matched = true;
                    for (i, field_value) in field_values.iter().enumerate() {
                        if !field_value.is_empty() && rule[field_index + i] != *field_value {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        res = true;
                    } else {
                        tmp.push(rule.clone());
                    }
                }
            }
        }

        // update new policy
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                t2.policy = tmp;
            }
        }
        res
    }
}

pub struct FunctionMap {
    pub(crate) fm: HashMap<String, fn(String, String) -> bool>,
}

impl Default for FunctionMap {
    fn default() -> FunctionMap {
        let mut fm: HashMap<String, fn(String, String) -> bool> = HashMap::new();
        fm.insert("keyMatch".to_owned(), key_match);
        fm.insert("keyMatch2".to_owned(), key_match2);
        fm.insert("keyMatch3".to_owned(), key_match3);
        fm.insert("regexMatch".to_owned(), regex_match);
        fm.insert("ipMatch".to_owned(), ip_match);

        FunctionMap { fm }
    }
}

impl FunctionMap {
    pub fn add_function(&mut self, fname: &str, f: fn(String, String) -> bool) {
        self.fm.insert(fname.to_owned(), f);
    }
}

pub fn key_match(key1: String, key2: String) -> bool {
    if let Some(i) = key2.find('*') {
        if key1.len() > i {
            return key1[..i] == key2[..i];
        }
        key1[..] == key2[..i]
    } else {
        key1 == key2
    }
}

fn key_match2(key1: String, key2: String) -> bool {
    let mut key2 = key2.replace("/*", "/.*");
    let re = Regex::new("(.*):[^/]+(.*)").unwrap();
    loop {
        if !key2.contains("/:") {
            break;
        }
        key2 = re.replace_all(key2.as_str(), "$1[^/]+$2").to_string();
    }
    regex_match(key1, format!("^{}$", key2))
}

fn key_match3(key1: String, key2: String) -> bool {
    let mut key2 = key2.replace("/*", "/.*");
    let re = Regex::new(r"(.*)\{[^/]+\}(.*)").unwrap();
    loop {
        if !key2.contains("/{") {
            break;
        }
        key2 = re.replace_all(key2.as_str(), "$1[^/]+$2").to_string();
    }
    regex_match(key1, format!("^{}$", key2))
}

pub fn in_match(k1: String, k2: Vec<Box<dyn Any>>) -> bool {
    let r = k2
        .into_iter()
        .filter_map(|x| x.downcast_ref::<String>().map(|y| y.to_owned()))
        .collect::<Vec<String>>();
    r.contains(&k1)
}

pub fn regex_match(key1: String, key2: String) -> bool {
    Regex::new(key2.as_str()).unwrap().is_match(key1.as_str())
}

pub fn ip_match(key1: String, key2: String) -> bool {
    let key2_split = key2.splitn(2, '/').collect::<Vec<&str>>();
    let ip_addr2 = key2_split[0];

    if let (Ok(ip_addr1), Ok(ip_addr2)) = (key1.parse::<IpAddr>(), ip_addr2.parse::<IpAddr>()) {
        if key2_split.len() == 2 {
            match key2_split[1].parse::<u8>() {
                Ok(ip_netmask) => match IpNetwork::new_truncate(ip_addr2, ip_netmask) {
                    Ok(ip_network) => ip_network.contains(ip_addr1),
                    Err(err) => panic!("invalid ip network {}", err),
                },
                Err(_err) => panic!("invalid netmask {}", key2_split[1]),
            }
        } else {
            if let (IpAddr::V4(ip_addr1_new), IpAddr::V6(ip_addr2_new)) = (ip_addr1, ip_addr2) {
                if let Some(ip_addr2_new) = ip_addr2_new.to_ipv4() {
                    return ip_addr2_new == ip_addr1_new;
                }
            }

            ip_addr1 == ip_addr2
        }
    } else {
        panic!("invalid argument {} {}", key1, key2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_match() {
        assert!(key_match("/foo/bar".to_owned(), "/foo/*".to_owned()));
        assert!(!key_match("/bar/foo".to_owned(), "/foo/*".to_owned()));
    }

    #[test]
    fn test_key_match2() {
        assert!(key_match2("/foo/bar".to_owned(), "/foo/*".to_owned()));
        assert!(key_match2("/foo/baz".to_owned(), "/foo/:bar".to_owned()));
        assert!(key_match2(
            "/foo/baz/foo".to_owned(),
            "/foo/:bar/foo".to_owned()
        ));
        assert!(!key_match2("/baz".to_owned(), "/foo".to_owned()));
    }

    #[test]
    fn test_regex_match() {
        assert!(regex_match("foobar".to_owned(), "^foo*".to_owned()));
        assert!(!regex_match("barfoo".to_owned(), "^foo*".to_owned()));
    }

    #[test]
    fn test_key_match3() {
        assert!(key_match3("/foo/bar".to_owned(), "/foo/*".to_owned()));
        assert!(key_match3("/foo/baz".to_owned(), "/foo/{bar}".to_owned()));
        assert!(key_match3(
            "/foo/baz/foo".to_owned(),
            "/foo/{bar}/foo".to_owned()
        ));
        assert!(!key_match3("/baz".to_owned(), "/foo".to_owned()));
    }

    #[test]
    fn test_ip_match() {
        assert!(ip_match("::1".to_owned(), "::0:1".to_owned()));
        assert!(ip_match("192.168.1.1".to_owned(), "192.168.1.1".to_owned()));
        assert!(ip_match(
            "127.0.0.1".to_owned(),
            "::ffff:127.0.0.1".to_owned()
        ));
        assert!(ip_match(
            "192.168.2.123".to_owned(),
            "192.168.2.0/24".to_owned()
        ));
        assert!(!ip_match("::1".to_owned(), "127.0.0.2".to_owned()));
        assert!(!ip_match(
            "192.168.2.189".to_owned(),
            "192.168.1.134/26".to_owned()
        ));
    }

    #[test]
    #[should_panic]
    fn test_ip_match_panic_1() {
        assert!(ip_match("I am alice".to_owned(), "127.0.0.1".to_owned()));
    }

    #[test]
    #[should_panic]
    fn test_ip_match_panic_2() {
        assert!(ip_match("127.0.0.1".to_owned(), "I am alice".to_owned()));
    }

    #[test]
    fn test_escape_g_function() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp = "g([r.sub, p.sub]) && r.obj == p.obj && r.act == p.act";

        assert_eq!(exp, escape_g_function(s.to_owned()));

        let s1 = "g2(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp1 = "g2([r.sub, p.sub]) && r.obj == p.obj && r.act == p.act";

        assert_eq!(exp1, escape_g_function(s1.to_owned()));

        let s2 = "g3(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp2 = "g3([r.sub, p.sub]) && r.obj == p.obj && r.act == p.act";

        assert_eq!(exp2, escape_g_function(s2.to_owned()));
    }

    #[test]
    fn test_escape_in_operator() {
        let s1 = r#"g(r.sub, p.sub) && r.act in ["a","b","c"] && r.sub in ["alice","bob"] && r.obj in ["data1","data2"]"#;
        let exp1 = r#"g(r.sub, p.sub) && inMatch(r.act, ["a","b","c"]) && inMatch(r.sub, ["alice","bob"]) && inMatch(r.obj, ["data1","data2"])"#;

        assert_eq!(exp1, escape_in_operator(s1.to_owned()));

        let s2 = r#"g(r.sub, p.sub) && p.act in ["a","b","c"] && p.sub in ["alice","bob"] && p.obj in ["data1","data2"]"#;
        let exp2 = r#"g(r.sub, p.sub) && inMatch(p.act, ["a","b","c"]) && inMatch(p.sub, ["alice","bob"]) && inMatch(p.obj, ["data1","data2"])"#;

        assert_eq!(exp2, escape_in_operator(s2.to_owned()));

        let s3 =
            r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ('data2', 'data3')"#;
        let exp3 = r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || inMatch(r.obj, ["data2", "data3"])"#;

        assert_eq!(exp3, escape_in_operator(s3.to_owned()));

        let s4 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act || r.tenant in ('alice', 'bob')"#;
        let exp4 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act || inMatch(r.tenant, ["alice", "bob"])"#;

        assert_eq!(exp4, escape_in_operator(s4.to_owned()));

        let s5 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act && p2.sub in ('alice', 'bob') || r.obj in ('data2', 'data3')"#;
        let exp5 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act && inMatch(p2.sub, ["alice", "bob"]) || inMatch(r.obj, ["data2", "data3"])"#;

        assert_eq!(exp5, escape_in_operator(s5.to_owned()));
    }

    #[test]
    fn test_escape_assertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act";

        assert_eq!(exp, escape_assertion(s.to_owned()));
    }

    use crate::adapter::{FileAdapter, MemoryAdapter};
    use crate::enforcer::Enforcer;
    #[test]
    fn test_basic_model() {
        let m = Model::from_file("examples/basic_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert!(e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert!(e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_basic_model_no_policy() {
        let m = Model::from_file("examples/basic_model.conf").unwrap();

        let adapter = MemoryAdapter::default();
        let e = Enforcer::new(m, adapter);

        assert!(!e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_basic_model_with_root() {
        let m = Model::from_file("examples/basic_with_root_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/basic_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert!(e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert!(e.enforce(vec!["bob", "data2", "write"]).unwrap());
        assert!(e.enforce(vec!["root", "data1", "read"]).unwrap());
        assert!(e.enforce(vec!["root", "data1", "write"]).unwrap());
        assert!(e.enforce(vec!["root", "data2", "read"]).unwrap());
        assert!(e.enforce(vec!["root", "data2", "write"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data2", "read"]).unwrap());
    }

    #[test]
    fn test_basic_model_with_root_no_policy() {
        let m = Model::from_file("examples/basic_with_root_model.conf").unwrap();

        let adapter = MemoryAdapter::default();
        let e = Enforcer::new(m, adapter);

        assert!(!e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data2", "write"]).unwrap());
        assert!(e.enforce(vec!["root", "data1", "read"]).unwrap());
        assert!(e.enforce(vec!["root", "data1", "write"]).unwrap());
        assert!(e.enforce(vec!["root", "data2", "read"]).unwrap());
        assert!(e.enforce(vec!["root", "data2", "write"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert!(!e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "data2", "read"]).unwrap());
    }

    #[test]
    fn test_basic_model_without_users() {
        let m = Model::from_file("examples/basic_without_users_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/basic_without_users_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert!(e.enforce(vec!["data1", "read"]).unwrap());
        assert!(!e.enforce(vec!["data1", "write"]).unwrap());
        assert!(!e.enforce(vec!["data2", "read"]).unwrap());
        assert!(e.enforce(vec!["data2", "write"]).unwrap());
    }

    #[test]
    fn test_basic_model_without_resources() {
        let m = Model::from_file("examples/basic_without_resources_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/basic_without_resources_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert!(e.enforce(vec!["alice", "read"]).unwrap());
        assert!(e.enforce(vec!["bob", "write"]).unwrap());
        assert!(!e.enforce(vec!["alice", "write"]).unwrap());
        assert!(!e.enforce(vec!["bob", "read"]).unwrap());
    }

    #[test]
    fn test_rbac_model() {
        let m = Model::from_file("examples/rbac_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_rbac_model_with_resource_roles() {
        let m = Model::from_file("examples/rbac_with_resource_roles_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_resource_roles_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_rbac_model_with_domains() {
        let m = Model::from_file("examples/rbac_with_domains_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(
            true,
            e.enforce(vec!["alice", "domain1", "data1", "read"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["alice", "domain1", "data1", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "read"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "read"]).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "write"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "read"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "write"]).unwrap()
        );
    }

    use crate::MgmtApi;
    #[test]
    fn test_rbac_model_with_domains_at_runtime() {
        let m = Model::from_file("examples/rbac_with_domains_model.conf").unwrap();

        let adapter = MemoryAdapter::default();
        let mut e = Enforcer::new(m, adapter);
        e.add_policy(vec!["admin", "domain1", "data1", "read"])
            .unwrap();
        e.add_policy(vec!["admin", "domain1", "data1", "write"])
            .unwrap();
        e.add_policy(vec!["admin", "domain2", "data2", "read"])
            .unwrap();
        e.add_policy(vec!["admin", "domain2", "data2", "write"])
            .unwrap();

        e.add_grouping_policy(vec!["alice", "admin", "domain1"])
            .unwrap();
        e.add_grouping_policy(vec!["bob", "admin", "domain2"])
            .unwrap();

        assert_eq!(
            true,
            e.enforce(vec!["alice", "domain1", "data1", "read"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["alice", "domain1", "data1", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "read"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "read"]).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "write"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "read"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "write"]).unwrap()
        );

        e.remove_filtered_policy(1, vec!["domain1", "data1"])
            .unwrap();

        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data1", "read"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data1", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "read"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "read"]).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "write"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "read"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "write"]).unwrap()
        );

        e.remove_policy(vec!["admin", "domain2", "data2", "read"])
            .unwrap();

        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data1", "read"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data1", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "read"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data2", "write"])
                .unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "read"]).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data1", "write"]).unwrap()
        );
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data2", "read"]).unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "write"]).unwrap()
        );
    }

    #[test]
    fn test_rbac_model_with_domains_at_runtime_mock_adapter() {
        let m = Model::from_file("examples/rbac_with_domains_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv");
        let mut e = Enforcer::new(m, adapter);

        e.add_policy(vec!["admin", "domain3", "data1", "read"])
            .unwrap();
        e.add_grouping_policy(vec!["alice", "admin", "domain3"])
            .unwrap();

        assert_eq!(
            true,
            e.enforce(vec!["alice", "domain3", "data1", "read"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["alice", "domain1", "data1", "read"])
                .unwrap()
        );

        e.remove_filtered_policy(1, vec!["domain1", "data1"])
            .unwrap();
        assert_eq!(
            false,
            e.enforce(vec!["alice", "domain1", "data1", "read"])
                .unwrap()
        );
        assert_eq!(
            true,
            e.enforce(vec!["bob", "domain2", "data2", "read"]).unwrap()
        );

        e.remove_policy(vec!["admin", "domain2", "data2", "read"])
            .unwrap();
        assert_eq!(
            false,
            e.enforce(vec!["bob", "domain2", "data2", "read"]).unwrap()
        );
    }

    #[test]
    fn test_rbac_model_with_deny() {
        let m = Model::from_file("examples/rbac_with_deny_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_rbac_model_with_not_deny() {
        let m = Model::from_file("examples/rbac_with_not_deny_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(false, e.enforce(vec!["alice", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_rbac_model_with_custom_data() {
        let m = Model::from_file("examples/rbac_model.conf").unwrap();

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let mut e = Enforcer::new(m, adapter);

        e.add_grouping_policy(vec!["bob", "data2_admin", "custom_data"])
            .unwrap();

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());

        e.remove_grouping_policy(vec!["bob", "data2_admin", "custom_data"])
            .unwrap();

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data1", "write"]).unwrap());
        assert_eq!(false, e.enforce(vec!["bob", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
    }

    #[test]
    fn test_rbac_model_using_in_op() {
        let m = Model::from_file("examples/rbac_model_matcher_using_in_op.conf").unwrap();
        println!("{}", m.model.get("m").unwrap().get("m").unwrap().value);

        let adapter = FileAdapter::new("examples/rbac_policy.csv");
        let e = Enforcer::new(m, adapter);

        assert_eq!(true, e.enforce(vec!["alice", "data1", "read"]).unwrap());
        assert_eq!(false, e.enforce(vec!["alice", "data1", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data2", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "write"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["guest", "data2", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["alice", "data3", "read"]).unwrap());
        assert_eq!(true, e.enforce(vec!["bob", "data3", "read"]).unwrap());
    }
}
