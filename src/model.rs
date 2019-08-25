use crate::config::Config;
use crate::errors::CasbinError;
use crate::rbac::{DefaultRoleManager, RoleManager};
use crate::Result;

use ip_network::IpNetwork;
use regex::Regex;

use std::collections::HashMap;
use std::net::IpAddr;

fn escape_assertion(s: String) -> String {
    let mut s = s;
    // TODO: should replace . using regex
    s = s.replacen(".", "_", 100);
    s
}

type AssertionMap = HashMap<String, Assertion>;

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
        for (_k, rule) in self.policy.iter().enumerate() {
            if count < 2 {
                return Err(CasbinError::new(
                    "the number of \"_\" in role definition should be at least 2",
                )
                .into());
            }
            if rule.len() < count {
                return Err(CasbinError::new(
                    "grouping policy elements do not meet role definition",
                )
                .into());
            }
            if count == 2 {
                rm.add_link(&rule[0], &rule[1], None);
            } else if count == 3 {
                rm.add_link(&rule[0], &rule[1], Some(&rule[2]));
            } else if count >= 4 {
                return Err(CasbinError::new("domain can at most contains 1 string").into());
            }
        }
        self.rm = rm.clone();
        // self.rm.print_roles();
        Ok(())
    }
}

#[derive(Clone)]
pub struct Model {
    pub model: HashMap<String, AssertionMap>,
}

impl Model {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Model {
            model: HashMap::new(),
        }
    }

    fn get_key_suffix(&self, i: u64) -> String {
        if i == 1 {
            "".to_owned()
        } else {
            i.to_string()
        }
    }

    fn load_assersion(&mut self, cfg: &Config, sec: &str, key: &str) -> bool {
        let sec_name = match sec {
            "r" => "request_definition",
            "p" => "policy_definition",
            "g" => "role_definition",
            "e" => "policy_effect",
            "m" => "matchers",
            _ => panic!("section is not one of [r,p,g,e,m] {}", sec),
        };

        if let Some(val) = cfg.get_str(&format!("{}::{}", sec_name, key)) {
            self.add_def(sec, key, val)
        } else {
            false
        }
    }

    fn load_section(&mut self, cfg: &Config, sec: &str) {
        let mut i = 1;

        loop {
            if !self.load_assersion(cfg, sec, &format!("{}{}", sec, self.get_key_suffix(i))) {
                break;
            } else {
                i += 1;
            }
        }
    }

    pub fn load_model(&mut self, path: &str) {
        let cfg = Config::new(path);

        self.load_section(&cfg, "r");
        self.load_section(&cfg, "p");
        self.load_section(&cfg, "e");
        self.load_section(&cfg, "m");

        self.load_section(&cfg, "g");
    }

    pub fn load_model_from_text(&mut self, text: &str) {
        let cfg = Config::from_text(text);

        self.load_section(&cfg, "r");
        self.load_section(&cfg, "p");
        self.load_section(&cfg, "e");
        self.load_section(&cfg, "m");

        self.load_section(&cfg, "g");
    }

    pub fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool {
        let mut ast = Assertion::new();
        ast.key = key.to_owned();
        ast.value = value.to_owned();

        if ast.value == "" {
            return false;
        }

        if sec == "r" || sec == "p" {
            ast.tokens = ast
                .value
                .split(", ")
                .map(|x| format!("{}_{}", key, x))
                .collect();
        } else {
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

pub type FunctionMap = HashMap<String, fn(String, String) -> bool>;

pub fn load_function_map() -> FunctionMap {
    let mut fm: HashMap<String, fn(String, String) -> bool> = HashMap::new();
    fm.insert("keyMatch".to_owned(), key_match);
    fm.insert("keyMatch2".to_owned(), key_match2);
    fm.insert("keyMatch3".to_owned(), key_match3);
    fm.insert("regexMatch".to_owned(), regex_match);
    fm.insert("ipMatch".to_owned(), ip_match);
    fm
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
}
