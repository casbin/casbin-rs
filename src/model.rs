use crate::rbac::{DefaultRoleManager, RoleManager};
use crate::config::{Config};
use regex::Regex;
use std::collections::HashMap;

fn escape_assertion(s: String) -> String {
    let mut s = s;
    // TODO: should replace . using regex
    s = s.replacen(".", "_", 100);
    return s;
}

type AssertionMap = HashMap<String, Assertion>;

pub struct Assertion {
    pub key: String,
    pub value: String,
    pub tokens: Vec<String>,
    pub policy: Vec<Vec<String>>,
    pub rm: Box<dyn RoleManager>,
}

impl Assertion {
    pub fn new() -> Self {
        return Assertion {
            key: String::new(),
            value: String::new(),
            tokens: vec![],
            policy: vec![],
            rm: Box::new(DefaultRoleManager::new(0)),
        };
    }

    pub fn build_role_links(&mut self, rm: &mut Box<dyn RoleManager>) {
        let count = self.value.chars().filter(|&c| c == '_').count();
        for (_k, rule) in self.policy.iter().enumerate() {
            if count < 2 {
                panic!("the number of \"_\" in role definition should be at least 2")
            }
            if rule.len() < count {
                panic!("grouping policy elements do not meet role definition")
            }
            if count == 2 {
                rm.add_link(&rule[0], &rule[1], vec![]);
            } else if count == 3 {
                rm.add_link(&rule[0], &rule[1], vec![&rule[2]]);
            } else if count == 4 {
                rm.add_link(&rule[0], &rule[1], vec![&rule[2], &rule[3]]);
            }
        }
        self.rm = rm.clone();
        // self.rm.print_roles();
    }
}

pub struct Model {
    pub model: HashMap<String, AssertionMap>,
}

impl Model {
    pub fn new() -> Self {
        return Model {
            model: HashMap::new(),
        };
    }

    fn get_key_suffix(&self, i: u64) -> String  {
        if i == 1 { "".to_owned() } else { i.to_string() }
    }

    fn load_assersion(&mut self, cfg: &Config, sec: &str, key: &str) -> bool {
        let sec_name = match sec {
            "r" => "request_definition",
            "p" => "policy_definition",
            "g" => "role_definition",
            "e" => "policy_effect",
            "m" => "matchers",
            _ => panic!("section is not one of [r,p,g,e,m] {}", sec)
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
            ast.tokens = ast.value.split(", ").map(String::from).collect();
            for i in 0..ast.tokens.len() {
                ast.tokens[i] = format!("{}_{}", key.clone(), ast.tokens[i]);
            }
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

        return true;
    }

    pub fn build_role_links(&mut self, rm: &mut Box<dyn RoleManager>) {
        let asts = self.model.get_mut("g").unwrap();
        for (_key, ast) in asts.iter_mut() {
            ast.build_role_links(rm);
        }
    }

    pub fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        if let Some(t1) = self.model.get_mut(sec) {
            if let Some(t2) = t1.get_mut(ptype) {
                t2.policy.push(rule.into_iter().map(String::from).collect());
                return true;
            }
        }
        return false;
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
    return fm;
}

pub fn key_match(key1: String, key2: String) -> bool {
    if let Some(i) = key2.find("*") {
        if key1.len() > i {
            return &key1[..i] == &key2[..i];
        }
        return &key1[..] == &key2[..i];
    } else {
        return key1 == key2;
    }
}

fn key_match2(key1: String, key2: String) -> bool {
    let mut key2 = key2.replace("/*", "/.*");
    let re = Regex::new("(.*):[^/]+(.*)").unwrap();
    loop {
        if key2.contains("/:") {
            break;
        }
        key2 = re.replace_all(key2.as_str(), "$1[^/]+$2").to_string();
    }
    return regex_match(key1, format!("^{}$", key2));
}

// fn key_match3(key1: String, key2: String) -> bool {
//     let mut key2 = key2.replace("/*", "/.*");
//     let re = Regex::new(r"(.*)\{[^/]+\}(.*)").unwrap();
//     loop {
//         if key2.contains("/{") {
//             break;
//         }
//         key2 = re.replace_all(key2.as_str(), "$1[^/]+$2").to_string();
//     }
//     return regex_match(key1, format!("^{}$", key2));
// }

// fn key_match3_func(args: Vec<String>) -> bool {
//     let args = args.unwrap();
//     let name1 = args[0].clone();
//     let name2 = args[1].clone();
//     return key_match3(name1, name2);
// }

pub fn regex_match(key1: String, key2: String) -> bool {
    return Regex::new(key2.as_str()).unwrap().is_match(key1.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match() {
        assert_eq!(
            true,
            key_match(
                "/alice_data/resource1".to_owned(),
                "/alice_data/*".to_owned()
            )
        );
        assert_eq!(true, key_match("GET".to_owned(), "GET".to_owned()));
    }
}
