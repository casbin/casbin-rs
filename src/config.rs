use std::collections::HashMap;

use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Cursor};

const DEFAULT_SECTION: &str = "default";
const DEFAULT_COMMENT: &str = "#";
const DEFAULT_COMMENT_SEM: &str = ";";
const DEFAULT_MULTI_LINE_SEPARATOR: &str = "\\";

pub struct Config {
    pub data: HashMap<String, HashMap<String, String>>,
}

impl Config {
    pub fn new(path: &str) -> Self {
        let mut c = Config {
            data: HashMap::new(),
        };
        c.parse(path);
        return c;
    }

    pub fn from_text(text: &str) -> Self {
        let mut c = Config {
            data: HashMap::new(),
        };

        c.parse_buffer(&mut BufReader::new(Cursor::new(text.as_bytes())));
        return c;
    }

    fn parse(&mut self, path: &str) {
        let mut f = File::open(path).expect("read config failed");
        let mut c = Vec::new();
        f.read_to_end(&mut c).expect("error while reading config");

        let mut reader: BufReader<Cursor<&[u8]>> = BufReader::new(Cursor::new(&c));
        self.parse_buffer(&mut reader);
    }

    fn parse_buffer(&mut self, reader: &mut BufReader<Cursor<&[u8]>>) {
        let mut section = String::new();

        loop {
            let mut line = String::new();
            let bytes = reader
                .read_line(&mut line)
                .expect("read config line failed");
            if bytes == 0 {
                // EOF reached
                break;
            }
            line = line.trim().to_string();
            if line.is_empty()
                || line.starts_with(DEFAULT_COMMENT)
                || line.starts_with(DEFAULT_COMMENT_SEM)
            {
                continue;
            } else if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_string();
            } else {
                let option_val: Vec<String> =
                    line.splitn(2, '=').map(|e| e.trim().to_string()).collect();
                if option_val.len() != 2 {
                    panic!("parse content error, line={}", line);
                }
                self.add_config(
                    section.clone(),
                    option_val[0].clone(),
                    option_val[1].clone(),
                );
            }
        }
    }

    pub fn add_config(&mut self, section: String, option: String, value: String) {
        let mut section = section;
        if section.is_empty() {
            section = DEFAULT_SECTION.to_owned();
        }
        let section_value = self.data.entry(section).or_insert(HashMap::new());
        // if key not exists then insert, else update
        let key_value = section_value.get_mut(&option);
        match key_value {
            Some(old_value) => {
                *old_value = value;
            }
            None => {
                section_value.insert(option, value);
            }
        }
    }

    pub fn get(&self, key: &str) -> String {
        let keys: Vec<String> = key.to_lowercase().split("::").map(String::from).collect();
        if keys.len() >= 2 {
            let section = keys[0].clone();
            let option = keys[1].clone();
            return self
                .data
                .get(&section)
                .unwrap()
                .get(&option)
                .unwrap()
                .clone();
        } else {
            let section = DEFAULT_SECTION.to_owned();
            let option = keys[0].clone();
            return self
                .data
                .get(&section)
                .unwrap()
                .get(&option)
                .unwrap()
                .clone();
        }
    }

    pub fn set(&mut self, key: &str, value: &str) {
        if key.is_empty() {
            panic!("key can't be empty");
        }
        let keys: Vec<String> = key.to_lowercase().split("::").map(String::from).collect();
        if keys.len() >= 2 {
            let section = keys[0].clone();
            let option = keys[1].clone();
            self.add_config(section, option, value.to_owned());
        } else {
            let section = DEFAULT_SECTION.to_owned();
            let option = keys[0].clone();
            self.add_config(section, option, value.to_owned());
        }
    }

    pub fn get_bool(&self, key: &str) -> bool {
        return self.get(key).parse::<bool>().unwrap();
    }

    pub fn get_string(&self, key: &str) -> String {
        return self.get(key);
    }

    pub fn get_int(&self, key: &str) -> i64 {
        return self.get(key).parse::<i64>().unwrap();
    }

    pub fn get_float(&self, key: &str) -> f64 {
        return self.get(key).parse::<f64>().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get() {
        let mut config = Config::new("examples/testini.ini");

        assert_eq!(true, config.get_bool("debug"));
        assert_eq!(64, config.get_int("math::math.i64"));
        assert_eq!(64.1, config.get_float("math::math.f64"));
        assert_eq!("10.0.0.1", config.get_string("mysql::mysql.master.host"));

        config.set("other::key1", "new test key");
        assert_eq!("new test key", config.get_string("other::key1"));

        config.set("other::key1", "test key");
        assert_eq!("test key", config.get_string("other::key1"));
    }

    #[test]
    fn test_from_text() {
        let text: &str = r#"
            # test config
            debug = true
            url = act.wiki

            ; redis config
            [redis]
            redis.key = push1,push2

            ; mysql config
            [mysql]
            mysql.dev.host = 127.0.0.1
            mysql.dev.user = root
            mysql.dev.pass = 123456
            mysql.dev.db = test

            mysql.master.host = 10.0.0.1
            mysql.master.user = root
            mysql.master.pass = 89dds)2$#d
            mysql.master.db = act

            ; math config
            [math]
            math.i64 = 64
            math.f64 = 64.1
        "#;

        let mut config = Config::from_text(text);

        assert_eq!(true, config.get_bool("debug"));
        assert_eq!(64, config.get_int("math::math.i64"));
        assert_eq!(64.1, config.get_float("math::math.f64"));
        assert_eq!("10.0.0.1", config.get_string("mysql::mysql.master.host"));

        config.set("other::key1", "new test key");
        assert_eq!("new test key", config.get_string("other::key1"));

        config.set("other::key1", "test key");
        assert_eq!("test key", config.get_string("other::key1"));
    }
}
