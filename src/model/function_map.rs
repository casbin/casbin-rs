use async_std::net::IpAddr;
use ip_network::IpNetwork;
use regex::Regex;
use rhai::Any;

use std::collections::HashMap;

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
                _ => panic!("invalid netmask {}", key2_split[1]),
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
