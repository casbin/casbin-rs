#[cfg(all(feature = "runtime-async-std", feature = "ip"))]
use async_std::net::IpAddr;

#[cfg(all(feature = "runtime-tokio", feature = "ip"))]
use std::net::IpAddr;

#[cfg(feature = "glob")]
use globset::GlobBuilder;
#[cfg(feature = "ip")]
use ip_network::IpNetwork;
use once_cell::sync::Lazy;
use regex::Regex;
use rhai::{Dynamic, ImmutableString};

static MAT_B: Lazy<Regex> = Lazy::new(|| Regex::new(r":[^/]*").unwrap());
static MAT_P: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{[^/]*\}").unwrap());

use std::any::Any;
use std::{borrow::Cow, collections::HashMap};

pub struct FunctionMap {
    pub(crate) fm: HashMap<String, fn(&[ImmutableString]) -> Dynamic>,
}

impl Default for FunctionMap {
    fn default() -> FunctionMap {
        let mut fm: HashMap<String, fn(&[ImmutableString]) -> Dynamic> =
            HashMap::new();
        fm.insert("keyMatch".to_owned(), |args: &[ImmutableString]| {
            key_match(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });
        fm.insert("keyGet".to_owned(), |args: &[ImmutableString]| {
            key_get(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });
        fm.insert("keyMatch2".to_owned(), |args: &[ImmutableString]| {
            key_match2(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });
        fm.insert("keyGet2".to_owned(), |args: &[ImmutableString]| {
            key_get2(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
                args.get(2).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });
        fm.insert("keyMatch3".to_owned(), |args: &[ImmutableString]| {
            key_match3(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });
        fm.insert("keyGet3".to_owned(), |args: &[ImmutableString]| {
            key_get3(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
                args.get(2).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });
        fm.insert("regexMatch".to_owned(), |args: &[ImmutableString]| {
            regex_match(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });

        #[cfg(feature = "glob")]
        fm.insert("globMatch".to_owned(), |args: &[ImmutableString]| {
            glob_match(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });

        #[cfg(feature = "ip")]
        fm.insert("ipMatch".to_owned(), |args: &[ImmutableString]| {
            ip_match(
                args.get(0).unwrap_or(&ImmutableString::from("")),
                args.get(1).unwrap_or(&ImmutableString::from("")),
            )
            .into()
        });

        FunctionMap { fm }
    }
}

impl FunctionMap {
    #[inline]
    pub fn add_function(
        &mut self,
        fname: &str,
        f: fn(&[ImmutableString]) -> Dynamic,
    ) {
        self.fm.insert(fname.to_owned(), f);
    }

    #[inline]
    pub fn get_functions(
        &self,
    ) -> impl Iterator<Item = (&String, &fn(&[ImmutableString]) -> Dynamic)>
    {
        self.fm.iter()
    }
}

// key_match determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain *
// For example, "/foo/bar" matches "/foo/*"
pub fn key_match(key1: &str, key2: &str) -> bool {
    if let Some(i) = key2.find('*') {
        if key1.len() > i {
            return key1[..i] == key2[..i];
        }
        key1[..] == key2[..i]
    } else {
        key1 == key2
    }
}

// key_get returns the matched part
// For example, "/foo/bar/foo" matches "/foo/*"
// "bar/foo" will be returned.
pub fn key_get(key1: &str, key2: &str) -> String {
    if let Some(i) = key2.find('*') {
        if key1.len() > i {
            if key1[..i] == key2[..i] {
                return key1[i..].to_string();
            }
        }
    }
    "".to_string()
}

// key_match2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
pub fn key_match2(key1: &str, key2: &str) -> bool {
    let mut key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    key2 = MAT_B.replace_all(&key2, "[^/]+").to_string().into();

    regex_match(key1, &format!("^{}$", key2))
}

// key_get2 returns value matched pattern
// For example, "/resource1" matches "/:resource"
// if the pathVar == "resource", then "resource1" will be returned.
pub fn key_get2(key1: &str, key2: &str, path_var: &str) -> String {
    let key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    let re = Regex::new(r":[^/]+").unwrap();
    let keys: Vec<_> = re.find_iter(&key2).collect();
    let key2 = re.replace_all(&key2, "([^/]+)").to_string();
    let key2 = format!("^{}$", key2);

    if let Ok(re2) = Regex::new(&key2) {
        if let Some(caps) = re2.captures(key1) {
            for (i, key) in keys.iter().enumerate() {
                if path_var == &key.as_str()[1..] {
                    return caps
                        .get(i + 1)
                        .map_or("".to_string(), |m| m.as_str().to_string());
                }
            }
        }
    }
    "".to_string()
}

// key_match3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
pub fn key_match3(key1: &str, key2: &str) -> bool {
    let mut key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    key2 = MAT_P.replace_all(&key2, "[^/]+").to_string().into();

    regex_match(key1, &format!("^{}$", key2))
}

// key_get3 returns value matched pattern
// For example, "project/proj_project1_admin/" matches "project/proj_{project}_admin/"
// if the pathVar == "project", then "project1" will be returned.
pub fn key_get3(key1: &str, key2: &str, path_var: &str) -> String {
    let key2: Cow<str> = if key2.contains("/*") {
        key2.replace("/*", "/.*").into()
    } else {
        key2.into()
    };

    let re = Regex::new(r"\{[^/]+?\}").unwrap();
    let keys: Vec<_> = re.find_iter(&key2).collect();
    let key2 = re.replace_all(&key2, "([^/]+?)").to_string();
    let key2 = Regex::new(r"\{")
        .unwrap()
        .replace_all(&key2, "\\{")
        .to_string();
    let key2 = format!("^{}$", key2);

    let re2 = Regex::new(&key2).unwrap();
    if let Some(caps) = re2.captures(key1) {
        for (i, key) in keys.iter().enumerate() {
            if path_var == &key.as_str()[1..key.as_str().len() - 1] {
                return caps
                    .get(i + 1)
                    .map_or("".to_string(), |m| m.as_str().to_string());
            }
        }
    }
    "".to_string()
}

// regex_match determines whether key1 matches the pattern of key2 in regular expression.
pub fn regex_match(key1: &str, key2: &str) -> bool {
    Regex::new(key2).unwrap().is_match(key1)
}

// ip_match determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
#[cfg(feature = "ip")]
pub fn ip_match(key1: &str, key2: &str) -> bool {
    let key2_split = key2.splitn(2, '/').collect::<Vec<&str>>();
    let ip_addr2 = key2_split[0];

    if let (Ok(ip_addr1), Ok(ip_addr2)) =
        (key1.parse::<IpAddr>(), ip_addr2.parse::<IpAddr>())
    {
        if key2_split.len() == 2 {
            match key2_split[1].parse::<u8>() {
                Ok(ip_netmask) => {
                    match IpNetwork::new_truncate(ip_addr2, ip_netmask) {
                        Ok(ip_network) => ip_network.contains(ip_addr1),
                        Err(err) => panic!("invalid ip network {}", err),
                    }
                }
                _ => panic!("invalid netmask {}", key2_split[1]),
            }
        } else {
            if let (IpAddr::V4(ip_addr1_new), IpAddr::V6(ip_addr2_new)) =
                (ip_addr1, ip_addr2)
            {
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

// glob_match determines whether key1 matches the pattern of key2 using glob pattern
#[cfg(feature = "glob")]
pub fn glob_match(key1: &str, key2: &str) -> bool {
    GlobBuilder::new(key2)
        .literal_separator(true)
        .build()
        .unwrap()
        .compile_matcher()
        .is_match(key1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_match() {
        assert!(key_match("/foo/bar", "/foo/*"));
        assert!(!key_match("/bar/foo", "/foo/*"));
        assert!(key_match("/bar", "/ba*"));
    }

    #[test]
    fn test_key_get() {
        assert_eq!(key_get("/foo", "/foo"), "");
        assert_eq!(key_get("/foo", "/foo*"), "");
        assert_eq!(key_get("/foo", "/foo/*"), "");
        assert_eq!(key_get("/foo/bar", "/foo"), "");
        assert_eq!(key_get("/foo/bar", "/foo*"), "/bar");
        assert_eq!(key_get("/foo/bar", "/foo/*"), "bar");
        assert_eq!(key_get("/foobar", "/foo"), "");
        assert_eq!(key_get("/foobar", "/foo*"), "bar");
        assert_eq!(key_get("/foobar", "/foo/*"), "");
    }

    #[test]
    fn test_key_match2() {
        assert!(key_match2("/foo/bar", "/foo/*"));
        assert!(key_match2("/foo/bar/baz", "/foo/*"));
        assert!(key_match2("/foo/baz", "/foo/:bar"));
        assert!(key_match2("/foo/baz", "/:foo/:bar"));
        assert!(key_match2("/foo/baz/foo", "/foo/:bar/foo"));
        assert!(!key_match2("/baz", "/foo"));

        // GH Issue #282
        assert!(key_match2("/foo/bar", "/foo/:"));
        assert!(!key_match2("/foo/bar/baz", "/foo/:"));
        assert!(key_match2("/foo/bar/baz", "/foo/:/baz"));
        assert!(!key_match2("/foo/bar", "/foo/:/baz"));
    }

    #[test]
    fn test_key_get2() {
        assert_eq!(key_get2("/foo", "/foo", "id"), "");
        assert_eq!(key_get2("/foo", "/foo*", "id"), "");
        assert_eq!(key_get2("/foo", "/foo/*", "id"), "");
        assert_eq!(key_get2("/foo/bar", "/foo", "id"), "");
        assert_eq!(key_get2("/foo/bar", "/foo*", "id"), "");
        assert_eq!(key_get2("/foo/bar", "/foo/*", "id"), "");
        assert_eq!(key_get2("/foobar", "/foo", "id"), "");
        assert_eq!(key_get2("/foobar", "/foo*", "id"), "");
        assert_eq!(key_get2("/foobar", "/foo/*", "id"), "");

        assert_eq!(key_get2("/", "/:resource", "resource"), "");
        assert_eq!(
            key_get2("/resource1", "/:resource", "resource"),
            "resource1"
        );
        assert_eq!(key_get2("/myid", "/:id/using/:resId", "id"), "");
        assert_eq!(
            key_get2("/myid/using/myresid", "/:id/using/:resId", "id"),
            "myid"
        );
        assert_eq!(
            key_get2("/myid/using/myresid", "/:id/using/:resId", "resId"),
            "myresid"
        );

        assert_eq!(key_get2("/proxy/myid", "/proxy/:id/*", "id"), "");
        assert_eq!(key_get2("/proxy/myid/", "/proxy/:id/*", "id"), "myid");
        assert_eq!(key_get2("/proxy/myid/res", "/proxy/:id/*", "id"), "myid");
        assert_eq!(
            key_get2("/proxy/myid/res/res2", "/proxy/:id/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get2("/proxy/myid/res/res2/res3", "/proxy/:id/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get2("/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id"),
            "myid"
        );
        assert_eq!(key_get2("/proxy/", "/proxy/:id/*", "id"), "");

        assert_eq!(key_get2("/alice", "/:id", "id"), "alice");
        assert_eq!(key_get2("/alice/all", "/:id/all", "id"), "alice");
        assert_eq!(key_get2("/alice", "/:id/all", "id"), "");
        assert_eq!(key_get2("/alice/all", "/:id", "id"), "");

        assert_eq!(key_get2("/alice/all", "/:/all", ""), "");
    }

    #[test]
    fn test_regex_match() {
        assert!(regex_match("foobar", "^foo*"));
        assert!(!regex_match("barfoo", "^foo*"));
    }

    #[test]
    fn test_key_match3() {
        assert!(key_match3("/foo/bar", "/foo/*"));
        assert!(key_match3("/foo/bar/baz", "/foo/*"));
        assert!(key_match3("/foo/baz", "/foo/{bar}"));
        assert!(key_match3("/foo/baz/foo", "/foo/{bar}/foo"));
        assert!(!key_match3("/baz", "/foo"));

        // GH Issue #282
        assert!(key_match3("/foo/bar", "/foo/{}"));
        assert!(key_match3("/foo/{}", "/foo/{}"));
        assert!(!key_match3("/foo/bar/baz", "/foo/{}"));
        assert!(!key_match3("/foo/bar", "/foo/{}/baz"));
        assert!(key_match3("/foo/bar/baz", "/foo/{}/baz"));
    }

    #[test]
    fn test_key_get3() {
        assert_eq!(key_get3("/foo", "/foo", "id"), "");
        assert_eq!(key_get3("/foo", "/foo*", "id"), "");
        assert_eq!(key_get3("/foo", "/foo/*", "id"), "");
        assert_eq!(key_get3("/foo/bar", "/foo", "id"), "");
        assert_eq!(key_get3("/foo/bar", "/foo*", "id"), "");
        assert_eq!(key_get3("/foo/bar", "/foo/*", "id"), "");
        assert_eq!(key_get3("/foobar", "/foo", "id"), "");
        assert_eq!(key_get3("/foobar", "/foo*", "id"), "");
        assert_eq!(key_get3("/foobar", "/foo/*", "id"), "");

        assert_eq!(key_get3("/", "/{resource}", "resource"), "");
        assert_eq!(
            key_get3("/resource1", "/{resource}", "resource"),
            "resource1"
        );
        assert_eq!(key_get3("/myid", "/{id}/using/{resId}", "id"), "");
        assert_eq!(
            key_get3("/myid/using/myresid", "/{id}/using/{resId}", "id"),
            "myid"
        );
        assert_eq!(
            key_get3("/myid/using/myresid", "/{id}/using/{resId}", "resId"),
            "myresid"
        );

        assert_eq!(key_get3("/proxy/myid", "/proxy/{id}/*", "id"), "");
        assert_eq!(key_get3("/proxy/myid/", "/proxy/{id}/*", "id"), "myid");
        assert_eq!(key_get3("/proxy/myid/res", "/proxy/{id}/*", "id"), "myid");
        assert_eq!(
            key_get3("/proxy/myid/res/res2", "/proxy/{id}/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/*", "id"),
            "myid"
        );
        assert_eq!(
            key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/res/*", "id"),
            "myid"
        );
        assert_eq!(key_get3("/proxy/", "/proxy/{id}/*", "id"), "");

        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{proj}_admin/info",
                "proj"
            ),
            ""
        );
        assert_eq!(
            key_get3("/{id/using/myresid", "/{id/using/{resId}", "resId"),
            "myresid"
        );
        assert_eq!(
            key_get3(
                "/{id/using/myresid/status}",
                "/{id/using/{resId}/status}",
                "resId"
            ),
            "myresid"
        );

        assert_eq!(
            key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/*/{res}", "res"),
            "res3"
        );
        assert_eq!(
            key_get3(
                "/api/project1_admin/info",
                "/api/{proj}_admin/info",
                "proj"
            ),
            "project1"
        );
        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{g}_{gn}/{proj}_admin/info",
                "g"
            ),
            "group1"
        );
        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{g}_{gn}/{proj}_admin/info",
                "gn"
            ),
            "group_name"
        );
        assert_eq!(
            key_get3(
                "/api/group1_group_name/project1_admin/info",
                "/api/{g}_{gn}/{proj}_admin/info",
                "proj"
            ),
            "project1"
        );
    }

    #[cfg(feature = "ip")]
    #[test]
    fn test_ip_match() {
        assert!(ip_match("::1", "::0:1"));
        assert!(ip_match("192.168.1.1", "192.168.1.1"));
        assert!(ip_match("127.0.0.1", "::ffff:127.0.0.1"));
        assert!(ip_match("192.168.2.123", "192.168.2.0/24"));
        assert!(!ip_match("::1", "127.0.0.2"));
        assert!(!ip_match("192.168.2.189", "192.168.1.134/26"));
    }

    #[cfg(feature = "ip")]
    #[test]
    #[should_panic]
    fn test_ip_match_panic_1() {
        assert!(ip_match("I am alice", "127.0.0.1"));
    }

    #[cfg(feature = "ip")]
    #[test]
    #[should_panic]
    fn test_ip_match_panic_2() {
        assert!(ip_match("127.0.0.1", "I am alice"));
    }

    #[cfg(feature = "glob")]
    #[test]
    fn test_glob_match() {
        assert!(glob_match("/abc/123", "/abc/*"));
        assert!(!glob_match("/abc/123/456", "/abc/*"));
        assert!(glob_match("/abc/123/456", "/abc/**"));
    }
}
