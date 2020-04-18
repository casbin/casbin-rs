use lazy_static::lazy_static;
use regex::Regex;

pub fn escape_assertion(s: String) -> String {
    lazy_static! {
        static ref ASSERT: Regex = Regex::new(r"(r|p)\.").unwrap();
    }
    ASSERT.replace_all(&s, "${1}_").to_string()
}

pub fn escape_g_function(s: String) -> String {
    lazy_static! {
        static ref ESC_G: Regex =
            Regex::new(r"(g\d*)\(((?:\s*[r|p]\.\w+\s*,\s*){1,2}\s*[r|p]\.\w+\s*)\)").unwrap();
    }
    ESC_G.replace_all(&s, "${1}([${2}])").to_string()
}

pub fn remove_comments(mut s: String) -> String {
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }

    s.trim().to_owned()
}

pub fn merge_abc_into_matcher(mut m: String, v: &str) -> String {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(.*)Any\(_\)(.*)").unwrap();
        static ref RE_M: Regex = Regex::new(r"Any\((?P<rule>[^),]*)\)").unwrap();
    }

    for caps in RE_M.captures_iter(v) {
        if !m.contains("Any(_)") {
            break;
        }
        m = RE
            .replace_all(
                m.as_str(),
                escape_assertion(format!("$1({})$2", &caps["rule"])).as_str(),
            )
            .to_string();
    }
    if m.contains("Any(_)") {
        panic!("abac placeholder in matcher doesn't match abac rule in policy");
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_remove_comments() {
        assert!(remove_comments("#".to_owned()).is_empty());
        assert_eq!(
            r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root""#,
            remove_comments(
                r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root" # root is the super user"#.to_owned()
            )
        );
    }

    #[test]
    fn test_escape_assertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act";

        assert_eq!(exp, escape_assertion(s.to_owned()));
    }

    #[test]
    fn test_merge_abac_into_matcher() {
        let m1 = r#"Any(_) && Any(_) && r_sub == "alice""#.to_owned();
        let v1 = r#"Any(r.sub.age >= 18), Any(r.obj.Owner == r.sub.name), (GET|POST)"#;

        assert_eq!(
            merge_abc_into_matcher(m1, v1),
            r#"(r_obj.Owner == r_sub.name) && (r_sub.age >= 18) && r_sub == "alice""#
        );
    }

    #[test]
    #[should_panic]
    fn test_merge_abac_into_matcher_panic() {
        let m1 = r#"Any(_) && Any(_) && r.sub == "alice""#.to_owned();
        let v1 = r#"Any(r.sub.age >= 18), /data1, (GET|POST)"#;

        assert_eq!(
            merge_abc_into_matcher(m1, v1),
            r#"(r_sub.age >= 18) && r_sub == "alice""#
        );
    }
}
