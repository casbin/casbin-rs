use lazy_static::lazy_static;
use regex::Regex;
use rhai::Scope;

lazy_static! {
    static ref ESC_A: Regex = Regex::new(r"(r|p)\.").unwrap();
    static ref ESC_G: Regex =
        Regex::new(r"(g\d*)\(((?:\s*[r|p]\.\w+\s*,\s*){1,2}\s*[r|p]\.\w+\s*)\)").unwrap();
    pub(crate) static ref ESC_E: Regex = Regex::new(r"eval\((?P<rule>[^)]*)\)").unwrap();
}

pub fn escape_assertion(s: String) -> String {
    ESC_A.replace_all(&s, "${1}_").to_string()
}

pub fn escape_g_function(s: String) -> String {
    ESC_G.replace_all(&s, "${1}([${2}])").to_string()
}

pub fn remove_comments(mut s: String) -> String {
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }

    s.trim_end().to_owned()
}

pub fn escape_eval(mut m: String, scope: &Scope) -> String {
    let cloned_m = m.to_owned();
    for caps in ESC_E.captures_iter(&cloned_m) {
        if let Some(val) = scope.get_value::<String>(&caps["rule"]) {
            m = ESC_E
                .replace(m.as_str(), escape_assertion(format!("({})", &val)).as_str())
                .to_string();
        } else {
            panic!("eval(*) must make sure * can be evaluated");
        }
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
}
