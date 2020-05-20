use lazy_static::lazy_static;
use regex::Regex;
use std::borrow::Cow;

lazy_static! {
    static ref ESC_A: Regex = Regex::new(r"\b(r\d*|p\d*)\.").unwrap();
    static ref ESC_G: Regex =
        Regex::new(r"\b(g\d*)\(((?:\s*[r|p]\d*\.\w+\s*,\s*){1,2}\s*[r|p]\d*\.\w+\s*)\)").unwrap();
    pub(crate) static ref ESC_E: Regex = Regex::new(r"\beval\((?P<rule>[^)]*)\)").unwrap();
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

pub fn escape_eval<'a>(m: &'a str) -> Cow<'a, str> {
    let mut cm: Cow<str> = m.into();
    for caps in ESC_E.captures_iter(&m) {
        cm = ESC_E
            .replace(
                &cm,
                format!("eval(escape_assertion({}))", &caps["rule"]).as_str(),
            )
            .to_string()
            .into();
    }
    cm
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

        let s3 = "g3(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act";
        let exp3 = "g3([r2.sub, p2.sub]) && r2.obj == p2.obj && r2.act == p2.act";

        assert_eq!(exp3, escape_g_function(s3.to_owned()));
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

        let s1 = "g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act";
        let exp1 = "g(r2_sub, p2_sub) && r2_obj == p2_obj && r2_act == p2_act";

        assert_eq!(exp1, escape_assertion(s1.to_owned()));
    }
}
