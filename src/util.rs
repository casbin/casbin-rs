use lazy_static::lazy_static;
use regex::Regex;
use std::borrow::Cow;

lazy_static! {
    static ref ESC_A: Regex = Regex::new(r"\b(r\d*|p\d*)\.").unwrap();
    static ref ESC_G: Regex =
        Regex::new(r"\b(g\d*)\(((?:\s*[r|p]\d*\.\w+\s*,\s*){1,2}\s*[r|p]\d*\.\w+\s*)\)").unwrap();
    pub(crate) static ref ESC_E: Regex = Regex::new(r"\beval\(([^)]*)\)").unwrap();
}

pub fn escape_assertion(s: String) -> String {
    ESC_A.replace_all(&s, "${1}_").to_string()
}

pub fn remove_comments(mut s: String) -> String {
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }

    s.trim_end().to_owned()
}

pub fn escape_eval(m: &str) -> Cow<str> {
    ESC_E.replace_all(m, "eval(escape_assertion(${1}))")
}

#[cfg(test)]
mod tests {
    use super::*;

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
