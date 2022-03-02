use once_cell::sync::Lazy;
use regex::Regex;

use std::borrow::Cow;

macro_rules! regex {
    ($re:expr) => {
        ::regex::Regex::new($re).unwrap()
    };
}

static ESC_A: Lazy<Regex> = Lazy::new(|| regex!(r"\b(r\d*|p\d*)\."));
#[allow(dead_code)]
static ESC_G: Lazy<Regex> = Lazy::new(|| {
    regex!(r"\b(g\d*)\(((?:\s*[r|p]\d*\.\w+\s*,\s*){1,2}\s*[r|p]\d*\.\w+\s*)\)")
});
static ESC_C: Lazy<Regex> = Lazy::new(|| regex!(r#"(\s*"[^"]*"?|\s*[^,]*)"#));
pub(crate) static ESC_E: Lazy<Regex> =
    Lazy::new(|| regex!(r"\beval\(([^)]*)\)"));

pub fn escape_assertion(s: &str) -> String {
    ESC_A.replace_all(s, "${1}_").to_string()
}

pub fn remove_comment(s: &str) -> String {
    let s = if let Some(idx) = s.find('#') {
        &s[..idx]
    } else {
        s
    };

    s.trim_end().to_owned()
}

pub fn escape_eval(m: &str) -> Cow<str> {
    ESC_E.replace_all(m, "eval(escape_assertion(${1}))")
}

pub fn parse_csv_line<S: AsRef<str>>(line: S) -> Option<Vec<String>> {
    let line = line.as_ref().trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut res = vec![];
    for col in ESC_C.find_iter(line).map(|m| m.as_str().trim()) {
        res.push({
            if col.len() >= 2 && col.starts_with('"') && col.ends_with('"') {
                col[1..col.len() - 1].to_owned()
            } else {
                col.to_owned()
            }
        })
    }
    if res.is_empty() {
        None
    } else {
        Some(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_comment() {
        assert!(remove_comment("#").is_empty());
        assert_eq!(
            r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root""#,
            remove_comment(
                r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root" # root is the super user"#
            )
        );
    }

    #[test]
    fn test_escape_assertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act";

        assert_eq!(exp, escape_assertion(s));

        let s1 = "g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act";
        let exp1 = "g(r2_sub, p2_sub) && r2_obj == p2_obj && r2_act == p2_act";

        assert_eq!(exp1, escape_assertion(s1));
    }

    #[test]
    fn test_csv_parse_1() {
        assert_eq!(
            parse_csv_line("alice, domain1, data1, action1"),
            Some(vec![
                "alice".to_owned(),
                "domain1".to_owned(),
                "data1".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_2() {
        assert_eq!(
            parse_csv_line("alice, \"domain1, domain2\", data1 , action1"),
            Some(vec![
                "alice".to_owned(),
                "domain1, domain2".to_owned(),
                "data1".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_3() {
        assert_eq!(
            parse_csv_line(","),
            Some(vec!["".to_owned(), "".to_owned(),])
        )
    }

    #[test]
    fn test_csv_parse_4() {
        assert_eq!(parse_csv_line(" "), None);
        assert_eq!(parse_csv_line("#"), None);
        assert_eq!(parse_csv_line(" #"), None);
    }

    #[test]
    fn test_csv_parse_5() {
        assert_eq!(
            parse_csv_line(
                "alice, \"domain1, domain2\", \"data1, data2\", action1"
            ),
            Some(vec![
                "alice".to_owned(),
                "domain1, domain2".to_owned(),
                "data1, data2".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_6() {
        assert_eq!(parse_csv_line("\" "), Some(vec!["\"".to_owned()]))
    }

    #[test]
    fn test_csv_parse_7() {
        assert_eq!(
            parse_csv_line("\" alice"),
            Some(vec!["\" alice".to_owned()])
        )
    }

    #[test]
    fn test_csv_parse_8() {
        assert_eq!(
            parse_csv_line("alice, \"domain1, domain2"),
            Some(vec!["alice".to_owned(), "\"domain1, domain2".to_owned(),])
        )
    }

    #[test]
    fn test_csv_parse_9() {
        assert_eq!(parse_csv_line("\"\""), Some(vec!["".to_owned()]));
    }

    #[test]
    fn test_csv_parse_10() {
        assert_eq!(
            parse_csv_line("r.sub.Status == \"ACTIVE\", /data1, read"),
            Some(vec![
                "r.sub.Status == \"ACTIVE\"".to_owned(),
                "/data1".to_owned(),
                "read".to_owned()
            ])
        );
    }
}
