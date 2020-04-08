use regex::Regex;

pub fn escape_assertion(s: String) -> String {
    let re = Regex::new(r#"(r|p)\."#).unwrap();
    re.replace_all(&s, "${1}_").to_string()
}

pub fn escape_g_function(s: String) -> String {
    let re = Regex::new(r#"(g\d*)\(((?:\s*[r|p]\.\w+\s*,\s*){1,2}\s*[r|p]\.\w+\s*)\)"#).unwrap();
    re.replace_all(&s, "${1}([${2}])").to_string()
}

pub fn remove_comments(mut s: String) -> String {
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }

    s.trim().to_owned()
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
