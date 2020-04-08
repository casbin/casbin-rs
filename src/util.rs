use lazy_static::lazy_static;
use regex::Regex;

pub fn escape_assertion(s: String) -> String {
    lazy_static! {
        static ref ASSERT: Regex = Regex::new(r#"(r|p)\."#).unwrap();
    }
    ASSERT.replace_all(&s, "${1}_").to_string()
}

pub fn escape_g_function(s: String) -> String {
    lazy_static! {
        static ref ESC_G: Regex =
            Regex::new(r#"(g\d*)\(((?:\s*[r|p]\.\w+\s*,\s*){1,2}\s*[r|p]\.\w+\s*)\)"#).unwrap();
    }
    ESC_G.replace_all(&s, "${1}([${2}])").to_string()
}

pub fn escape_in_operator(s: String) -> String {
    lazy_static! {
        static ref IN_OP: Regex =
            Regex::new(r#"((?:r\d*|p\d*)\.(?:[^\s]+))\s+in\s+(?:\[|\()([^\)\]]*)(?:\]|\))"#).unwrap();
    }
    IN_OP
        .replace_all(&s, "inMatch($1, [$2])")
        .replace("'", r#"""#)
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
    fn test_escape_in_operator() {
        let s1 = r#"g(r.sub, p.sub) && r.act in ["a","b","c"] && r.sub in ["alice","bob"] && r.obj in ["data1","data2"]"#;
        let exp1 = r#"g(r.sub, p.sub) && inMatch(r.act, ["a","b","c"]) && inMatch(r.sub, ["alice","bob"]) && inMatch(r.obj, ["data1","data2"])"#;

        assert_eq!(exp1, escape_in_operator(s1.to_owned()));

        let s2 = r#"g(r.sub, p.sub) && p.act in ["a","b","c"] && p.sub in ["alice","bob"] && p.obj in ["data1","data2"]"#;
        let exp2 = r#"g(r.sub, p.sub) && inMatch(p.act, ["a","b","c"]) && inMatch(p.sub, ["alice","bob"]) && inMatch(p.obj, ["data1","data2"])"#;

        assert_eq!(exp2, escape_in_operator(s2.to_owned()));

        let s3 =
            r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ('data2', 'data3')"#;
        let exp3 = r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || inMatch(r.obj, ["data2", "data3"])"#;

        assert_eq!(exp3, escape_in_operator(s3.to_owned()));

        let s4 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act || r.tenant in ('alice', 'bob')"#;
        let exp4 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act || inMatch(r.tenant, ["alice", "bob"])"#;

        assert_eq!(exp4, escape_in_operator(s4.to_owned()));

        let s5 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act && p2.sub in ('alice', 'bob') || r.obj in ('data2', 'data3')"#;
        let exp5 = r#"g(r.tenant, p.tenant) && r.obj == p.obj && r.act == p.act && inMatch(p2.sub, ["alice", "bob"]) || inMatch(r.obj, ["data2", "data3"])"#;

        assert_eq!(exp5, escape_in_operator(s5.to_owned()));
    }

    #[test]
    fn test_escape_assertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act";

        assert_eq!(exp, escape_assertion(s.to_owned()));
    }
}
