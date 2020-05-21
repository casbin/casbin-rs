#[macro_export]
macro_rules! get_or_err {
    ($this:ident, $key:expr, $err:expr, $msg:expr) => {{
        $this
            .get_model()
            .get_model()
            .get($key)
            .ok_or_else(|| {
                $crate::error::Error::from($err(format!(
                    "Missing {} definition in conf file",
                    $msg
                )))
            })?
            .get($key)
            .ok_or_else(|| {
                $crate::error::Error::from($err(format!("Missing {} section in conf file", $msg)))
            })?
    }};
}

pub fn get_link_args(args: &rhai::Array) -> [Option<&str>; 3] {
    const G_FUNC_ERROR_MSG: &str = "g function only supports 2 or 3 parameters";

    let mut drain = args
        .iter()
        .filter_map(|x| x.downcast_ref::<String>().map(String::as_str));

    [
        Some(drain.next().expect(G_FUNC_ERROR_MSG)),
        Some(drain.next().expect(G_FUNC_ERROR_MSG)),
        drain.next(),
    ]
}

#[macro_export]
macro_rules! generate_g_function {
    ($rm:ident) => {{
        let cb = move |args: &mut rhai::Array| -> bool {
            let link_args = crate::macros::get_link_args(args);

            $rm.write().unwrap().has_link(
                link_args[0].unwrap(),
                link_args[1].unwrap(),
                link_args[2],
            )
        };
        Box::new(cb)
    }};
}
