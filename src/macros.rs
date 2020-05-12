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

#[macro_export]
macro_rules! generate_g_function {
    ($rm:ident) => {{
        let cb = move |args: rhai::Array| -> bool {
            let args = args
                .into_iter()
                .filter_map(|x| x.downcast_ref::<String>().map(|y| y.to_owned()))
                .collect::<Vec<String>>();

            if args.len() == 3 {
                $rm.write()
                    .unwrap()
                    .has_link(&args[0], &args[1], Some(&args[2]))
            } else if args.len() == 2 {
                $rm.write().unwrap().has_link(&args[0], &args[1], None)
            } else {
                panic!("g function supports at most 3 parameters");
            }
        };
        Box::new(cb)
    }};
}
