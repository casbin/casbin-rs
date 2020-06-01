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
macro_rules! register_g_function {
    ($enforcer:ident, $fname:expr) => {{
        let rm = Arc::clone(&$enforcer.rm);
        $enforcer.engine.register_fn(
            $fname,
            move |arg1: ImmutableString, arg2: ImmutableString| {
                rm.write().unwrap().has_link(&arg1, &arg2, None)
            },
        );

        let rm = Arc::clone(&$enforcer.rm);
        $enforcer.engine.register_fn(
            $fname,
            move |arg1: ImmutableString, arg2: ImmutableString, arg3: ImmutableString| {
                rm.write().unwrap().has_link(&arg1, &arg2, Some(&arg3))
            },
        );
    }};
}
