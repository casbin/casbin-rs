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
                $crate::error::Error::from($err(format!(
                    "Missing {} section in conf file",
                    $msg
                )))
            })?
    }};
}

#[macro_export]
macro_rules! register_g_function {
    ($enforcer:ident, $fname:ident, $ast:ident) => {{
        let rm = Arc::clone(&$enforcer.rm);
        let count = $ast.value.matches('_').count();

        if count == 2 {
            $enforcer.engine.register_fn(
                $fname,
                move |arg1: ImmutableString, arg2: ImmutableString| {
                    rm.write().unwrap().has_link(&arg1, &arg2, None)
                },
            );
        } else if count == 3 {
            $enforcer.engine.register_fn(
                $fname,
                move |arg1: ImmutableString,
                      arg2: ImmutableString,
                      arg3: ImmutableString| {
                    rm.write().unwrap().has_link(&arg1, &arg2, Some(&arg3))
                },
            );
        } else {
            return Err(ModelError::P(
                r#"the number of "_" in role definition should be at least 2"#
                    .to_owned(),
            )
            .into());
        }
    }};
}

#[macro_export]
macro_rules! push_index_if_explain {
    ($this:ident) => {{
        #[cfg(feature = "explain")]
        if $this.cap > 1 {
            $this.expl.push($this.idx);
        }
    }};
}

#[macro_export]
macro_rules! tuplet {
 { ($y:ident $(, $x:ident)*) = $v:expr } => {
    let ($y,$($x),*, _) = tuplet!($v ; 1 ; ($($x),*) ; ($v.get(0)) ); };
 { ($y:ident , * $x:ident) = $v:expr } => {
    let ($y,$x) = tuplet!($v ; 1 ; () ; ($v.get(0)) ); };
 { ($y:ident $(, $x:ident)* , * $z:ident) = $v:expr } => {
    let ($y,$($x),*, $z) = tuplet!($v ; 1 ; ($($x),*) ; ($v.get(0)) ); };
 { $v:expr ; $j:expr ; ($y:ident $(, $x:ident)*) ; ($($a:expr),*)  } => {
    tuplet!( $v ; $j+1 ; ($($x),*) ; ($($a),*,$v.get($j)) ) };
 { $v:expr ; $j:expr ; () ; ($($a:expr),*) } => {
   {
    if $v.len() >= $j {
        let remain = $v.len() - $j;
        if remain > 0 {
            ($($a),*, Some(&$v[$j..]))
        } else {
            ($($a),*, None)
        }
    } else {
        ($($a),*, None)
    }
   }
 }
}
