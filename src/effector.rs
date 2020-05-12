#[derive(PartialEq, Clone, Copy)]
pub enum EffectKind {
    Allow = 0,
    Indeterminate = 1,
    Deny = 2,
}

pub trait Effector: Send + Sync {
    fn new_stream(&self, expr: &str, cap: usize) -> Box<dyn EffectorStream>;
}

pub trait EffectorStream: Send + Sync {
    fn current(&self) -> bool;
    fn expl(&self) -> Option<Vec<usize>>;
    fn push_effect(&mut self, eft: EffectKind) -> bool;
}

#[derive(Clone)]
pub struct DefaultEffectStream {
    done: bool,
    res: bool,
    expr: String,
    idx: usize,
    cap: usize,
    expl: Vec<usize>,
}

#[derive(Default)]
pub struct DefaultEffector;

impl Effector for DefaultEffector {
    fn new_stream(&self, expr: &str, cap: usize) -> Box<dyn EffectorStream> {
        assert!(cap > 0);

        let res = match &*expr {
            "some(where (p_eft == allow))"
            | "some(where (p_eft == allow)) && !some(where (p_eft == deny))"
            | "priority(p_eft) || deny" => false,
            "!some(where (p_eft == deny))" => true,
            _ => panic!("unsupported effect: `{}`", expr),
        };

        Box::new(DefaultEffectStream {
            done: false,
            res,
            expr: expr.to_owned(),
            cap,
            idx: 0,
            expl: Vec::with_capacity(10),
        })
    }
}

impl EffectorStream for DefaultEffectStream {
    #[inline]
    fn current(&self) -> bool {
        assert!(self.done);
        self.res
    }

    #[inline]
    fn expl(&self) -> Option<Vec<usize>> {
        assert!(self.done);
        if self.expl.is_empty() {
            None
        } else {
            Some(self.expl.clone())
        }
    }

    fn push_effect(&mut self, eft: EffectKind) -> bool {
        let has_policy = self.cap > 1;

        if self.expr == "some(where (p_eft == allow))" {
            if eft == EffectKind::Allow {
                self.done = true;
                self.res = true;

                if has_policy {
                    self.expl.push(self.idx);
                }
            }
        } else if self.expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))" {
            if eft == EffectKind::Allow {
                self.res = true;

                if has_policy {
                    self.expl.push(self.idx);
                }
            } else if eft == EffectKind::Deny {
                self.done = true;
                self.res = false;

                if has_policy {
                    self.expl.push(self.idx);
                }
            }
        } else if self.expr == "!some(where (p_eft == deny))" {
            if eft == EffectKind::Deny {
                self.done = true;
                self.res = false;

                if has_policy {
                    self.expl.push(self.idx);
                }
            }
        } else if self.expr == "priority(p_eft) || deny" && eft != EffectKind::Indeterminate {
            if eft == EffectKind::Allow {
                self.res = true;
            } else {
                self.res = false;
            }
            self.done = true;

            if has_policy {
                self.expl.push(self.idx);
            }
        }

        if self.idx + 1 == self.cap {
            self.done = true;
            self.idx = self.cap;
        } else {
            self.idx += 1;
        }

        self.done
    }
}
