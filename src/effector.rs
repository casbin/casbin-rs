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
    fn push_effect(&mut self, eft: EffectKind) -> (bool, bool);
}

pub struct DefaultEffectStream {
    done: bool,
    res: bool,
    expr: String,
    effects: Vec<EffectKind>,
}

#[derive(Default)]
pub struct DefaultEffector;

impl Effector for DefaultEffector {
    fn new_stream(&self, expr: &str, cap: usize) -> Box<dyn EffectorStream> {
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
            effects: Vec::with_capacity(cap),
        })
    }
}

impl EffectorStream for DefaultEffectStream {
    fn current(&self) -> bool {
        assert!(self.done);
        self.res
    }

    fn push_effect(&mut self, eft: EffectKind) -> (bool, bool) {
        let cap = self.effects.capacity();
        self.effects.push(eft);

        if self.expr == "some(where (p_eft == allow))" {
            if eft == EffectKind::Allow {
                self.done = true;
                self.res = true;
            }
        } else if self.expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))" {
            if eft == EffectKind::Allow {
                self.res = true;
            } else if eft == EffectKind::Deny {
                self.done = true;
                self.res = false;
            }
        } else if self.expr == "!some(where (p_eft == deny))" {
            if eft == EffectKind::Deny {
                self.done = true;
                self.res = false;
            }
        } else if self.expr == "priority(p_eft) || deny" {
            if eft != EffectKind::Indeterminate {
                if eft == EffectKind::Allow {
                    self.res = true;
                } else {
                    self.res = false;
                }
                self.done = true;
            }
        }

        if cap == self.effects.len() {
            self.done = true;
        }

        return (self.done, self.res);
    }
}
