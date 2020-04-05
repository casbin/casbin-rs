pub trait Effector: Send + Sync {
    fn merge_effects(&self, expr: &str, effects: Vec<EffectKind>) -> bool;
}

#[derive(PartialEq, Clone)]
pub enum EffectKind {
    Allow = 0,
    Indeterminate = 1,
    Deny = 2,
}

#[derive(Default)]
pub struct DefaultEffector {}

impl Effector for DefaultEffector {
    fn merge_effects(&self, expr: &str, effects: Vec<EffectKind>) -> bool {
        if expr == "some(where (p_eft == allow))" {
            let mut result = false;
            for eft in effects {
                if eft == EffectKind::Allow {
                    result = true;
                    break;
                }
            }

            result
        } else if expr == "!some(where (p_eft == deny))" {
            let mut result = true;
            for eft in effects {
                if eft == EffectKind::Deny {
                    result = false;
                    break;
                }
            }

            result
        } else if expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))" {
            let mut result = false;
            for eft in effects {
                if eft == EffectKind::Allow {
                    result = true;
                } else if eft == EffectKind::Deny {
                    result = false;
                    break;
                }
            }

            result
        } else if expr == "priority(p_eft) || deny" {
            let mut result = false;
            for eft in effects {
                if eft != EffectKind::Indeterminate {
                    if eft == EffectKind::Allow {
                        result = true
                    } else {
                        result = false
                    }
                    break;
                }
            }

            result
        } else {
            panic!("unsupported effect");
        }
    }
}
