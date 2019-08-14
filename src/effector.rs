pub trait Effector {
    fn merge_effects(&self, expr: String, effects: Vec<EffectKind>, results: Vec<f64>) -> bool;
}

#[derive(PartialEq, Clone)]
pub enum EffectKind {
    Allow = 0,
    Indeterminate = 1,
    Deny = 2,
}

#[derive(Default)]
pub struct DefaultEffector {}

// TODO: can we remove results? seems to be useless
impl Effector for DefaultEffector {
    fn merge_effects(&self, expr: String, effects: Vec<EffectKind>, results: Vec<f64>) -> bool {
        let mut result = false;
        if expr == "some(where (p_eft == allow))" {
            result = false;
            for eft in effects {
                if eft == EffectKind::Allow {
                    result = true;
                    break;
                }
            }
        } else if expr == "!some(where (p_eft == deny))" {
            result = true;
            for eft in effects {
                if eft == EffectKind::Deny {
                    result = false;
                    break;
                }
            }
        } else if expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))" {
            result = false;
            for eft in effects {
                if eft == EffectKind::Allow {
                    result = true;
                } else if eft == EffectKind::Deny {
                    result = false;
                    break;
                }
            }
        } else if expr == "priority(p_eft) || deny" {
            result = false;
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
        } else {
            panic!("unsupported effect");
            // result = false;
        }

        return result;
    }
}
