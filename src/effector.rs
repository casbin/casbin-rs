use async_trait::async_trait;

#[cfg(all(feature = "runtime-async-std", not(target_arch = "wasm32")))]
use async_std::{sync::Receiver, task::spawn};
#[cfg(all(feature = "runtime-async-std", target_arch = "wasm32"))]
use async_std::{sync::Receiver, task::spawn_local as spawn};

#[cfg(feature = "runtime-tokio")]
use tokio::{sync::mpsc::Receiver, task::spawn};

#[async_trait]
pub trait Effector: Send + Sync {
    #[allow(unused_mut)]
    async fn merge_effects(&self, expr: &str, rx: Receiver<EffectKind>) -> bool;
}

#[derive(PartialEq, Clone, Debug)]
pub enum EffectKind {
    Allow = 0,
    Indeterminate = 1,
    Deny = 2,
}

#[derive(Default)]
pub struct DefaultEffector;

#[async_trait]
impl Effector for DefaultEffector {
    #[allow(unused_mut)]
    async fn merge_effects(&self, expr: &str, mut rx: Receiver<EffectKind>) -> bool {
        let expr = expr.to_string();
        let fut = spawn(async move {
            let mut result = match &*expr {
                "some(where (p_eft == allow))"
                | "some(where (p_eft == allow)) && !some(where (p_eft == deny))"
                | "priority(p_eft) || deny" => false,
                "!some(where (p_eft == deny))" => true,
                _ => panic!("unsupported effect: `{}`", expr),
            };

            while let Some(eft) = rx.recv().await {
                if &expr == "some(where (p_eft == allow))" && eft == EffectKind::Allow {
                    result = true;
                    break;
                } else if &expr == "!some(where (p_eft == deny))" && eft == EffectKind::Deny {
                    result = false;
                    break;
                } else if &expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))"
                    && eft == EffectKind::Allow
                {
                    result = true;
                } else if &expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))"
                    && eft == EffectKind::Deny
                {
                    result = false;
                    break;
                } else if &expr == "priority(p_eft) || deny" && eft != EffectKind::Indeterminate {
                    if eft == EffectKind::Allow {
                        result = true
                    } else {
                        result = false
                    }
                    break;
                }
            }

            result
        });

        #[cfg(feature = "runtime-async-std")]
        {
            fut.await
        }

        #[cfg(feature = "runtime-tokio")]
        {
            match fut.await {
                Ok(result) => result,
                Err(err) => panic!("effector stream error: {}", err),
            }
        }
    }
}
