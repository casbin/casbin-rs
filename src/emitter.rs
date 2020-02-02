use crate::enforcer::Enforcer;

use emitbrown::Emitter;
use lazy_static::lazy_static;

use std::sync::Mutex;

#[derive(Hash, PartialEq, Eq)]
pub(crate) enum Event {
    PolicyChange,
}

lazy_static! {
    pub(crate) static ref EMITTER: Mutex<Emitter<'static, Event, Enforcer>> =
        { Mutex::new(Emitter::new()) };
}
