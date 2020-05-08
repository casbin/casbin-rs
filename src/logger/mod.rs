use crate::emitter::EventData;

mod default_logger;

pub use default_logger::DefaultLogger;

pub trait Logger: Send + Sync {
    fn enable_log(&mut self, enable: bool);
    fn is_enabled(&self) -> bool;
    fn print_enforce_log(&self, rvals: Vec<String>, authorized: bool, is_cached: bool);
    fn print_mgmt_log(&self, event_data: &EventData);
}
