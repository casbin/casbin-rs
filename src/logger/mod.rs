use crate::emitter::EventData;

mod default_logger;

pub use default_logger::DefaultLogger;

pub trait Logger: Send + Sync {
    fn enable_log(&mut self, enabled: bool);
    fn is_enabled(&self) -> bool;
    fn print_enforce_log(&self, rvals: Vec<String>, authorized: bool, cached: bool);
    fn print_mgmt_log(&self, event_data: &EventData);
    fn print_explain_log(&self, rules: Vec<&Vec<String>>);
}
