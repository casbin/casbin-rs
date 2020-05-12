use crate::{emitter::EventData, logger::Logger};

use log::{error, info};

#[derive(Default)]
pub struct DefaultLogger {
    enabled: bool,
}

impl Logger for DefaultLogger {
    #[inline]
    fn enable_log(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    #[inline]
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn print_enforce_log(&self, rvals: Vec<String>, authorized: bool, cached: bool) {
        if !self.is_enabled() {
            return;
        }

        let mut text: String = String::from(if cached { "[CACHE]" } else { "" });

        if authorized {
            text = format!(
                "{} Request: {:?}, Response: {}",
                text,
                rvals.join(", "),
                true
            );
            info!("{}", text);
        } else {
            text = format!(
                "{} Request: {:?}, Response: {}",
                text,
                rvals.join(", "),
                false
            );
            error!("{}", text);
        }
    }

    fn print_mgmt_log(&self, d: &EventData) {
        if !self.is_enabled() {
            return;
        }

        info!("{}", d);
    }

    fn print_explain_log(&self, rules: Vec<&Vec<String>>) {
        if !self.is_enabled() {
            return;
        }
        info!("Explain: {:?}", rules);
    }
}
