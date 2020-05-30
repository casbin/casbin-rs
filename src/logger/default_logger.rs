use crate::{emitter::EventData, logger::Logger};

use log::{error, info, warn};

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

        let text = format!(
            "{} Request: {}, Response: {}",
            if cached { "[CACHE]" } else { "[FRESH]" },
            rvals.join(", "),
            authorized
        );

        if authorized {
            info!("[Enforce]{}", text);
        } else {
            error!("[Enforce]{}", text);
        }
    }

    fn print_mgmt_log(&self, d: &EventData) {
        if !self.is_enabled() {
            return;
        }

        info!("[Mgmt] {}", d);
    }

    #[cfg(feature = "explain")]
    fn print_expl_log(&self, rules: Vec<String>) {
        if !self.is_enabled() {
            return;
        }

        info!("[Explain] {}", rules.join(", "));
    }

    fn print_status_log(&self, enabled: bool) {
        if !self.is_enabled() {
            return;
        }

        if enabled {
            info!("[Status] casbin has been enabled!");
        } else {
            warn!("[Status] casbin has been disabled!");
        }
    }
}
