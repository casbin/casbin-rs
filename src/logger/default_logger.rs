use crate::{emitter::EventData, logger::Logger};

use slog::Drain;
use slog::Logger as SLogger;
use slog::{info, o};

pub struct DefaultLogger {
    enabled: bool,
    slogger: SLogger,
}

impl Default for DefaultLogger {
    fn default() -> Self {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain)
            .chan_size(4096)
            .overflow_strategy(slog_async::OverflowStrategy::Block)
            .build()
            .fuse();

        let slogger = SLogger::root(drain, o!());

        Self {
            enabled: false,
            slogger,
        }
    }
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

    fn print_enforce_log(
        &self,
        rvals: Vec<String>,
        authorized: bool,
        cached: bool,
    ) {
        if !self.is_enabled() {
            return;
        }

        info!(self.slogger, "Enforce Request"; "Request" => rvals.join(","), "Cached" => cached, "Response" => authorized);
    }

    fn print_mgmt_log(&self, e: &EventData) {
        if !self.is_enabled() {
            return;
        }

        info!(self.slogger, "Policy Management"; "Event" => e.to_string());
    }

    #[cfg(feature = "explain")]
    fn print_explain_log(&self, rules: Vec<String>) {
        if !self.is_enabled() {
            return;
        }

        info!(self.slogger, "Hitted Policies"; "Explain" => rules.join(","));
    }

    fn print_status_log(&self, enabled: bool) {
        if !self.is_enabled() {
            return;
        }

        info!(self.slogger, "Status"; "Enabled" => enabled);
    }
}
