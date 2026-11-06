//! Fuzz target shared by the `fuzz_target!` and `fuzz!` binaries.

pub mod crashes;

use std::sync::OnceLock;

/// Triggers the crash named by [`crashes::ENV`] on non-empty inputs.
pub fn run(data: &[u8]) {
    static TRIGGER: OnceLock<Option<fn()>> = OnceLock::new();
    let trigger = TRIGGER.get_or_init(|| {
        let name = std::env::var(crashes::ENV).ok()?;
        let crash = crashes::CRASHES.iter().find(|crash| crash.name == name);
        Some(
            crash
                .unwrap_or_else(|| panic!("unknown crash {name:?}"))
                .trigger,
        )
    });
    if let Some(trigger) = trigger {
        if !data.is_empty() {
            trigger();
        }
    }
}
