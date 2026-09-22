//! Process-wide Codex home override loaded from settings.
//!
//! `settings.json` can point CodexBar at an alternate Codex home (for example
//! a secondary account directory) without touching the default `~/.codex`.
//! Binaries call [`set_from_settings`] once at startup; the first call wins so
//! a later settings reload cannot move the home mid-process. The `CODEX_HOME`
//! environment variable keeps priority so per-shell overrides still work in
//! the CLI. Tests never call the setter, keeping per-test thread-local
//! overrides authoritative.

use std::path::PathBuf;
use std::sync::OnceLock;

static OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();

fn normalize(value: Option<String>) -> Option<PathBuf> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Install the settings-provided override (first call wins).
pub fn set_from_settings(codex_home: Option<String>) {
    if OVERRIDE.set(normalize(codex_home)).is_err() {
        tracing::debug!("codex home override already installed; keeping the startup value");
    }
}

/// The settings-provided Codex home, if configured.
pub fn override_path() -> Option<PathBuf> {
    OVERRIDE.get().cloned().flatten()
}

/// `CODEX_HOME` (non-empty) → settings override → `None`.
pub fn env_or_override() -> Option<PathBuf> {
    std::env::var("CODEX_HOME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(override_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_and_drops_empties() {
        assert_eq!(normalize(None), None);
        assert_eq!(normalize(Some("   ".to_string())), None);
        assert_eq!(
            normalize(Some(" C:\\codex-home ".to_string())),
            Some(PathBuf::from("C:\\codex-home"))
        );
    }
}
