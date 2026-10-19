use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Client;

use crate::core::{
    FetchContext, ProviderError, ProviderFetchResult, RateWindow, UsageSnapshot,
    open_readonly_sqlite_connection,
};

const USAGE_API_URL: &str = "https://opencode.ai/zen/go/v1/usage";

static LOCAL_AUTH_JSON_DISCOVERY: AtomicBool = AtomicBool::new(false);

/// Lets binaries use credentials stored by the local `opencode` CLI
/// (`~/.local/share/opencode/auth.json` and the V2 OAuth row in `opencode.db`)
/// without duplicating the secret in CodexBar settings. Off by default so tests
/// stay hermetic; the desktop app and the CLI enable it at startup.
pub fn enable_local_auth_json_discovery() {
    LOCAL_AUTH_JSON_DISCOVERY.store(true, Ordering::Relaxed);
}

fn opencode_auth_json_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|dir| !dir.as_os_str().is_empty())
        .or_else(|| dirs::home_dir().map(|home| home.join(".local").join("share")))?;
    Some(base.join("opencode").join("auth.json"))
}

fn opencode_auth_json_api_key() -> Option<String> {
    if !LOCAL_AUTH_JSON_DISCOVERY.load(Ordering::Relaxed) {
        return None;
    }
    let text = std::fs::read_to_string(opencode_auth_json_path()?).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    normalized_api_key(
        value
            .get("opencode-go")
            .and_then(|entry| entry.get("key"))
            .and_then(serde_json::Value::as_str),
    )
}

/// OpenCode V2 authenticates the console/CLI with an OAuth credential stored
/// in `opencode.db` (`credential.value`). Its `access` token works against the
/// public Go usage endpoint, while the legacy `auth.json` API key may be
/// revoked after a plan renewal. Read only active OAuth rows.
fn opencode_v2_oauth_access_token(now: DateTime<Utc>) -> Option<String> {
    if !LOCAL_AUTH_JSON_DISCOVERY.load(Ordering::Relaxed) {
        return None;
    }
    for (_, db) in super::local::candidate_paths() {
        if let Some(token) = oauth_access_token_from_db(&db, now) {
            return Some(token);
        }
    }
    None
}

fn oauth_access_token_from_db(db_path: &Path, now: DateTime<Utc>) -> Option<String> {
    if !db_path.is_file() {
        return None;
    }
    let conn = open_readonly_sqlite_connection(db_path, Duration::from_millis(250)).ok()?;
    let mut stmt = conn
        .prepare(
            "SELECT value
             FROM credential
             WHERE integration_id IN ('opencode', 'opencode-go')
               AND active = 1
             ORDER BY time_updated DESC",
        )
        .ok()?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).ok()?;
    rows.flatten()
        .find_map(|value| parse_oauth_access_token(&value, now))
}

fn parse_oauth_access_token(value: &str, now: DateTime<Utc>) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(value).ok()?;
    if parsed.get("type").and_then(serde_json::Value::as_str) != Some("oauth") {
        return None;
    }
    let access = parsed
        .get("access")
        .and_then(serde_json::Value::as_str)?
        .trim();
    if access.is_empty() {
        return None;
    }
    if let Some(expires) = parsed.get("expires").and_then(serde_json::Value::as_i64)
        && expires <= now.timestamp_millis() + 60_000
    {
        return None;
    }
    Some(access.to_string())
}

pub(super) fn normalized_api_key(raw: Option<&str>) -> Option<String> {
    let mut value = raw?.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = value[1..value.len() - 1].trim();
    }
    (!value.is_empty()).then(|| value.to_string())
}

fn push_unique(keys: &mut Vec<String>, key: Option<String>) {
    if let Some(key) = key
        && !keys.iter().any(|existing| existing == &key)
    {
        keys.push(key);
    }
}

/// Credential candidates in priority order. Explicit settings/environment
/// values win; the V2 OAuth token is tried before the legacy `auth.json` key
/// so a revoked key does not mask a valid console login.
pub(super) fn resolve_api_keys(ctx: &FetchContext) -> Vec<String> {
    let mut keys = Vec::new();
    push_unique(&mut keys, normalized_api_key(ctx.api_key.as_deref()));
    push_unique(
        &mut keys,
        std::env::var("OPENCODE_API_KEY")
            .ok()
            .and_then(|value| normalized_api_key(Some(&value))),
    );
    push_unique(&mut keys, opencode_v2_oauth_access_token(Utc::now()));
    push_unique(&mut keys, opencode_auth_json_api_key());
    keys
}

pub(super) async fn fetch(
    client: &Client,
    ctx: &FetchContext,
    api_key: &str,
    source_label: &str,
) -> Result<ProviderFetchResult, ProviderError> {
    let response = client
        .get(USAGE_API_URL)
        .timeout(std::time::Duration::from_secs(ctx.web_timeout.max(1)))
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Accept", "application/json")
        .header("User-Agent", "CodexBar")
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ProviderError::AuthRequired);
    }
    if !status.is_success() {
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                ["message", "error", "detail"]
                    .into_iter()
                    .find_map(|key| value.get(key).and_then(serde_json::Value::as_str))
                    .map(str::to_string)
            })
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(ProviderError::Other(format!(
            "OpenCode Go API error: {message}"
        )));
    }
    let usage = parse_usage_text(&body, Utc::now())?;
    Ok(ProviderFetchResult::new(usage, source_label))
}

/// Try every discovered credential until one is accepted. This keeps a stale
/// API key in settings or `auth.json` from hiding a valid V2 OAuth login.
pub(super) async fn fetch_with_fallback(
    client: &Client,
    ctx: &FetchContext,
    source_label: &str,
) -> Result<ProviderFetchResult, ProviderError> {
    let keys = resolve_api_keys(ctx);
    if keys.is_empty() {
        return Err(ProviderError::NotInstalled(
            "Missing OpenCode Go API key. Add one in Settings or set OPENCODE_API_KEY.".to_string(),
        ));
    }
    let mut last_error = None;
    for key in keys {
        match fetch(client, ctx, &key, source_label).await {
            Ok(result) => return Ok(result),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(ProviderError::AuthRequired))
}

fn parse_usage_text(text: &str, now: DateTime<Utc>) -> Result<UsageSnapshot, ProviderError> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| ProviderError::Parse(format!("Invalid OpenCode Go API JSON: {e}")))?;
    let usage = value.get("usage").unwrap_or(&value);
    let rolling = api_window(usage, &["rolling", "rollingUsage", "rolling_usage"], now)
        .ok_or_else(|| ProviderError::Parse("Missing rolling usage window".to_string()))?;
    let mut snapshot = UsageSnapshot::new(RateWindow::with_details(
        rolling.0,
        Some(300),
        Some(rolling.1),
        None,
    ))
    .with_login_method("OpenCode Go");
    if let Some(weekly) = api_window(usage, &["weekly", "weeklyUsage", "weekly_usage"], now) {
        snapshot = snapshot.with_secondary(RateWindow::with_details(
            weekly.0,
            Some(10080),
            Some(weekly.1),
            None,
        ));
    }
    if let Some(monthly) = api_window(usage, &["monthly", "monthlyUsage", "monthly_usage"], now) {
        snapshot = snapshot.with_tertiary(RateWindow::with_details(
            monthly.0,
            RateWindow::monthly_window_minutes(Some(monthly.1)).or(Some(43200)),
            Some(monthly.1),
            None,
        ));
    }
    Ok(snapshot)
}

fn api_window(
    usage: &serde_json::Value,
    names: &[&str],
    now: DateTime<Utc>,
) -> Option<(f64, DateTime<Utc>)> {
    let object = names.iter().find_map(|name| usage.get(*name))?;
    let percent = [
        "percent",
        "usagePercent",
        "usedPercent",
        "percentUsed",
        "utilization",
    ]
    .into_iter()
    .find_map(|key| {
        object.get(key).and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })
    })?;
    // GET /zen/go/v1/usage returns whole percentages in 0..=100 (including exact
    // 1% / 0.5%). Do not treat values in (0, 1] as 0..=1 fractions: that turns
    // a real 1% into a false 100% exhausted state (win-fork #247 / upstream #3216).
    let percent = percent.clamp(0.0, 100.0);
    let reset = [
        "resetInSec",
        "resetInSeconds",
        "resetSeconds",
        "reset_in_sec",
    ]
    .into_iter()
    .find_map(|key| {
        object.get(key).and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })
    })
    .map(|seconds| now + chrono::Duration::seconds(seconds.max(0)))
    .or_else(|| {
        ["resetsAt", "resetAt", "resets_at", "reset_at"]
            .into_iter()
            .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
            .map(|timestamp| timestamp.with_timezone(&Utc))
    })?;
    Some((percent, reset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_credential_db(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("opencodego-usage-api-{label}-{nanos}.db"))
    }

    fn write_credential_db(path: &Path, rows: &[(i64, &str, &str, i64)]) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE credential (
                id TEXT PRIMARY KEY,
                integration_id TEXT NOT NULL,
                value TEXT NOT NULL,
                active INTEGER,
                time_updated INTEGER NOT NULL
            );",
        )
        .unwrap();
        for (index, (active, integration_id, value, time_updated)) in rows.iter().enumerate() {
            conn.execute(
                "INSERT INTO credential
                    (id, integration_id, value, active, time_updated)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    format!("cred{index}"),
                    integration_id,
                    value,
                    active,
                    time_updated
                ],
            )
            .unwrap();
        }
    }

    #[test]
    fn discovers_active_v2_oauth_token_and_skips_expired_rows() {
        let now = DateTime::parse_from_rfc3339("2026-10-19T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let db = temp_credential_db("oauth");
        let expired = format!(
            r#"{{"type":"oauth","access":"st_expired","expires":{}}}"#,
            now.timestamp_millis() - 1
        );
        let valid = format!(
            r#"{{"type":"oauth","access":"st_valid","expires":{}}}"#,
            now.timestamp_millis() + 3_600_000
        );
        write_credential_db(
            &db,
            &[
                (1, "opencode", expired.as_str(), 3),
                (1, "opencode", valid.as_str(), 2),
                (0, "opencode", valid.as_str(), 1),
            ],
        );

        assert_eq!(
            oauth_access_token_from_db(&db, now).as_deref(),
            Some("st_valid")
        );

        let _removed = std::fs::remove_file(&db);
    }

    #[test]
    fn ignores_non_oauth_credentials_in_the_credential_table() {
        let now = DateTime::parse_from_rfc3339("2026-10-19T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let db = temp_credential_db("api-key");
        write_credential_db(
            &db,
            &[(1, "opencode-go", r#"{"type":"key","key":"sk_stale"}"#, 1)],
        );

        assert_eq!(oauth_access_token_from_db(&db, now), None);

        let _removed = std::fs::remove_file(&db);
    }

    #[test]
    fn api_key_normalization_matches_upstream_settings_reader() {
        assert_eq!(
            normalized_api_key(Some("  go_test  ")).as_deref(),
            Some("go_test")
        );
        assert_eq!(
            normalized_api_key(Some("'go_quoted'")).as_deref(),
            Some("go_quoted")
        );
        assert_eq!(normalized_api_key(Some("   ")), None);
    }

    #[test]
    fn parses_public_usage_api_windows() {
        let now = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let text = r#"{"usage":{"rolling":{"percent":12,"resetsAt":"2026-08-12T02:00:00.000Z"},"weekly":{"percent":8,"resetsAt":"2026-08-18T00:00:00.000Z"},"monthly":{"percent":35,"resetsAt":"2026-09-01T00:00:00.000Z"}}}"#;
        let snapshot = parse_usage_text(text, now).unwrap();
        assert!((snapshot.primary.used_percent - 12.0).abs() < 0.001);
        assert!((snapshot.secondary.as_ref().unwrap().used_percent - 8.0).abs() < 0.001);
        assert!((snapshot.tertiary.as_ref().unwrap().used_percent - 35.0).abs() < 0.001);
    }

    #[test]
    fn preserves_whole_percent_units_including_exact_one() {
        let now = DateTime::parse_from_rfc3339("2026-08-31T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // Live Go API shape: percent is already 0..=100. Exact 1 must stay 1%.
        let text = r#"{"usage":{"rolling":{"status":"ok","percent":1,"resetsAt":"2026-08-31T17:12:09.085Z"},"weekly":{"status":"ok","percent":0,"resetsAt":"2026-09-07T00:00:00.085Z"},"monthly":{"status":"ok","percent":23,"resetsAt":"2026-09-20T04:39:33.085Z"}}}"#;
        let snapshot = parse_usage_text(text, now).unwrap();
        assert!(
            (snapshot.primary.used_percent - 1.0).abs() < 0.001,
            "rolling 1% must not be rescaled to 100%, got {}",
            snapshot.primary.used_percent
        );
        assert!((snapshot.secondary.as_ref().unwrap().used_percent - 0.0).abs() < 0.001);
        assert!((snapshot.tertiary.as_ref().unwrap().used_percent - 23.0).abs() < 0.001);
    }

    #[test]
    fn preserves_sub_one_percent_without_fraction_rescale() {
        let now = DateTime::parse_from_rfc3339("2026-08-31T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let text = r#"{"usage":{"rolling":{"percent":0.5,"resetsAt":"2026-08-31T17:00:00Z"},"weekly":{"percent":100,"resetsAt":"2026-09-07T00:00:00Z"}}}"#;
        let snapshot = parse_usage_text(text, now).unwrap();
        assert!(
            (snapshot.primary.used_percent - 0.5).abs() < 0.001,
            "0.5% must stay 0.5, got {}",
            snapshot.primary.used_percent
        );
        assert!((snapshot.secondary.as_ref().unwrap().used_percent - 100.0).abs() < 0.001);
    }
}
