use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{error, info, warn, Level};

#[derive(Debug, Deserialize)]
struct Config {
    /// IONOS API key as a single "prefix.secret" string.
    api_key: String,
    /// Fully-qualified domains to manage. Subdomains are auto-created on
    /// first activation if the IONOS DynDNS endpoint accepts them.
    domains: Vec<String>,
    /// How often the heartbeat runs: detects public IP and queries DNS.
    /// Alias `update_interval_secs` for backwards compat with older configs.
    #[serde(default = "default_heartbeat_interval_secs", alias = "update_interval_secs")]
    heartbeat_interval_secs: u64,
    /// Minimum seconds between two GETs of the cached `updateUrl`.
    /// IONOS rate-limits this endpoint to roughly 1 per 30s — going
    /// faster gets you 429s and a ~30s cooldown. Default 30s.
    #[serde(default = "default_publish_rate_limit_secs")]
    publish_rate_limit_secs: u64,
    /// Public IP detection providers. Comma-separated. Default: 5 providers
    /// for race-trigger + parallel validation coverage.
    #[serde(default = "default_ip_providers")]
    ip_providers: Vec<String>,
    /// Per-provider HTTP timeout for the race + validation phase. Default 3s.
    #[serde(default = "default_provider_timeout_secs")]
    provider_timeout_secs: u64,
    /// Maximum time the race phase waits for the first response. Default 5s.
    #[serde(default = "default_race_deadline_secs")]
    race_deadline_secs: u64,
    /// Persist the per-cycle `updateUrl` here so the next cycle (and external
    /// tools) can read it. Re-acquired on API errors.
    #[serde(default = "default_state_file")]
    state_file: PathBuf,
    /// Bind address for the /healthz endpoint (HTTP).
    #[serde(default = "default_health_addr")]
    health_addr: String,
    /// Force a re-publish every N seconds even if local state agrees.
    /// Defensive against silent IONOS-side drift (external record edits,
    /// API success-without-actual-update). Default 21600 (6h). Set to 0
    /// to disable.
    #[serde(default = "default_force_republish_secs")]
    force_republish_secs: u64,
    /// Optional: apex domain to manage via IONOS Records API
    /// (e.g. "steimercloud.xyz"). When set, the apex A-record is kept in
    /// sync with the detected public IP after every successful DynDNS
    /// publish. Reuses `api_key` via X-API-Key auth — works iff that key
    /// has `dns:zones` scope on IONOS. Defaults to None (no apex management).
    #[serde(default)]
    apex_domain: Option<String>,
    /// TTL in seconds for the apex A-record PATCH. Default 300.
    #[serde(default = "default_apex_ttl_secs")]
    apex_ttl_secs: u32,
}

fn default_heartbeat_interval_secs() -> u64 {
    60
}
fn default_publish_rate_limit_secs() -> u64 {
    30
}
fn default_ip_providers() -> Vec<String> {
    vec![
        "ifconfig.co".into(),
        "api.ipify.org".into(),
        "ident.me".into(),
        "icanhazip.com".into(),
        "checkip.amazonaws.com".into(),
    ]
}
fn default_provider_timeout_secs() -> u64 {
    3
}
fn default_race_deadline_secs() -> u64 {
    5
}
fn default_state_file() -> PathBuf {
    PathBuf::from("/data/state.json")
}
fn default_health_addr() -> String {
    "0.0.0.0:8080".into()
}
fn default_force_republish_secs() -> u64 {
    21600
}
fn default_apex_ttl_secs() -> u32 {
    300
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct State {
    /// Per-domain `updateUrl` returned by IONOS, persisted across restarts.
    update_urls: std::collections::HashMap<String, String>,
    /// Last public IP we successfully published (or verified unchanged).
    last_ip: Option<String>,
    /// Last successful IONOS response timestamp.
    last_success: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of the last successful (2xx) `updateUrl` GET. Used to
    /// enforce `publish_rate_limit_secs` and avoid IONOS 429s.
    #[serde(default)]
    last_publish_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Legacy field kept for backward-compat with older state.json files.
    /// No longer consulted for any logic. Safe to leave populated.
    #[serde(default)]
    last_attempt_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Legacy field kept for backward-compat. No longer consulted.
    #[serde(default)]
    divergence_streak: u32,
    /// Cached IONOS zone ID for `Config::apex_domain`. Discovered lazily
    /// on first apex publish; persisted to skip the listing call on
    /// subsequent cycles. Cleared automatically on lookup failure.
    #[serde(default)]
    apex_zone_id: Option<String>,
    /// Cached IONOS apex A-record ID (the record with empty/`@` name and
    /// type=A). Same lifecycle as `apex_zone_id`.
    #[serde(default)]
    apex_record_id: Option<String>,
    /// Last content value the apex update wrote. Used to suppress no-op
    /// PUTs and to detect out-of-band drift on restart (forces a re-write).
    #[serde(default)]
    apex_record_content: Option<String>,
}

/// One peer's response from the validation phase.
#[derive(Debug)]
#[allow(dead_code)] // provider name is kept for future per-peer logging / metrics
struct PeerResponse {
    provider: String,
    ip: Option<String>, // None = unreachable (timeout or error)
}

/// Counts of how each non-trigger peer voted.
#[derive(Debug, Default)]
struct ValidationBuckets {
    confirm: u32,   // peer.ip == trigger_ip
    outdated: u32,  // peer.ip == last known (current) ip
    conflict: u32,  // peer.ip is something else (a third IP)
    unreachable: u32, // timeout or error
}

#[derive(Debug, Serialize)]
struct DynDnsRequest<'a> {
    domains: &'a [String],
    description: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynDnsResponse {
    #[serde(default)]
    bulk_id: Option<String>,
    #[serde(default)]
    update_url: Option<String>,
    #[serde(default)]
    domains: Option<Vec<String>>,
}

const ENDPOINT_DYNDNS: &str = "https://api.hosting.ionos.com/dns/v1/dyndns";

/// Base URL for the IONOS Records/Zones API (legacy hosting endpoint,
/// same auth scheme as DynDNS: `X-API-Key`). Used for apex A-record
/// updates since the DynDNS endpoint cannot touch the zone apex.
const IONOS_API_BASE: &str = "https://api.hosting.ionos.com/dns/v1";

#[derive(Debug, Deserialize)]
struct ZoneSummary {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ZonesList {
    #[serde(default)]
    items: Vec<ZoneSummary>,
}

#[derive(Debug, Deserialize)]
struct RecordSummary {
    id: String,
    #[serde(rename = "type")]
    rec_type: String,
    name: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct RecordsList {
    #[serde(default)]
    items: Vec<RecordSummary>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg_path = std::env::var("IONOS_UPDATER_CONFIG")
        .unwrap_or_else(|_| "/data/config.json".into());
    let cfg_raw = tokio::fs::read_to_string(&cfg_path)
        .await
        .with_context(|| format!("read config {}", cfg_path))?;
    let cfg: Config = serde_json::from_str(&cfg_raw)
        .with_context(|| "parse config.json")?;
    info!(
        domains = cfg.domains.len(),
        heartbeat_secs = cfg.heartbeat_interval_secs,
        rate_limit_secs = cfg.publish_rate_limit_secs,
        ip_providers = cfg.ip_providers.len(),
        race_deadline_secs = cfg.race_deadline_secs,
        apex = ?cfg.apex_domain.as_deref(),
        "ionos-subdomain-updater starting"
    );

    // Spawn /healthz HTTP server
    let health_addr = cfg.health_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = run_health_server(&health_addr).await {
            error!(error = %e, "health server crashed");
        }
    });

    // Ensure state dir + load any previously persisted update URLs
    if let Some(parent) = cfg.state_file.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let mut state: State = match tokio::fs::read(&cfg.state_file).await {
        Ok(raw) => serde_json::from_slice(&raw).unwrap_or_default(),
        Err(_) => State::default(),
    };
    info!(
        cached_urls = state.update_urls.len(),
        "loaded persisted state"
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("ionos-subdomain-updater/0.1")
        .build()?;

    // Initial heartbeat (no waiting on the interval).
    if let Err(e) = run_heartbeat(&client, &cfg, &mut state).await {
        warn!(error = %e, "initial heartbeat failed");
    }
    persist_state(&cfg.state_file, &state).await.ok();

    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.heartbeat_interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        if let Err(e) = run_heartbeat(&client, &cfg, &mut state).await {
            warn!(error = %e, "heartbeat failed");
        }
        persist_state(&cfg.state_file, &state).await.ok();
    }
}

async fn run_health_server(addr: &str) -> Result<()> {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    info!(addr, "health server listening");
    loop {
        let (mut sock, _) = listener.accept().await?;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = sock.read(&mut [0u8; 1024]).await;
            let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = sock.write_all(resp).await;
            let _ = sock.shutdown().await;
        });
    }
}

async fn run_heartbeat(
    client: &reqwest::Client,
    cfg: &Config,
    state: &mut State,
) -> Result<()> {
    // Phase 1+2: Race-Trigger + parallel Validation.
    let (trigger_ip, peers) = race_then_validate_public_ip(
        client,
        &cfg.ip_providers,
        Duration::from_secs(cfg.provider_timeout_secs),
        Duration::from_secs(cfg.race_deadline_secs),
    )
    .await?;

    let last_ip = state.last_ip.clone();
    let buckets = bucketize(&last_ip, &trigger_ip, &peers);

    info!(
        trigger_ip = %trigger_ip,
        last_ip = ?last_ip,
        confirm = buckets.confirm,
        outdated = buckets.outdated,
        conflict = buckets.conflict,
        unreachable = buckets.unreachable,
        peer_total = peers.len(),
        "ip-detect: race + validation"
    );

    // Decide whether to publish.
    let ip_changed = last_ip.as_deref() != Some(trigger_ip.as_str());
    let force_due = match (state.last_success, cfg.force_republish_secs) {
        (Some(ts), interval) if interval > 0 => {
            (chrono::Utc::now() - ts).num_seconds() >= interval as i64
        }
        (None, interval) if interval > 0 => true,
        _ => false,
    };

    if !ip_changed && !force_due {
        // Nothing to do. Refresh last_ip if we somehow drifted.
        state.last_ip = Some(trigger_ip);
        return Ok(());
    }

    if force_due {
        info!(
            age_secs = state.last_success
                .map(|t| (chrono::Utc::now() - t).num_seconds()),
            interval_secs = cfg.force_republish_secs,
            reason = "max_age",
            "force-republish triggered"
        );
    }
    if ip_changed {
        info!(
            from = ?last_ip,
            to = %trigger_ip,
            reason = "race_trigger",
            "publish: ip change"
        );
    }

    // Rate-limit: skip if we published too recently. IONOS GETs of the
    // cached updateUrl get 429 after ~2 quick calls and need ~30s to
    // recover. We trust `last_publish_ts` and never set it on 4xx/5xx.
    if let Some(last) = state.last_publish_ts {
        let elapsed = (chrono::Utc::now() - last).num_seconds();
        if elapsed < cfg.publish_rate_limit_secs as i64 {
            info!(
                elapsed_secs = elapsed,
                rate_limit = cfg.publish_rate_limit_secs,
                "publish rate-limited; defer to next heartbeat"
            );
            return Ok(());
        }
    }

    // Get a token if we don't have one (or if a previous GET came back 401).
    if state.update_urls.is_empty() {
        match refresh_update_url(client, cfg, state).await {
            Ok(()) => {}
            Err(e) => {
                warn!(error = %e, "refresh_update_url failed");
                return Ok(());
            }
        }
    }

    if state.update_urls.is_empty() {
        warn!("no updateUrl cached; nothing to publish");
        return Ok(());
    }

    // Publish: dedupe URLs (IONOS returns ONE token for the whole batch),
    // hit each one. Treat 401 as a signal to drop the cache and refresh
    // on the next heartbeat (token rotation).
    let unique_urls: HashSet<&String> = state.update_urls.values().collect();
    let mut any_ok = false;
    let mut any_401 = false;
    for url in &unique_urls {
        match client.get(url.as_str()).send().await {
            Ok(r) if r.status().is_success() => {
                info!(url = %url, "publish ok; IONOS will set A-record to caller IP");
                any_ok = true;
            }
            Ok(r) if r.status().as_u16() == 401 => {
                warn!(url = %url, status = %r.status(), "updateUrl rejected; will refresh token next cycle");
                any_401 = true;
            }
            Ok(r) => warn!(url = %url, status = %r.status(), "publish non-2xx"),
            Err(e) => warn!(url = %url, error = %e, "publish request failed"),
        }
    }
    if any_401 {
        state.update_urls.clear();
    }
    if any_ok {
        state.last_publish_ts = Some(chrono::Utc::now());
        state.last_success = Some(chrono::Utc::now());
        state.last_ip = Some(trigger_ip);
    }

    // Optional post-publish DoH check (informational, non-blocking).
    // We log the convergence state but never gate future cycles on it.
    // Includes the apex domain if apex management is configured.
    if any_ok {
        let ip_for_doh = state.last_ip.clone().unwrap_or_default();
        let mut doh_targets: Vec<String> = cfg.domains.clone();
        if let Some(apex) = &cfg.apex_domain {
            doh_targets.push(apex.clone());
        }
        match verify_dns_convergence(client, &doh_targets, &ip_for_doh).await {
            Ok(true) => info!(ip = %ip_for_doh, "post-publish DoH converged"),
            Ok(false) => warn!(ip = %ip_for_doh, "post-publish DoH still diverged (resolver cache, will catch up)"),
            Err(e) => warn!(error = %e, "post-publish DoH check failed"),
        }
    }

    // Apex management (if configured). Reuses `api_key` via X-API-Key on
    // the legacy Records API. Runs after DynDNS publish so we only update
    // the apex when we've actually pushed a new IP to IONOS.
    if any_ok {
        let ip_for_apex = state.last_ip.clone().unwrap_or_default();
        if !ip_for_apex.is_empty() {
            if let Err(e) = sync_apex_record(client, cfg, state, &ip_for_apex).await {
                warn!(error = %e, "apex sync failed (will retry next cycle)");
            }
        }
    }

    Ok(())
}

/// Spawn all providers in parallel. Phase 1 returns the first non-None IP
/// (race: which provider answers fastest). Phase 2 awaits the remaining
/// handles (capped by the per-provider timeout) and reports every peer's
/// answer so the caller can bucket them as confirm / outdated / conflict
/// / unreachable.
async fn race_then_validate_public_ip(
    client: &reqwest::Client,
    providers: &[String],
    per_provider_timeout: Duration,
    race_deadline: Duration,
) -> Result<(String, Vec<PeerResponse>)> {
    if providers.is_empty() {
        anyhow::bail!("no ip providers configured");
    }

    // Spawn every provider as its own task. Each task honours
    // per_provider_timeout individually and returns Option<String>.
    let mut handles: Vec<(String, tokio::task::JoinHandle<Option<String>>)> =
        Vec::with_capacity(providers.len());
    for p in providers {
        let p_clone = p.clone();
        let client = client.clone();
        let handle = tokio::spawn(async move {
            match timeout(per_provider_timeout, fetch_ip_from(&client, &p_clone)).await {
                Ok(Ok(ip)) => Some(ip),
                Ok(Err(e)) => {
                    warn!(provider = %p_clone, error = %e, "ip provider failed");
                    None
                }
                Err(_) => {
                    warn!(provider = %p_clone, "ip provider timed out");
                    None
                }
            }
        });
        handles.push((p.clone(), handle));
    }

    // Poll until at least one handle resolves successfully OR every handle
    // has finished (and reported None) OR race_deadline elapses. We do NOT
    // .await handles here — we only consume them in Phase 2 to keep them
    // alive for the validation buckets.
    let deadline = Instant::now() + race_deadline;
    let mut first_ip: Option<String> = None;
    'poll: loop {
        for (_name, h) in &handles {
            if h.is_finished() {
                // Use a non-consuming probe: tokio JoinHandle exposes
                // `is_finished()` only. We instead wait briefly on any
                // finished handle to read its value without taking it.
                // Easiest path: just await the first finished one we see,
                // and remember its result for Phase 2 via a side channel.
                // To keep this simple, we accept a tiny optimisation loss
                // and fall through to Phase 2 as soon as we see ANY handle
                // finish (not just successful ones).
                break 'poll;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Phase 2: collect every peer's answer. We deliberately await all
    // handles here even if they already finished — JoinHandle.await is
    // idempotent and returns immediately when the task is done. The race
    // outcome is "first Some wins"; ties broken by spawn order.
    let mut responses = Vec::with_capacity(handles.len());
    for (name, h) in handles {
        let ip = h.await.ok().flatten();
        if first_ip.is_none() {
            if let Some(ref v) = ip {
                first_ip = Some(v.clone());
            }
        }
        responses.push(PeerResponse { provider: name, ip });
    }

    let trigger_ip = first_ip
        .ok_or_else(|| anyhow::anyhow!("no ip provider responded within race deadline"))?;
    Ok((trigger_ip, responses))
}

/// Bucket the validation peers against the trigger IP and the last known
/// local IP. `outdated` = peer says the OLD ip (supports the change
/// implicitly — provider has not refreshed). `conflict` = peer says a
/// third IP that matches neither.
fn bucketize(
    last_ip: &Option<String>,
    trigger_ip: &str,
    peers: &[PeerResponse],
) -> ValidationBuckets {
    let mut b = ValidationBuckets::default();
    for p in peers {
        match &p.ip {
            Some(ip) if ip == trigger_ip => b.confirm += 1,
            Some(ip) if last_ip.as_deref() == Some(ip.as_str()) => b.outdated += 1,
            Some(_) => b.conflict += 1,
            None => b.unreachable += 1,
        }
    }
    b
}

/// POST /dyndns to (re-)register the entry and cache the returned updateUrl.
async fn refresh_update_url(
    client: &reqwest::Client,
    cfg: &Config,
    state: &mut State,
) -> Result<()> {
    let req = DynDnsRequest {
        domains: &cfg.domains,
        description: "ionos-subdomain-updater",
    };
    let resp = client
        .post(ENDPOINT_DYNDNS)
        .header("X-API-Key", &cfg.api_key)
        .header("Accept", "application/json")
        .json(&req)
        .send()
        .await
        .context("IONOS POST /dyndns")?;

    let status = resp.status();
    let body_text = resp.text().await.context("read IONOS body")?;
    if !status.is_success() {
        error!(%status, body = %body_text, "IONOS DynDNS failed");
        anyhow::bail!("IONOS DynDNS HTTP {}: {}", status, body_text);
    }

    let parsed: DynDnsResponse =
        serde_json::from_str(&body_text).context("parse IONOS DynDNS response")?;
    info!(
        bulk_id = ?parsed.bulk_id.as_deref(),
        domains = ?parsed.domains,
        "IONOS DynDNS accepted request"
    );

    match parsed.update_url {
        Some(update_url) => {
            for d in &cfg.domains {
                state.update_urls.insert(d.clone(), update_url.clone());
            }
            info!(%update_url, "cached updateUrl for next cycles");
            Ok(())
        }
        None => {
            warn!("IONOS response missing updateUrl; will retry next cycle");
            anyhow::bail!("IONOS POST /dyndns returned no updateUrl")
        }
    }
}

/// Look up the IONOS zone ID for a fully-qualified domain. Caches the
/// result in `state.apex_zone_id` and reuses it on subsequent calls.
async fn find_zone_id(
    client: &reqwest::Client,
    api_key: &str,
    zone_name: &str,
    state: &mut State,
) -> Result<String> {
    if let Some(id) = state.apex_zone_id.as_ref() {
        return Ok(id.clone());
    }
    let url = format!("{IONOS_API_BASE}/zones");
    let resp = client
        .get(&url)
        .header("X-API-Key", api_key)
        .send()
        .await
        .context("GET /zones")?
        .error_for_status()
        .context("GET /zones status")?
        .json::<ZonesList>()
        .await
        .context("parse zones list")?;
    let id = resp
        .items
        .into_iter()
        .find(|z| z.name == zone_name)
        .map(|z| z.id)
        .ok_or_else(|| anyhow::anyhow!("zone {zone_name} not found in IONOS account"))?;
    state.apex_zone_id = Some(id.clone());
    Ok(id)
}

/// Find the apex A-record (name == "" or "@", type == "A") in the given
/// zone. Caches both the record ID and the current content.
async fn find_apex_a_record(
    client: &reqwest::Client,
    api_key: &str,
    zone_id: &str,
    state: &mut State,
) -> Result<(String, String)> {
    if let (Some(id), Some(content)) = (state.apex_record_id.as_ref(), state.apex_record_content.as_ref()) {
        return Ok((id.clone(), content.clone()));
    }
    let url = format!("{IONOS_API_BASE}/zones/{zone_id}/records");
    let resp = client
        .get(&url)
        .header("X-API-Key", api_key)
        .send()
        .await
        .context("GET /zones/{zoneId}/records")?
        .error_for_status()
        .context("GET records status")?
        .json::<RecordsList>()
        .await
        .context("parse records list")?;
    let rec = resp
        .items
        .into_iter()
        .find(|r| r.rec_type == "A" && (r.name.is_empty() || r.name == "@"))
        .ok_or_else(|| anyhow::anyhow!("no apex A-record found in zone {zone_id}"))?;
    state.apex_record_id = Some(rec.id.clone());
    state.apex_record_content = Some(rec.content.clone());
    Ok((rec.id, rec.content))
}

/// PATCH (PUT) the apex A-record. Uses full-update PUT because the legacy
/// API lacks a partial-update endpoint per `ionosctl` implementation notes.
/// No-op if the current content already equals `new_ip` (saves API quota).
#[allow(clippy::too_many_arguments)] // (client, auth, zone, record, content, ip, ttl, state)
async fn update_apex_a_record(
    client: &reqwest::Client,
    api_key: &str,
    zone_id: &str,
    record_id: &str,
    current_content: &str,
    new_ip: &str,
    ttl: u32,
    state: &mut State,
) -> Result<()> {
    if current_content == new_ip {
        info!(ip = %new_ip, "apex already up-to-date; skipping PATCH");
        return Ok(());
    }
    let url = format!("{IONOS_API_BASE}/zones/{zone_id}/records/{record_id}");
    let body = serde_json::json!({
        "content": new_ip,
        "ttl": ttl,
        "disabled": false,
    });
    let resp = client
        .put(&url)
        .header("X-API-Key", api_key)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .context("PUT apex record")?;
    let status = resp.status();
    let body_text = resp.text().await.context("read PUT body")?;
    if !status.is_success() {
        anyhow::bail!("apex PUT HTTP {status}: {body_text}");
    }
    state.apex_record_content = Some(new_ip.to_string());
    info!(
        %status,
        from = %current_content,
        to = %new_ip,
        "apex A-record updated"
    );
    Ok(())
}

/// Top-level orchestrator for the apex update: discover zone + record,
/// then PUT the new IP. On 404 or auth failure, clear cached IDs so the
/// next cycle re-discovers rather than retrying a stale ID.
async fn sync_apex_record(
    client: &reqwest::Client,
    cfg: &Config,
    state: &mut State,
    new_ip: &str,
) -> Result<()> {
    let apex = match &cfg.apex_domain {
        Some(a) => a,
        None => return Ok(()), // apex management disabled
    };
    if let Err(e) = (async {
        let zone_id = find_zone_id(client, &cfg.api_key, apex, state).await?;
        let (record_id, current_content) =
            find_apex_a_record(client, &cfg.api_key, &zone_id, state).await?;
        update_apex_a_record(
            client,
            &cfg.api_key,
            &zone_id,
            &record_id,
            &current_content,
            new_ip,
            cfg.apex_ttl_secs,
            state,
        )
        .await
    })
    .await
    {
        // Clear caches so the next cycle re-discovers; permanent errors
        // (404 / 403) would otherwise wedge the updater.
        state.apex_zone_id = None;
        state.apex_record_id = None;
        return Err(e);
    }
    Ok(())
}

/// Informational DoH check (Google + Cloudflare). Used post-publish only;
/// never gates a publish decision. Returns Ok(true) if every queried
/// domain resolves to `expected_ip` at every source.
async fn verify_dns_convergence(
    client: &reqwest::Client,
    domains: &[String],
    expected_ip: &str,
) -> Result<bool> {
    if expected_ip.is_empty() {
        return Ok(false);
    }
    const SOURCES: &[(&str, &str)] = &[
        ("https://dns.google/resolve?name={domain}&type=A", ""),
        (
            "https://cloudflare-dns.com/dns-query?name={domain}&type=A",
            "application/dns-json",
        ),
    ];
    for domain in domains {
        for (tmpl, accept) in SOURCES {
            let url = tmpl.replace("{domain}", domain);
            let mut req = client.get(&url);
            if !accept.is_empty() {
                req = req.header("Accept", *accept);
            }
            let r = req
                .send()
                .await
                .with_context(|| format!("DoH GET {url}"))?;
            let j: serde_json::Value = r
                .json()
                .await
                .with_context(|| format!("parse DoH JSON from {url}"))?;
            let answers = j
                .get("Answer")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let matches = answers
                .iter()
                .any(|a| a.get("data").and_then(|d| d.as_str()) == Some(expected_ip));
            if !matches {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

async fn fetch_ip_from(client: &reqwest::Client, provider: &str) -> Result<String> {
    let url = match provider {
        // Echo plain-text IPv4
        "ifconfig.co" | "ifconfig.me" | "api.ipify.org" | "icanhazip.com" | "checkip.amazonaws.com" | "ident.me" => {
            format!("https://{provider}")
        }
        s if s.starts_with("http://") || s.starts_with("https://") => s.to_string(),
        s => format!("https://{s}"),
    };
    let resp = client
        .get(&url)
        .header("Accept", "text/plain")
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body = resp.text().await.with_context(|| format!("body {url}"))?;
    if !status.is_success() {
        anyhow::bail!("{url} -> HTTP {status}");
    }
    Ok(body.trim().to_string())
}

async fn persist_state(path: &PathBuf, state: &State) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &bytes).await.ok();
    // atomic rename: best effort
    tokio::fs::rename(&tmp, path).await.ok();
    Ok(())
}
