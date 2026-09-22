use anyhow::{Context, Result};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{error, info, warn, Level};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

// =============================================================================
// Configuration
// =============================================================================

#[derive(Debug, Deserialize)]
struct Config {
    /// Cloudflare API Token (Bearer) with `DNS:Edit` permission scoped to
    /// the configured zone. Create at dash.cloudflare.com → My Profile →
    /// API Tokens → Edit zone DNS.
    cloudflare_api_token: String,
    /// Cloudflare Zone ID for `cloudflare_zone_name`. Visible in the CF
    /// dashboard's API section for the site.
    cloudflare_zone_id: String,
    /// Zone apex (e.g. "steimercloud.xyz"). Used for logging/verification
    /// only; the zone_id is what identifies it programmatically.
    cloudflare_zone_name: String,
    /// FQDN list of A-records to keep in sync with the detected public IP.
    /// Apex: pass `"steimercloud.xyz"` (full domain). Subdomain: either
    /// `"pi"` or `"pi.steimercloud.xyz"` (both accepted by CF).
    /// Wildcard: pass `"*.steimercloud.xyz"` for a zone-wide catch-all.
    /// Records that don't exist will be auto-created.
    managed_records: Vec<String>,
    /// Cloudflare proxy mode for managed records. `false` = DNS-only (we
    /// want this for a Homelab DynDNS — proxying would mask the public IP
    /// behind CF and break the entire point of DynDNS).
    #[serde(default)]
    proxied: bool,
    #[serde(default = "default_heartbeat_interval_secs")]
    heartbeat_interval_secs: u64,
    /// Minimum seconds between two full updates of all managed records.
    /// Cloudflare rate limit is 1200 req / 5 min across the whole account,
    /// so 30s leaves plenty of headroom.
    #[serde(default = "default_publish_rate_limit_secs")]
    publish_rate_limit_secs: u64,
    #[serde(default = "default_ip_providers")]
    ip_providers: Vec<String>,
    #[serde(default = "default_provider_timeout_secs")]
    provider_timeout_secs: u64,
    #[serde(default = "default_race_deadline_secs")]
    race_deadline_secs: u64,
    #[serde(default = "default_state_file")]
    state_file: PathBuf,
    #[serde(default = "default_health_addr")]
    health_addr: String,
    /// Force a re-publish every N seconds even if local state agrees.
    /// Defensive against silent CF-side drift. Default 21600 (6h). Set to 0
    /// to disable.
    #[serde(default = "default_force_republish_secs")]
    force_republish_secs: u64,
    /// Authoritative nameservers for the apex domain. Post-publish we
    /// query each of these for a probe record and compare against the
    /// just-published IP. With Cloudflare this is normally stable within
    /// seconds — the check exists for visibility and to auto-retry when
    /// anycast propagation is unexpectedly slow.
    #[serde(default = "default_authoritative_ns")]
    authoritative_ns: Vec<String>,
    #[serde(default = "default_ns_check_timeout_secs")]
    ns_check_timeout_secs: u64,
    #[serde(default = "default_max_ns_inconsistency_cycles")]
    max_ns_inconsistency_cycles: u32,
}

fn default_heartbeat_interval_secs() -> u64 { 60 }
fn default_publish_rate_limit_secs() -> u64 { 30 }
fn default_ip_providers() -> Vec<String> {
    vec![
        "ifconfig.co".into(),
        "api.ipify.org".into(),
        "ident.me".into(),
        "icanhazip.com".into(),
        "checkip.amazonaws.com".into(),
    ]
}
fn default_provider_timeout_secs() -> u64 { 3 }
fn default_race_deadline_secs() -> u64 { 5 }
fn default_state_file() -> PathBuf { PathBuf::from("/data/state.json") }
fn default_health_addr() -> String { "0.0.0.0:8080".into() }
fn default_force_republish_secs() -> u64 { 21600 }
fn default_authoritative_ns() -> Vec<String> {
    // Cloudflare assigns 2 NS per zone. The user overrides these in their
    // config once they know what CF assigned. Defaults match the most
    // common CF NS pair as of 2026 but operators MUST verify against
    // their actual CF dashboard.
    vec![
        "karl.ns.cloudflare.com".into(),
        "vera.ns.cloudflare.com".into(),
    ]
}
fn default_ns_check_timeout_secs() -> u64 { 5 }
fn default_max_ns_inconsistency_cycles() -> u32 { 10 }

// =============================================================================
// State (cached record IDs to skip list-records on every cycle)
// =============================================================================

#[derive(Debug, Serialize, Deserialize, Default)]
struct State {
    /// FQDN -> Cloudflare record ID. Discovered lazily on first publish.
    /// Cleared on lookup failure to force re-discovery next cycle.
    #[serde(default)]
    managed_record_ids: HashMap<String, String>,
    /// Last public IP we successfully published.
    #[serde(default)]
    last_ip: Option<String>,
    #[serde(default)]
    last_success: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    last_publish_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Last NS-convergence report. Operator-visible.
    #[serde(default)]
    ns_convergence_report: Option<NsReport>,
    #[serde(default)]
    ns_inconsistency_cycles: u32,
}

// =============================================================================
// IP-detection: race-trigger + validation buckets (unchanged)
// =============================================================================

#[derive(Debug)]
#[allow(dead_code)]
struct PeerResponse {
    provider: String,
    ip: Option<String>,
}

#[derive(Debug, Default)]
struct ValidationBuckets {
    confirm: u32,
    outdated: u32,
    conflict: u32,
    unreachable: u32,
}

async fn race_then_validate_public_ip(
    client: &reqwest::Client,
    providers: &[String],
    per_provider_timeout: Duration,
    race_deadline: Duration,
) -> Result<(String, Vec<PeerResponse>)> {
    if providers.is_empty() {
        anyhow::bail!("no ip providers configured");
    }
    let mut handles: Vec<(String, tokio::task::JoinHandle<Option<String>>)> =
        Vec::with_capacity(providers.len());
    for p in providers {
        let p_clone = p.clone();
        let client = client.clone();
        let timeout_d = per_provider_timeout;
        let handle = tokio::spawn(async move {
            match timeout(timeout_d, fetch_ip_from(&client, &p_clone)).await {
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

    let deadline = Instant::now() + race_deadline;
    let mut trigger: Option<(String, String)> = None;
    'poll: loop {
        for (_name, h) in &handles {
            if h.is_finished() {
                break 'poll;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let mut responses = Vec::with_capacity(handles.len());
    for (name, h) in handles {
        let ip = h.await.ok().flatten();
        if trigger.is_none() {
            if let Some(ref v) = ip {
                trigger = Some((name.clone(), v.clone()));
            }
        }
        responses.push(PeerResponse { provider: name, ip });
    }
    let trigger_ip = trigger
        .ok_or_else(|| anyhow::anyhow!("no ip provider responded within race deadline"))?
        .1;
    Ok((trigger_ip, responses))
}

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

async fn fetch_ip_from(client: &reqwest::Client, provider: &str) -> Result<String> {
    let url = match provider {
        "ifconfig.co" | "ifconfig.me" | "api.ipify.org" | "icanhazip.com"
        | "checkip.amazonaws.com" | "ident.me" => format!("https://{provider}"),
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

// =============================================================================
// Cloudflare API: types + envelope + 3 endpoint helpers
// =============================================================================

/// Standard Cloudflare API envelope. We deserialize every response into
/// this shape, then check `success` and unpack `result`.
#[derive(Debug, Deserialize)]
struct CfEnvelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    #[allow(dead_code)]
    code: u32,
    message: String,
}

impl<T> CfEnvelope<T> {
    fn into_result(self, op: &str) -> Result<T> {
        if !self.success {
            let msg = self
                .errors
                .into_iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ");
            anyhow::bail!("{op} failed: {msg}");
        }
        self.result.ok_or_else(|| anyhow::anyhow!("{op}: empty result"))
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
#[allow(dead_code)] // Default impl required by serde-deserialize; fields are read via .into_iter() in callers
struct CfRecord {
    id: String,
    #[serde(rename = "type")]
    rec_type: String,
    name: String,
    content: String,
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default)]
    proxied: Option<bool>,
}

fn default_ttl() -> u32 { 1 } // 1 = automatic in Cloudflare

#[derive(Debug, Serialize)]
struct CfRecordWrite<'a> {
    #[serde(rename = "type")]
    rec_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    proxied: bool,
}

/// List DNS records of type A matching `name.exact`. Returns the records
/// (typically 0 or 1 for our use case).
async fn cf_list_a_records(
    client: &reqwest::Client,
    token: &str,
    zone_id: &str,
    fqdn: &str,
) -> Result<Vec<CfRecord>> {
    let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .query(&[("type", "A"), ("name.exact", fqdn)])
        .send()
        .await
        .context("CF GET /dns_records")?
        .error_for_status()
        .context("CF list status")?
        .json::<CfEnvelope<Vec<CfRecord>>>()
        .await
        .context("parse CF list")?;
    let records = resp.into_result("CF list")?;
    Ok(records.into_iter().filter(|r| r.rec_type == "A").collect())
}

/// Update an existing A-record's content. `name` is the FQDN as stored on
/// the record (CF echoes it back unchanged). TTL=1 means "automatic".
async fn cf_update_a_record(
    client: &reqwest::Client,
    token: &str,
    zone_id: &str,
    record_id: &str,
    fqdn: &str,
    new_ip: &str,
    proxied: bool,
) -> Result<()> {
    let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}");
    let body = CfRecordWrite {
        rec_type: "A",
        name: fqdn,
        content: new_ip,
        ttl: 1,
        proxied,
    };
    let resp = client
        .put(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .context("CF PUT /dns_records/{id}")?;
    let status = resp.status();
    let body_text = resp.text().await.context("read PUT body")?;
    if !status.is_success() {
        anyhow::bail!("CF PUT HTTP {status}: {body_text}");
    }
    let parsed: CfEnvelope<CfRecord> =
        serde_json::from_str(&body_text).context("parse CF PUT")?;
    parsed.into_result("CF update")?;
    Ok(())
}

/// Create a new A-record. Returns the new record's ID.
async fn cf_create_a_record(
    client: &reqwest::Client,
    token: &str,
    zone_id: &str,
    fqdn: &str,
    ip: &str,
    proxied: bool,
) -> Result<String> {
    let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records");
    let body = CfRecordWrite {
        rec_type: "A",
        name: fqdn,
        content: ip,
        ttl: 1,
        proxied,
    };
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .context("CF POST /dns_records")?;
    let status = resp.status();
    let body_text = resp.text().await.context("read POST body")?;
    if !status.is_success() {
        anyhow::bail!("CF POST HTTP {status}: {body_text}");
    }
    let parsed: CfEnvelope<CfRecord> =
        serde_json::from_str(&body_text).context("parse CF POST")?;
    let record = parsed.into_result("CF create")?;
    Ok(record.id)
}

/// Pre-flight token verification. Hits `GET /user/tokens/verify` and fails
/// fast on any error so a misconfigured token never makes it past startup.
/// Also doubles as a zone_id sanity check via `GET /zones/{id}`.
async fn cf_verify_credentials(
    client: &reqwest::Client,
    token: &str,
    zone_id: &str,
) -> Result<()> {
    // 1. Token + perms
    let url = format!("{CF_API_BASE}/user/tokens/verify");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .context("CF GET /user/tokens/verify")?;
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "cloudflare_api_token rejected by CF (HTTP {status}): {body_text}. \
             check scope: needs DNS:Edit for the target zone."
        );
    }
    let parsed: CfEnvelope<serde_json::Value> =
        serde_json::from_str(&body_text).context("parse token verify")?;
    parsed.into_result("CF token verify")?;
    info!("CF token verified (DNS:Edit scope accepted)");

    // 2. Zone id resolves to the expected zone
    let url = format!("{CF_API_BASE}/zones/{zone_id}");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .context("CF GET /zones/{id}")?;
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "cloudflare_zone_id {zone_id} not accessible (HTTP {status}): {body_text}"
        );
    }
    let parsed: CfEnvelope<serde_json::Value> =
        serde_json::from_str(&body_text).context("parse zone lookup")?;
    let zone = parsed.into_result("CF zone lookup")?;
    let zone_name = zone
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    info!(zone_id = %zone_id, zone_name = %zone_name, "CF zone verified");
    Ok(())
}

// =============================================================================
// NS convergence check (unchanged from previous design)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NsReport {
    fresh: Vec<String>,
    stale: Vec<NsStaleEntry>,
    #[serde(with = "chrono::serde::ts_seconds")]
    checked_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NsStaleEntry {
    ns: String,
    returned_ip: String,
}

async fn build_ns_resolver(ns_host: &str, _per_query_timeout: Duration) -> Result<TokioResolver> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{ns_host}:53"))
        .await
        .with_context(|| format!("lookup NS {ns_host}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("NS {ns_host} did not resolve to any address");
    }
    let ips: Vec<std::net::IpAddr> = addrs.iter().map(|a| a.ip()).collect();
    // from_ips_clear constructs NameServerConfig entries internally with
    // both UDP and TCP variants. Avoids the private Protocol enum.
    let group = NameServerConfigGroup::from_ips_clear(&ips, 53, true);
    let config = ResolverConfig::from_parts(None, vec![], group);
    Ok(TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build())
}

async fn check_ns_convergence(
    ns_list: &[String],
    probe_domain: &str,
    expected_ip: &str,
    per_query_timeout: Duration,
    overall_timeout: Duration,
) -> NsReport {
    let fqdn = if probe_domain.ends_with('.') {
        probe_domain.to_string()
    } else {
        format!("{probe_domain}.")
    };
    let expected = expected_ip.to_string();
    let queries = ns_list.iter().map(|ns| {
        let ns = ns.clone();
        let domain = fqdn.clone();
        let expected = expected.clone();
        async move {
            let res = tokio::time::timeout(overall_timeout, async {
                let resolver = build_ns_resolver(&ns, per_query_timeout).await?;
                let lookup = resolver.lookup_ip(&domain).await?;
                let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                Ok::<Vec<String>, anyhow::Error>(ips)
            })
            .await;
            match res {
                Ok(Ok(ips)) => {
                    let matches = ips.iter().any(|ip| ip == &expected);
                    let returned =
                        ips.first().cloned().unwrap_or_else(|| "<no records>".into());
                    (ns.clone(), matches, returned)
                }
                Ok(Err(_)) => (ns.clone(), false, "<query failed>".into()),
                Err(_) => (ns.clone(), false, "<timeout>".into()),
            }
        }
    });
    let results = futures::future::join_all(queries).await;

    let mut fresh = Vec::new();
    let mut stale = Vec::new();
    for (ns, matches, returned) in results {
        if matches {
            fresh.push(ns);
        } else {
            stale.push(NsStaleEntry { ns, returned_ip: returned });
        }
    }
    NsReport { fresh, stale, checked_at: chrono::Utc::now() }
}

// =============================================================================
// Heartbeat
// =============================================================================

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg_path = std::env::var("IONOS_UPDATER_CONFIG")
        .unwrap_or_else(|_| "/data/config.json".into());
    let cfg_raw = tokio::fs::read_to_string(&cfg_path)
        .await
        .with_context(|| format!("read config {cfg_path}"))?;
    let cfg: Config =
        serde_json::from_str(&cfg_raw).with_context(|| "parse config.json")?;
    if cfg.managed_records.is_empty() {
        anyhow::bail!("managed_records must contain at least one FQDN");
    }
    info!(
        zone = %cfg.cloudflare_zone_name,
        zone_id = %cfg.cloudflare_zone_id,
        managed_records = cfg.managed_records.len(),
        heartbeat_secs = cfg.heartbeat_interval_secs,
        rate_limit_secs = cfg.publish_rate_limit_secs,
        ip_providers = cfg.ip_providers.len(),
        race_deadline_secs = cfg.race_deadline_secs,
        authoritative_ns = cfg.authoritative_ns.len(),
        proxied = cfg.proxied,
        "cloudflare-subdomain-updater starting"
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("cloudflare-subdomain-updater/0.2")
        .build()?;

    // Pre-flight: verify the CF token and zone id BEFORE we start the
    // health server and heartbeat loop. A bad token would otherwise only
    // surface as 401 on the first record update — harder to diagnose
    // than a clean startup failure.
    if let Err(e) = cf_verify_credentials(
        &client,
        &cfg.cloudflare_api_token,
        &cfg.cloudflare_zone_id,
    )
    .await
    {
        anyhow::bail!("CF credential pre-flight failed: {e}");
    }

    let health_addr = cfg.health_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = run_health_server(&health_addr).await {
            error!(error = %e, "health server crashed");
        }
    });

    if let Some(parent) = cfg.state_file.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let mut state: State = match tokio::fs::read(&cfg.state_file).await {
        Ok(raw) => serde_json::from_slice(&raw).unwrap_or_default(),
        Err(_) => State::default(),
    };
    info!(
        cached_records = state.managed_record_ids.len(),
        "loaded persisted state"
    );

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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    info!(addr, "health server listening");
    loop {
        let (mut sock, _) = listener.accept().await?;
        tokio::spawn(async move {
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
    // Phase 1+2: race + validation
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

    let ip_changed = last_ip.as_deref() != Some(trigger_ip.as_str());
    let force_due = match (state.last_success, cfg.force_republish_secs) {
        (Some(ts), interval) if interval > 0 => {
            (chrono::Utc::now() - ts).num_seconds() >= interval as i64
        }
        (None, interval) if interval > 0 => true,
        _ => false,
    };

    if !ip_changed && !force_due {
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

    // Rate-limit
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

    // Update every managed record
    let mut any_ok = false;
    for fqdn in &cfg.managed_records {
        match update_one_record(client, cfg, state, fqdn, &trigger_ip).await {
            Ok(record_id) => {
                info!(fqdn = %fqdn, ip = %trigger_ip, record_id = %record_id, "record updated");
                any_ok = true;
            }
            Err(e) => {
                warn!(fqdn = %fqdn, error = %e, "record update failed");
                // Clear cached ID; next cycle re-discovers via list-records.
                state.managed_record_ids.remove(fqdn);
            }
        }
    }

    if any_ok {
        state.last_publish_ts = Some(chrono::Utc::now());
        state.last_success = Some(chrono::Utc::now());
        state.last_ip = Some(trigger_ip);
    }

    // Post-publish NS convergence check
    if any_ok && !cfg.managed_records.is_empty() {
        let probe = cfg.managed_records[0].clone();
        let ip_for_ns = state.last_ip.clone().unwrap_or_default();
        if !ip_for_ns.is_empty() {
            let per_q = Duration::from_secs(cfg.ns_check_timeout_secs);
            let overall = per_q * cfg.authoritative_ns.len().max(1) as u32 + Duration::from_secs(1);
            let report = check_ns_convergence(
                &cfg.authoritative_ns,
                &probe,
                &ip_for_ns,
                per_q,
                overall,
            )
            .await;
            let total = report.fresh.len() + report.stale.len();
            if report.stale.is_empty() {
                info!(
                    fresh = total,
                    ip = %ip_for_ns,
                    "post-publish NS check: all authoritative NS converged"
                );
                state.ns_convergence_report = Some(report);
                state.ns_inconsistency_cycles = 0;
            } else {
                let stale_names: Vec<&str> =
                    report.stale.iter().map(|s| s.ns.as_str()).collect();
                let stale_ips: Vec<&str> =
                    report.stale.iter().map(|s| s.returned_ip.as_str()).collect();
                warn!(
                    fresh = report.fresh.len(),
                    stale = report.stale.len(),
                    total,
                    stale_ns = ?stale_names,
                    stale_returned = ?stale_ips,
                    "post-publish NS check: stale NS detected"
                );
                state.ns_convergence_report = Some(report);
                state.ns_inconsistency_cycles += 1;
                if state.ns_inconsistency_cycles <= cfg.max_ns_inconsistency_cycles {
                    state.last_publish_ts = None;
                    info!(
                        cycle = state.ns_inconsistency_cycles,
                        max = cfg.max_ns_inconsistency_cycles,
                        "rate-limit cleared; next cycle will re-publish"
                    );
                } else {
                    error!(
                        cycle = state.ns_inconsistency_cycles,
                        "max_ns_inconsistency_cycles reached; accepting partial convergence"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Resolve a single managed record's CF record ID (cached or via
/// list-records), then PUT the new IP. Creates the record if it doesn't
/// exist. Returns the record ID on success.
async fn update_one_record(
    client: &reqwest::Client,
    cfg: &Config,
    state: &mut State,
    fqdn: &str,
    new_ip: &str,
) -> Result<String> {
    let record_id = match state.managed_record_ids.get(fqdn).cloned() {
        Some(id) => id,
        None => {
            // Discover
            let records = cf_list_a_records(
                client,
                &cfg.cloudflare_api_token,
                &cfg.cloudflare_zone_id,
                fqdn,
            )
            .await?;
            if let Some(rec) = records.into_iter().next() {
                state.managed_record_ids.insert(fqdn.to_string(), rec.id.clone());
                rec.id
            } else {
                // Auto-create
                warn!(fqdn, "record not found in zone; auto-creating");
                let id = cf_create_a_record(
                    client,
                    &cfg.cloudflare_api_token,
                    &cfg.cloudflare_zone_id,
                    fqdn,
                    new_ip,
                    cfg.proxied,
                )
                .await?;
                state.managed_record_ids.insert(fqdn.to_string(), id.clone());
                return Ok(id);
            }
        }
    };

    cf_update_a_record(
        client,
        &cfg.cloudflare_api_token,
        &cfg.cloudflare_zone_id,
        &record_id,
        fqdn,
        new_ip,
        cfg.proxied,
    )
    .await?;
    Ok(record_id)
}

async fn persist_state(path: &PathBuf, state: &State) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &bytes).await.ok();
    tokio::fs::rename(&tmp, path).await.ok();
    Ok(())
}
