use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
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
    /// Public IP detection service(s). Comma-separated. Default: ifconfig.co,api.ipify.org.
    #[serde(default = "default_ip_providers")]
    ip_providers: Vec<String>,
    /// Persist the per-cycle `updateUrl` here so the next cycle (and external
    /// tools) can read it. Re-acquired on API errors.
    #[serde(default = "default_state_file")]
    state_file: PathBuf,
    /// Bind address for the /healthz endpoint (HTTP).
    #[serde(default = "default_health_addr")]
    health_addr: String,
}

fn default_heartbeat_interval_secs() -> u64 {
    60
}
fn default_publish_rate_limit_secs() -> u64 {
    30
}
fn default_ip_providers() -> Vec<String> {
    vec!["ifconfig.co".into(), "api.ipify.org".into()]
}
fn default_state_file() -> PathBuf {
    PathBuf::from("/data/state.json")
}
fn default_health_addr() -> String {
    "0.0.0.0:8080".into()
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct State {
    /// Per-domain `updateUrl` returned by IONOS, persisted across restarts.
    update_urls: std::collections::HashMap<String, String>,
    /// Last public IP we successfully saw and verified via DNS.
    last_ip: Option<String>,
    /// Last successful IONOS response timestamp.
    last_success: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of the last successful (2xx) `updateUrl` GET. Used to
    /// enforce `publish_rate_limit_secs` and avoid IONOS 429s.
    #[serde(default)]
    last_publish_ts: Option<chrono::DateTime<chrono::Utc>>,
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
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = b"ok\n";
            let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok";
            // We don't actually need the request; just respond.
            let _ = sock.write_all(resp).await;
            let _ = sock.write_all(b"ok").await;
            let _ = sock.shutdown().await;
        });
    }
}

async fn run_heartbeat(
    client: &reqwest::Client,
    cfg: &Config,
    state: &mut State,
) -> Result<()> {
    let my_ip = detect_public_ip(client, &cfg.ip_providers).await?;

    // (1) Compare with what IONOS actually has registered. We trust the
    //     DoH view over our local `state.last_ip` because IONOS could
    //     have been edited externally, or our cached IP could be stale.
    let doh_converged = match verify_dns_convergence(client, &cfg.domains, &my_ip).await {
        Ok(c) => Some(c),
        Err(e) => {
            warn!(error = %e, "DoH check failed; will fall back to local state");
            None
        }
    };

    let local_converged = state.last_ip.as_deref() == Some(my_ip.as_str());

    info!(
        %my_ip,
        local_last = ?state.last_ip,
        doh_converged = ?doh_converged,
        "heartbeat: detected public IPv4"
    );

    if matches!(doh_converged, Some(true)) && local_converged {
        // Everything matches — skip entirely, no IONOS API call.
        return Ok(());
    }

    let needs_publish = match doh_converged {
        Some(true) => false,           // DNS already correct, nothing to do
        Some(false) => true,           // IONOS diverges from our IP
        None => !local_converged,      // DoH unavailable, fall back to local
    };

    if !needs_publish {
        // DNS is correct but our local state hadn't caught up — sync it
        // and skip the API call.
        state.last_ip = Some(my_ip.clone());
        return Ok(());
    }

    // (2) Rate-limit: skip if we published too recently. IONOS GETs of the
    //     cached updateUrl get 429 after ~2 quick calls and need ~30s to
    //     recover. We trust `last_publish_ts` and never set it on 4xx/5xx.
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

    // (3) Get a token if we don't have one (or if a previous GET came back
    //     401 — see publish step below). POST /dyndns both registers the
    //     entry and returns the updateUrl.
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

    // (4) Publish: dedupe URLs (IONOS returns ONE token for the whole batch),
    //     hit each one. Treat 401 as a signal to drop the cache and refresh
    //     on the next heartbeat (token rotation).
    let unique_urls: std::collections::HashSet<&String> = state.update_urls.values().collect();
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
    }

    // (5) Update local view. Trust DoH over local; only mark the IP as
    //     published once DNS actually shows it.
    state.last_success = Some(chrono::Utc::now());
    if let Ok(true) = verify_dns_convergence(client, &cfg.domains, &my_ip).await {
        state.last_ip = Some(my_ip);
    }
    Ok(())
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

/// Query Google DoH for each domain's A-record. Returns true iff every
/// domain resolves to `expected_ip`. Uses DoH (not the local resolver) so
/// we don't see stale TTL caches.
async fn verify_dns_convergence(
    client: &reqwest::Client,
    domains: &[String],
    expected_ip: &str,
) -> Result<bool> {
    for domain in domains {
        let url = format!("https://dns.google/resolve?name={domain}&type=A");
        let r = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("DoH GET {url}"))?;
        let j: serde_json::Value = r.json().await.context("parse DoH JSON")?;
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
    Ok(true)
}

async fn detect_public_ip(client: &reqwest::Client, providers: &[String]) -> Result<String> {
    let mut last_err: Option<anyhow::Error> = None;
    for p in providers {
        match fetch_ip_from(client, p).await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                warn!(provider = %p, error = %e, "ip provider failed, trying next");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no ip providers configured")))
}

async fn fetch_ip_from(client: &reqwest::Client, provider: &str) -> Result<String> {
    let url = match provider {
        // Echo plain-text IPv4
        "ifconfig.co" | "ifconfig.me" | "api.ipify.org" | "icanhazip.com" | "checkip.amazonaws.com" => {
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
