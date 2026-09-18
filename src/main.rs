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
    /// How often to refresh the public IP and trigger an update.
    #[serde(default = "default_update_interval_secs")]
    update_interval_secs: u64,
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

fn default_update_interval_secs() -> u64 {
    300
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
    /// Last public IP we successfully saw (for log noise reduction).
    last_ip: Option<String>,
    /// Last successful IONOS response timestamp.
    last_success: Option<chrono::DateTime<chrono::Utc>>,
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
        update_secs = cfg.update_interval_secs,
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

    // Initial update cycle (no waiting on the interval).
    if let Err(e) = run_cycle(&client, &cfg, &mut state).await {
        warn!(error = %e, "initial update cycle failed");
    }
    persist_state(&cfg.state_file, &state).await.ok();

    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.update_interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        if let Err(e) = run_cycle(&client, &cfg, &mut state).await {
            warn!(error = %e, "update cycle failed");
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

async fn run_cycle(
    client: &reqwest::Client,
    cfg: &Config,
    state: &mut State,
) -> Result<()> {
    let ip = detect_public_ip(client, &cfg.ip_providers).await?;
    info!(%ip, last = ?state.last_ip, "detected public IPv4");
    let changed = state.last_ip.as_deref() != Some(ip.as_str());
    if !changed && !state.update_urls.is_empty() {
        info!("ip unchanged, skipping IONOS update");
        return Ok(());
    }

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

    if let Some(update_url) = parsed.update_url {
        for d in &cfg.domains {
            state.update_urls.insert(d.clone(), update_url.clone());
        }
        info!(%update_url, "cached updateUrl for next cycles");
    } else {
        // Fall back to the canonical update URL pattern (token-less). IONOS
        // always returns one for fresh activations; missing means the
        // subdomain is already configured and not returning it again.
        warn!("IONOS response missing updateUrl; will retry next cycle");
    }

    state.last_ip = Some(ip);
    state.last_success = Some(chrono::Utc::now());
    Ok(())
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
