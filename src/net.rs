//! Network helpers: subscription fetching and proxy reachability tests.
//!
//! M1 scope: fetch a raw subscription URL and parse it into URI lines;
//! ping a TCP endpoint and return round-trip time.  No retry logic yet –
//! that comes in M2 alongside the connection-quality poller.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::Client;
use tokio::net::TcpStream;
use tracing::{debug, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Hard ceiling on how long we wait for a subscription fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// Hard ceiling for a single TCP reachability probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

// ── Client construction ───────────────────────────────────────────────────────

/// Build a one-shot `reqwest::Client` suitable for subscription fetches.
///
/// We do not cache the client because fetches are infrequent (user-triggered).
fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("vpnt/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")
}

// ── Subscription fetch ────────────────────────────────────────────────────────

/// Download a subscription URL and return the decoded, non-empty lines.
///
/// Subscriptions are either plain text (one URI per line) or base64-encoded
/// plain text.  We try base64 first; if that fails we treat the body as-is.
pub async fn fetch_subscription(url: &str) -> Result<Vec<String>> {
    let url = url.trim();
    if url.is_empty() {
        bail!("subscription URL is empty");
    }

    debug!("fetching subscription: {url}");

    let client = build_client()?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url} failed"))?;

    let status = response.status();
    if !status.is_success() {
        bail!("subscription server returned {status}");
    }

    let body = response
        .text()
        .await
        .context("failed to read subscription body")?;

    let lines = decode_subscription_body(&body);

    if lines.is_empty() {
        bail!("subscription returned no usable proxy URIs");
    }

    debug!("subscription returned {} URIs", lines.len());
    Ok(lines)
}

/// Decode a raw subscription body into a list of URI strings.
///
/// Attempts base64 decode first; falls through to plain text on any error.
fn decode_subscription_body(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();

    // Try base64 (standard + URL-safe; ignore padding errors).
    use base64::Engine as _;
    let decoded_attempt = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed));

    let text = match decoded_attempt {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) if looks_like_uri_list(&s) => s,
            _ => {
                warn!("base64 decode succeeded but output is not a URI list; using raw body");
                trimmed.to_owned()
            }
        },
        Err(_) => trimmed.to_owned(),
    };

    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// Heuristic: does the string look like a list of proxy URIs?
fn looks_like_uri_list(s: &str) -> bool {
    s.lines().any(|l| {
        let l = l.trim();
        l.starts_with("vless://")
            || l.starts_with("vmess://")
            || l.starts_with("trojan://")
            || l.starts_with("ss://")
    })
}

// ── TCP reachability probe ────────────────────────────────────────────────────

/// Result of a single TCP probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub addr:    SocketAddr,
    pub rtt_ms:  u64,
    pub success: bool,
}

/// Attempt a TCP connection to `addr` and return the round-trip time in ms.
///
/// Returns `Ok(ProbeResult { success: false, … })` for timeouts; only hard
/// I/O errors produce `Err`.
pub async fn tcp_probe(addr: SocketAddr) -> Result<ProbeResult> {
    let start = Instant::now();

    let outcome = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await;

    let rtt_ms = start.elapsed().as_millis() as u64;

    match outcome {
        Ok(Ok(_stream)) => {
            // Connection established; stream drops immediately (we only need RTT).
            debug!("probe {addr} ok  {rtt_ms} ms");
            Ok(ProbeResult { addr, rtt_ms, success: true })
        }
        Ok(Err(e)) => {
            warn!("probe {addr} refused: {e}");
            Ok(ProbeResult { addr, rtt_ms, success: false })
        }
        Err(_timeout) => {
            warn!("probe {addr} timed out after {rtt_ms} ms");
            Ok(ProbeResult { addr, rtt_ms, success: false })
        }
    }
}

/// Convenience wrapper: resolve `host:port` and probe the first address.
pub async fn probe_host(host: &str, port: u16) -> Result<ProbeResult> {
    use tokio::net::lookup_host;

    let target = format!("{host}:{port}");
    let mut addrs = lookup_host(&target)
        .await
        .with_context(|| format!("DNS lookup failed for {target}"))?;

    let addr = addrs
        .next()
        .with_context(|| format!("no addresses resolved for {target}"))?;

    tcp_probe(addr).await
}

// ── TCP ping ──────────────────────────────────────────────────────────────────

/// Default timeout for `tcp_ping` / `ping_all`.
pub const PING_TIMEOUT: Duration = Duration::from_secs(3);

// ── Exit IP ───────────────────────────────────────────────────────────────────

/// Plain-text "what is my IP" endpoint.
pub const EXIT_IP_URL: &str = "https://api.ipify.org";

/// Timeout for one exit-IP request through the local proxy.
pub const EXIT_IP_TIMEOUT: Duration = Duration::from_secs(10);

/// Find the local HTTP-capable inbound in a generated sing-box config and
/// return it as a proxy URL (`http://127.0.0.1:<port>`).
/// Prefers a `mixed` inbound, falls back to `http`.
pub fn local_http_proxy_url(config: &serde_json::Value) -> Option<String> {
    let inbounds = config.get("inbounds")?.as_array()?;
    for wanted in ["mixed", "http"] {
        for inbound in inbounds {
            if inbound.get("type").and_then(|t| t.as_str()) != Some(wanted) {
                continue;
            }
            let Some(port) = inbound.get("listen_port").and_then(|p| p.as_u64()) else {
                continue;
            };
            let listen = inbound
                .get("listen")
                .and_then(|l| l.as_str())
                .filter(|l| !l.is_empty() && *l != "0.0.0.0" && *l != "::")
                .unwrap_or("127.0.0.1");
            let host = if listen.contains(':') { format!("[{listen}]") } else { listen.to_string() };
            return Some(format!("http://{host}:{port}"));
        }
    }
    None
}

/// Fetch the public exit IP through `proxy_url` (an HTTP proxy), so the result
/// does not depend on TUN routing.
pub async fn fetch_exit_ip(proxy_url: &str) -> Result<String> {
    let proxy = reqwest::Proxy::all(proxy_url).context("invalid local proxy URL")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(EXIT_IP_TIMEOUT)
        .user_agent(concat!("vpnt/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")?;
    let body = client
        .get(EXIT_IP_URL)
        .send()
        .await
        .context("exit IP request failed")?
        .error_for_status()?
        .text()
        .await?;
    let ip = body.trim();
    ip.parse::<std::net::IpAddr>()
        .with_context(|| format!("unexpected exit IP response ({} bytes)", ip.len()))?;
    Ok(ip.to_string())
}

/// One target for `ping_all`: an opaque id plus `host:port`.
#[derive(Debug, Clone)]
pub struct PingTarget {
    pub id: String,
    pub host: String,
    pub port: u16,
}

/// Measure TCP connect time (DNS lookup included) to `host:port`.
/// Returns `None` on DNS failure, refusal or timeout.
pub async fn tcp_ping(host: &str, port: u16, timeout: Duration) -> Option<u64> {
    let target = format!("{host}:{port}");
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(target.clone())).await {
        Ok(Ok(_stream)) => {
            let ms = start.elapsed().as_millis() as u64;
            debug!("ping {target} ok {ms} ms");
            Some(ms)
        }
        Ok(Err(e)) => {
            debug!("ping {target} failed: {e}");
            None
        }
        Err(_) => {
            debug!("ping {target} timed out");
            None
        }
    }
}

/// Ping every target concurrently. Results come back in input order.
pub async fn ping_all(targets: Vec<PingTarget>, timeout: Duration) -> Vec<(String, Option<u64>)> {
    let mut handles = Vec::new();
    for t in targets {
        handles.push(tokio::spawn(async move {
            let ms = tcp_ping(&t.host, t.port, timeout).await;
            (t.id, ms)
        }));
    }
    let mut out = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            out.push(result);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let results = ping_all(
            vec![PingTarget { id: "a".into(), host: "127.0.0.1".into(), port }],
            PING_TIMEOUT,
        )
        .await;
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_some());
    }

    #[test]
    fn local_proxy_prefers_mixed_then_http() {
        let mixed = serde_json::json!({ "inbounds": [
            { "type": "http", "listen": "127.0.0.1", "listen_port": 1 },
            { "type": "mixed", "listen": "127.0.0.1", "listen_port": 2 }
        ]});
        assert_eq!(local_http_proxy_url(&mixed).as_deref(), Some("http://127.0.0.1:2"));
        let none = serde_json::json!({ "inbounds": [{ "type": "tun" }] });
        assert_eq!(local_http_proxy_url(&none), None);
    }

    #[test]
    fn local_proxy_found_in_generated_config() {
        let proxy = crate::ui::app::proxy_from_link("hy2://pass@1.2.3.4:443#t").unwrap();
        let settings = crate::config::Settings::default();
        let config = crate::gen::build(&proxy, &settings).unwrap();
        assert!(local_http_proxy_url(&config).is_some());
        assert!(crate::clash::ClashApi::from_config(&config).is_ok());
    }
}
