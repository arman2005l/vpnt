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
