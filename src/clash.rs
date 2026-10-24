//! Minimal Clash API client for the sing-box `experimental.clash_api`.
//!
//! Endpoints used:
//! * `GET /traffic` – streaming response, one JSON object per line per second.
//! * `GET /connections` – snapshot of open connections.
//! * `GET /proxies/{name}/delay` – URL delay test through one outbound.
//!
//! JSON parsing lives in free functions so it can be unit-tested with
//! fixtures and no network access.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;

/// Outbound tag the generator gives to the selected config.
pub const PROXY_TAG: &str = "proxy";

/// URL used by the delay test.
pub const DELAY_TEST_URL: &str = "https://www.gstatic.com/generate_204";

/// Delay test timeout passed to sing-box, in milliseconds.
pub const DELAY_TIMEOUT_MS: u64 = 5000;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

// ── Parsed data ───────────────────────────────────────────────────────────────

/// One `/traffic` sample, in bytes per second.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct Traffic {
    #[serde(default)]
    pub up: u64,
    #[serde(default)]
    pub down: u64,
}

/// Digest of a `/connections` snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionsSummary {
    /// Number of open connections.
    pub count: usize,
    /// Bytes uploaded since sing-box started.
    pub upload_total: u64,
    /// Bytes downloaded since sing-box started.
    pub download_total: u64,
    /// `(process name, connection count)`, most connections first.
    pub per_process: Vec<(String, usize)>,
}

#[derive(Debug, Deserialize)]
struct RawConnections {
    #[serde(default, rename = "uploadTotal")]
    upload_total: u64,
    #[serde(default, rename = "downloadTotal")]
    download_total: u64,
    #[serde(default)]
    connections: Option<Vec<RawConnection>>,
}

#[derive(Debug, Deserialize)]
struct RawConnection {
    #[serde(default)]
    metadata: RawMetadata,
}

#[derive(Debug, Default, Deserialize)]
struct RawMetadata {
    #[serde(default, rename = "processPath")]
    process_path: String,
}

/// Parse one line of the `/traffic` stream.
pub fn parse_traffic_line(line: &str) -> Result<Traffic> {
    serde_json::from_str(line.trim()).context("invalid /traffic line")
}

/// Parse a `/connections` body.
pub fn parse_connections(body: &str) -> Result<ConnectionsSummary> {
    let raw: RawConnections = serde_json::from_str(body).context("invalid /connections body")?;
    let conns = raw.connections.unwrap_or_default();

    let mut counts: HashMap<String, usize> = HashMap::new();
    for conn in &conns {
        let name = process_label(&conn.metadata.process_path);
        *counts.entry(name).or_insert(0) += 1;
    }
    let mut per_process: Vec<(String, usize)> = counts.into_iter().collect();
    per_process.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    Ok(ConnectionsSummary {
        count: conns.len(),
        upload_total: raw.upload_total,
        download_total: raw.download_total,
        per_process,
    })
}

/// Parse a `/proxies/{name}/delay` body into milliseconds.
pub fn parse_delay(body: &str) -> Result<u64> {
    let value: Value = serde_json::from_str(body).context("invalid delay response")?;
    if let Some(ms) = value.get("delay").and_then(|d| d.as_u64()) {
        if ms > 0 {
            return Ok(ms);
        }
    }
    let msg = value
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("delay test failed");
    bail!("{msg}")
}

/// Short process name from a full `processPath`; "unknown" when empty.
pub fn process_label(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return "unknown".to_string();
    }
    path.rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

/// Splits a byte stream into complete lines and keeps any partial tail.
#[derive(Debug, Default)]
pub struct LineBuffer {
    buf: Vec<u8>,
}

impl LineBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a chunk and return every complete, non-empty line.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut lines = Vec::new();
        while let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&line).trim().to_string();
            if !text.is_empty() {
                lines.push(text);
            }
        }
        lines
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Clash API endpoint plus secret.  Cheap to clone.
#[derive(Clone)]
pub struct ClashApi {
    /// e.g. `http://127.0.0.1:43210`
    pub base_url: String,
    secret: String,
    client: Client,
}

impl std::fmt::Debug for ClashApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("ClashApi").field("base_url", &self.base_url).finish()
    }
}

impl ClashApi {
    pub fn new(controller: &str, secret: &str) -> Result<Self> {
        let controller = controller.trim();
        if controller.is_empty() {
            bail!("clash_api external_controller is empty");
        }
        let client = Client::builder()
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("failed to build Clash API client")?;
        Ok(Self {
            base_url: format!("http://{controller}"),
            secret: secret.to_string(),
            client,
        })
    }

    /// Read `experimental.clash_api` from a generated sing-box config.
    pub fn from_config(config: &Value) -> Result<Self> {
        let api = config
            .get("experimental")
            .and_then(|e| e.get("clash_api"))
            .context("config has no experimental.clash_api")?;
        let controller = api
            .get("external_controller")
            .and_then(|c| c.as_str())
            .context("clash_api has no external_controller")?;
        let secret = api.get("secret").and_then(|s| s.as_str()).unwrap_or("");
        Self::new(controller, secret)
    }

    /// Read `experimental.clash_api` from a config file on disk.
    pub fn from_config_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: Value = serde_json::from_str(&text).context("config is not valid JSON")?;
        Self::from_config(&config)
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        if !self.secret.is_empty() {
            req = req.bearer_auth(&self.secret);
        }
        req
    }

    /// Snapshot of open connections.
    pub async fn connections(&self) -> Result<ConnectionsSummary> {
        let body = self
            .get("/connections")
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .context("GET /connections failed")?
            .error_for_status()?
            .text()
            .await?;
        parse_connections(&body)
    }

    /// URL delay test through the outbound tagged `proxy_tag`, in ms.
    pub async fn delay(&self, proxy_tag: &str) -> Result<u64> {
        let timeout = DELAY_TIMEOUT_MS.to_string();
        let resp = self
            .get(&format!("/proxies/{proxy_tag}/delay"))
            .query(&[("timeout", timeout.as_str()), ("url", DELAY_TEST_URL)])
            .timeout(Duration::from_millis(DELAY_TIMEOUT_MS) + Duration::from_secs(2))
            .send()
            .await
            .context("delay test request failed")?;
        // Failures also come back as JSON with a "message".
        let body = resp.text().await?;
        parse_delay(&body)
    }

    /// Stream `/traffic` samples into `tx`.  Returns `Ok(())` once the
    /// receiver is dropped, or an error when the stream breaks.
    pub async fn stream_traffic(&self, tx: mpsc::UnboundedSender<Traffic>) -> Result<()> {
        let mut resp = self
            .get("/traffic")
            .send()
            .await
            .context("GET /traffic failed")?
            .error_for_status()?;
        let mut lines = LineBuffer::new();
        while let Some(chunk) = resp.chunk().await? {
            for line in lines.push(&chunk) {
                match parse_traffic_line(&line) {
                    Ok(sample) => {
                        if tx.send(sample).is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => tracing::debug!("skipping traffic line: {e}"),
                }
            }
        }
        bail!("/traffic stream ended")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRAFFIC: &str = include_str!("fixtures/clash_traffic.txt");
    const CONNECTIONS: &str = include_str!("fixtures/clash_connections.json");
    const DELAY: &str = include_str!("fixtures/clash_delay.json");
    const DELAY_ERROR: &str = include_str!("fixtures/clash_delay_error.json");

    #[test]
    fn traffic_lines_parse() {
        let samples: Vec<Traffic> = TRAFFIC
            .lines()
            .map(|l| parse_traffic_line(l).unwrap())
            .collect();
        assert_eq!(samples.len(), 3);
        assert_eq!(samples[1], Traffic { up: 1024, down: 20480 });
    }

    #[test]
    fn traffic_bad_line_is_error() {
        assert!(parse_traffic_line("not json").is_err());
    }

    #[test]
    fn line_buffer_handles_split_chunks() {
        let bytes = TRAFFIC.as_bytes();
        let mut lb = LineBuffer::new();
        let mut all = Vec::new();
        for chunk in bytes.chunks(7) {
            all.extend(lb.push(chunk));
        }
        assert_eq!(all.len(), 3);
        assert_eq!(parse_traffic_line(&all[2]).unwrap(), Traffic { up: 512, down: 4096 });
    }

    #[test]
    fn connections_counts_per_process() {
        let s = parse_connections(CONNECTIONS).unwrap();
        assert_eq!(s.count, 5);
        assert_eq!(s.upload_total, 65536);
        assert_eq!(s.download_total, 1048576);
        assert_eq!(s.per_process[0], ("firefox".to_string(), 2));
        assert_eq!(s.per_process[1], ("unknown".to_string(), 2));
        assert_eq!(s.per_process[2], ("curl".to_string(), 1));
    }

    #[test]
    fn connections_null_list() {
        let s = parse_connections(r#"{"downloadTotal":0,"uploadTotal":0,"connections":null}"#)
            .unwrap();
        assert_eq!(s.count, 0);
        assert!(s.per_process.is_empty());
    }

    #[test]
    fn delay_ok_and_error() {
        assert_eq!(parse_delay(DELAY).unwrap(), 187);
        let err = parse_delay(DELAY_ERROR).unwrap_err().to_string();
        assert!(err.contains("delay test"));
    }

    #[test]
    fn from_config_reads_generator_output() {
        let cfg = serde_json::json!({
            "experimental": { "clash_api": {
                "external_controller": "127.0.0.1:45678",
                "secret": "s3cret"
            }}
        });
        let api = ClashApi::from_config(&cfg).unwrap();
        assert_eq!(api.base_url, "http://127.0.0.1:45678");
        assert!(!format!("{api:?}").contains("s3cret"));
        assert!(ClashApi::from_config(&serde_json::json!({})).is_err());
    }

    #[test]
    fn process_label_variants() {
        assert_eq!(process_label("/usr/bin/curl"), "curl");
        assert_eq!(process_label("C:\\Apps\\app.exe"), "app.exe");
        assert_eq!(process_label(""), "unknown");
    }
}
