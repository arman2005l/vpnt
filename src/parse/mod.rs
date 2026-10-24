//! Link-parsing entry point and shared helpers.

pub mod hysteria2;
pub mod ss;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;

use anyhow::{bail, Result};
use serde_json::Value;

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse any supported share link into `(display_name, sing-box outbound JSON)`.
/// Also accepts a raw sing-box outbound JSON object.
pub fn parse_link(raw: &str) -> Result<(String, Value)> {
    let raw = raw.trim();

    if raw.starts_with("vless://") {
        vless::parse(raw)
    } else if raw.starts_with("vmess://") {
        vmess::parse(raw)
    } else if raw.starts_with("trojan://") {
        trojan::parse(raw)
    } else if raw.starts_with("ss://") {
        ss::parse(raw)
    } else if raw.starts_with("hysteria2://") || raw.starts_with("hy2://") {
        hysteria2::parse(raw)
    } else if raw.starts_with("tuic://") {
        tuic::parse(raw)
    } else if raw.starts_with('{') {
        parse_raw_json(raw)
    } else {
        let scheme: String = match raw.find("://") {
            Some(end) => raw[..end].chars().take(20).collect(),
            None => raw.chars().take(20).collect(),
        };
        bail!("Unsupported link scheme: {scheme}");
    }
}

fn parse_raw_json(raw: &str) -> Result<(String, Value)> {
    let v: Value = serde_json::from_str(raw)?;
    let name = v
        .get("tag")
        .and_then(|t| t.as_str())
        .unwrap_or("imported")
        .to_string();
    Ok((name, v))
}

// ── Shared TLS builder ────────────────────────────────────────────────────────

/// Build a sing-box `tls` block.  Returns `None` when security is "none"/empty.
pub fn build_tls(
    security: &str,
    sni: &str,
    fingerprint: &str,
    reality_pk: &str,
    reality_sid: &str,
) -> Option<Value> {
    if security != "tls" && security != "reality" {
        return None;
    }

    let mut tls = serde_json::json!({
        "enabled": true,
        "server_name": sni,
    });

    if !fingerprint.is_empty() {
        tls["utls"] = serde_json::json!({
            "enabled": true,
            "fingerprint": fingerprint,
        });
    }

    if security == "reality" {
        tls["reality"] = serde_json::json!({
            "enabled": true,
            "public_key": reality_pk,
            "short_id": reality_sid,
        });
    }

    Some(tls)
}

// ── Shared transport builder ──────────────────────────────────────────────────

/// Build a sing-box `transport` block.  Returns `None` for plain TCP.
pub fn build_transport(
    net: &str,
    path: &str,
    host: &str,
    service_name: &str,
) -> Result<Option<Value>> {
    let path = if path.is_empty() { "/" } else { path };

    match net {
        "tcp" | "" => Ok(None),
        "ws" => {
            let headers = if host.is_empty() {
                serde_json::json!({})
            } else {
                serde_json::json!({ "Host": host })
            };
            Ok(Some(serde_json::json!({
                "type": "ws",
                "path": path,
                "headers": headers,
            })))
        }
        "grpc" => Ok(Some(serde_json::json!({
            "type": "grpc",
            "service_name": service_name,
        }))),
        "httpupgrade" => Ok(Some(serde_json::json!({
            "type": "httpupgrade",
            "path": path,
            "host": host,
        }))),
        "xhttp" => bail!("Transport type 'xhttp' is not supported by sing-box"),
        other => bail!("Unsupported transport type: {}", other),
    }
}

// ── Percent-decode helper ─────────────────────────────────────────────────────

/// Minimal percent-decoder for config names/fragments (UTF-8, best-effort).
pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode_plain() {
        assert_eq!(url_decode("hello"), "hello");
    }

    #[test]
    fn test_url_decode_percent() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("caf%C3%A9"), "café");
    }

    #[test]
    fn test_raw_json() {
        let json = r#"{"type":"vless","tag":"my-proxy","server":"1.2.3.4","server_port":443,"uuid":"abc"}"#;
        let (name, v) = parse_link(json).unwrap();
        assert_eq!(name, "my-proxy");
        assert_eq!(v["type"], "vless");
    }

    #[test]
    fn test_unsupported_scheme() {
        assert!(parse_link("http://example.com").is_err());
    }

    #[test]
    fn test_garbage_non_ascii_does_not_panic() {
        assert!(parse_link("ççççççççççççççççççççç").is_err());
        assert!(parse_link("not a link").is_err());
    }
}
