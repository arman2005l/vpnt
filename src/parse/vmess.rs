//! Parse vmess:// share links into sing-box outbound JSON.
//!
//! vmess:// links are base64-encoded JSON objects (V2RayN format).
//! Expected fields: v, ps, add, port, id, aid, scy, net, type, host,
//!                  path, tls, sni, alpn, fp

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{build_tls, build_transport};

/// Raw deserialized vmess JSON.
#[derive(Debug, Deserialize)]
struct VmessJson {
    /// Display name
    #[serde(default, rename = "ps")]
    ps: String,
    /// Server address
    #[serde(rename = "add")]
    add: String,
    /// Server port (may come as string or number)
    #[serde(rename = "port", deserialize_with = "de_port")]
    port: u16,
    /// User UUID
    #[serde(rename = "id")]
    id: String,
    /// Alter ID (legacy, 0 for AEAD)
    #[serde(default, rename = "aid", deserialize_with = "de_u16_or_str")]
    aid: u16,
    /// Security / cipher
    #[serde(default, rename = "scy")]
    scy: String,
    /// Network type: tcp, ws, grpc, httpupgrade
    #[serde(default, rename = "net")]
    net: String,
    /// Header type (obfs), usually "none" or "http"
    #[serde(default, rename = "type")]
    type_: String,
    /// Host header (ws) or service name (grpc)
    #[serde(default, rename = "host")]
    host: String,
    /// Path (ws / httpupgrade)
    #[serde(default, rename = "path")]
    path: String,
    /// TLS: "tls" | "reality" | ""
    #[serde(default, rename = "tls")]
    tls: String,
    /// SNI
    #[serde(default, rename = "sni")]
    sni: String,
    /// uTLS fingerprint
    #[serde(default, rename = "fp")]
    fp: String,
    /// ALPN (comma-separated string or JSON array — we ignore it; sing-box picks it)
    #[serde(default, rename = "alpn")]
    _alpn: Value,
}

pub fn parse(raw: &str) -> Result<(String, Value)> {
    // Strip the "vmess://" prefix and base64-decode.
    let encoded = raw
        .strip_prefix("vmess://")
        .ok_or_else(|| anyhow::anyhow!("vmess: missing scheme"))?;

    // Some clients pad, some don't. Try standard first, then URL-safe.
    let bytes = decode_b64(encoded)
        .context("vmess: base64 decode failed")?;

    let v: VmessJson = serde_json::from_slice(&bytes)
        .context("vmess: JSON decode failed")?;

    if v.add.is_empty() {
        bail!("vmess: missing server address");
    }
    if v.id.is_empty() {
        bail!("vmess: missing UUID");
    }

    let net = if v.net.is_empty() { "tcp" } else { v.net.as_str() };
    let security = if v.tls.is_empty() { "none" } else { v.tls.as_str() };

    // For grpc the "host" field carries the service name in some clients.
    let service_name = if net == "grpc" { &v.host } else { "" };

    let transport = build_transport(net, &v.path, &v.host, service_name)
        .with_context(|| format!("vmess: transport {net}"))?;

    let tls = build_tls(security, &v.sni, &v.fp, "", "");

    let cipher = if v.scy.is_empty() {
        "auto".to_string()
    } else {
        v.scy.clone()
    };

    let name = if v.ps.is_empty() {
        format!("vmess@{}:{}", v.add, v.port)
    } else {
        v.ps.clone()
    };

    let mut outbound = json!({
        "type": "vmess",
        "tag": name,
        "server": v.add,
        "server_port": v.port,
        "uuid": v.id,
        "security": cipher,
        "alter_id": v.aid,
        "packet_encoding": "xudp",
    });

    if let Some(tls_val) = tls {
        outbound["tls"] = tls_val;
    }
    if let Some(transport_val) = transport {
        outbound["transport"] = transport_val;
    }

    Ok((name, outbound))
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::engine::general_purpose::STANDARD_NO_PAD;

    // Try all four common variants in order.
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE.decode(s)
        })
        .context("all base64 variants failed")
}

// Port can arrive as either a JSON number or a quoted string.
fn de_port<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u16, D::Error> {
    let v: Value = serde::Deserialize::deserialize(d)?;
    match &v {
        Value::Number(n) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| serde::de::Error::custom("invalid port number")),
        Value::String(s) => s
            .parse::<u16>()
            .map_err(|_| serde::de::Error::custom(format!("invalid port string: {s}"))),
        _ => Err(serde::de::Error::custom("port must be number or string")),
    }
}

// alter_id similarly can be a number or a string.
fn de_u16_or_str<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u16, D::Error> {
    let v: Value = serde::Deserialize::deserialize(d)?;
    match &v {
        Value::Number(n) => Ok(n.as_u64().unwrap_or(0) as u16),
        Value::String(s) => Ok(s.parse::<u16>().unwrap_or(0)),
        Value::Null => Ok(0),
        _ => Ok(0),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_link(json: &str) -> String {
        let encoded = STANDARD.encode(json.as_bytes());
        format!("vmess://{encoded}")
    }

    #[test]
    fn test_vmess_tcp_basic() {
        let link = make_link(r#"{
            "v":"2","ps":"my-vmess","add":"1.2.3.4","port":"443",
            "id":"abcd-1234","aid":"0","scy":"auto",
            "net":"tcp","type":"none","host":"","path":"",
            "tls":"tls","sni":"1.2.3.4","fp":"chrome"
        }"#);
        let (name, ob) = parse(&link).unwrap();
        assert_eq!(name, "my-vmess");
        assert_eq!(ob["type"], "vmess");
        assert_eq!(ob["server"], "1.2.3.4");
        assert_eq!(ob["server_port"], 443);
        assert_eq!(ob["uuid"], "abcd-1234");
        assert_eq!(ob["tls"]["enabled"], true);
    }

    #[test]
    fn test_vmess_ws() {
        let link = make_link(r#"{
            "ps":"ws-node","add":"example.com","port":8080,
            "id":"uuid","aid":0,"net":"ws","path":"/ws","host":"example.com",
            "tls":"","sni":"","fp":""
        }"#);
        let (name, ob) = parse(&link).unwrap();
        assert_eq!(name, "ws-node");
        assert_eq!(ob["transport"]["type"], "ws");
        assert_eq!(ob["transport"]["path"], "/ws");
        assert!(ob.get("tls").is_none());
    }

    #[test]
    fn test_vmess_port_as_number() {
        let link = make_link(r#"{"ps":"n","add":"h.com","port":1234,"id":"u","net":"tcp"}"#);
        let (_, ob) = parse(&link).unwrap();
        assert_eq!(ob["server_port"], 1234);
    }

    #[test]
    fn test_vmess_missing_server() {
        let link = make_link(r#"{"ps":"n","add":"","port":443,"id":"u"}"#);
        assert!(parse(&link).is_err());
    }

    #[test]
    fn test_vmess_xhttp_rejected() {
        let link = make_link(r#"{"ps":"x","add":"h.com","port":443,"id":"u","net":"xhttp"}"#);
        assert!(parse(&link).is_err());
    }

    #[test]
    fn test_vmess_default_name() {
        let link = make_link(r#"{"ps":"","add":"1.2.3.4","port":443,"id":"u","net":"tcp"}"#);
        let (name, _) = parse(&link).unwrap();
        assert_eq!(name, "vmess@1.2.3.4:443");
    }
}
