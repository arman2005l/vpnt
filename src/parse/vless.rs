//! Parse vless:// share links into sing-box outbound JSON.
//!
//! Supported:
//!   - Transport: tcp, ws, grpc, httpupgrade
//!   - TLS: none, tls, reality (with utls fingerprint)
//!   - Flow: xtls-rprx-vision
//!
//! Rejected with a clear error:
//!   - Transport: xhttp (not supported by sing-box)

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use url::Url;

use super::{build_tls, build_transport, url_decode};

pub fn parse(raw: &str) -> Result<(String, Value)> {
    let url = Url::parse(raw).context("invalid vless:// URL")?;

    // ── uuid (user info) ──────────────────────────────────────────────────────
    let uuid = url.username();
    if uuid.is_empty() {
        bail!("vless: missing UUID in userinfo");
    }

    // ── server / port ─────────────────────────────────────────────────────────
    let server = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("vless: missing host"))?;
    let port = url
        .port()
        .ok_or_else(|| anyhow::anyhow!("vless: missing port"))?;

    // ── query params ──────────────────────────────────────────────────────────
    let params = query_map(&url);

    let security = params.get("security").map(|s| s.as_str()).unwrap_or("none");
    let net = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let sni = params.get("sni").cloned().unwrap_or_default();
    let fp = params.get("fp").cloned().unwrap_or_default();
    let pb = params.get("pbk").cloned().unwrap_or_default();  // reality public key
    let sid = params.get("sid").cloned().unwrap_or_default(); // reality short ID
    let path = params.get("path").cloned().unwrap_or_default();
    let host = params.get("host").cloned().unwrap_or_default();
    let service_name = params.get("serviceName").cloned().unwrap_or_default();
    let flow = params.get("flow").cloned().unwrap_or_default();

    // ── transport ─────────────────────────────────────────────────────────────
    let transport = build_transport(net, &path, &host, &service_name)
        .with_context(|| format!("vless: transport {net}"))?;

    // ── TLS ───────────────────────────────────────────────────────────────────
    let tls = build_tls(security, &sni, &fp, &pb, &sid);

    // ── display name ──────────────────────────────────────────────────────────
    let name = url
        .fragment()
        .map(url_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("vless@{server}:{port}"));

    // ── outbound ──────────────────────────────────────────────────────────────
    let mut outbound = json!({
        "type": "vless",
        "tag": name,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "packet_encoding": "xudp",
    });

    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }

    if let Some(tls_val) = tls {
        outbound["tls"] = tls_val;
    }

    if let Some(transport_val) = transport {
        outbound["transport"] = transport_val;
    }

    Ok((name, outbound))
}

/// Collect all query params into a HashMap (last value wins for duplicates).
fn query_map(url: &Url) -> std::collections::HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_tcp_tls() {
        let link = "vless://abcd1234-0000-0000-0000-000000000000@1.2.3.4:443?\
                    security=tls&sni=example.com&fp=chrome&type=tcp#My%20Proxy";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "My Proxy");
        assert_eq!(ob["type"], "vless");
        assert_eq!(ob["server"], "1.2.3.4");
        assert_eq!(ob["server_port"], 443);
        assert_eq!(ob["uuid"], "abcd1234-0000-0000-0000-000000000000");
        assert_eq!(ob["tls"]["enabled"], true);
        assert_eq!(ob["tls"]["server_name"], "example.com");
        assert_eq!(ob["tls"]["utls"]["fingerprint"], "chrome");
        assert!(ob.get("transport").is_none());
    }

    #[test]
    fn test_vless_ws_tls() {
        let link = "vless://uuid@host.example:8443?\
                    security=tls&sni=host.example&type=ws&path=%2Fwspath&host=host.example#ws-node";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "ws-node");
        assert_eq!(ob["transport"]["type"], "ws");
        assert_eq!(ob["transport"]["path"], "/wspath");
        assert_eq!(ob["transport"]["headers"]["Host"], "host.example");
    }

    #[test]
    fn test_vless_grpc_reality() {
        let link = "vless://uuid@host.example:443?\
                    security=reality&pbk=PUBLICKEY&sid=abc123&sni=host.example\
                    &fp=safari&type=grpc&serviceName=myservice#grpc-node";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "grpc-node");
        assert_eq!(ob["tls"]["reality"]["enabled"], true);
        assert_eq!(ob["tls"]["reality"]["public_key"], "PUBLICKEY");
        assert_eq!(ob["tls"]["reality"]["short_id"], "abc123");
        assert_eq!(ob["transport"]["type"], "grpc");
        assert_eq!(ob["transport"]["service_name"], "myservice");
    }

    #[test]
    fn test_vless_xhttp_rejected() {
        let link = "vless://uuid@host.example:443?type=xhttp#bad";
        assert!(parse(link).is_err());
        let err = parse(link).unwrap_err().to_string();
        assert!(err.contains("xhttp"), "error should mention xhttp: {err}");
    }

    #[test]
    fn test_vless_flow() {
        let link = "vless://uuid@host.example:443?\
                    security=reality&pbk=PK&sid=s&sni=h&fp=chrome\
                    &flow=xtls-rprx-vision#flow-test";
        let (_, ob) = parse(link).unwrap();
        assert_eq!(ob["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn test_vless_missing_uuid() {
        let link = "vless://@1.2.3.4:443?type=tcp#test";
        assert!(parse(link).is_err());
    }

    #[test]
    fn test_vless_default_name() {
        let link = "vless://uuid@1.2.3.4:443?type=tcp";
        let (name, _) = parse(link).unwrap();
        assert_eq!(name, "vless@1.2.3.4:443");
    }
}
