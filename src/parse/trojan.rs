//! Parse trojan:// share links into sing-box outbound JSON.
//!
//! Format: trojan://<password>@<host>:<port>?<params>#<name>
//! Supported transports: tcp, ws, grpc, httpupgrade
//! TLS is always enabled for trojan (the protocol requires it).

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use url::Url;

use super::{build_tls, build_transport, url_decode};

pub fn parse(raw: &str) -> Result<(String, Value)> {
    let url = Url::parse(raw).context("invalid trojan:// URL")?;

    let password = url.username();
    if password.is_empty() {
        bail!("trojan: missing password in userinfo");
    }
    // URL-decode the password (some clients percent-encode special chars)
    let password = url_decode(password);

    let server = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("trojan: missing host"))?;
    let port = url
        .port()
        .ok_or_else(|| anyhow::anyhow!("trojan: missing port"))?;

    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let security = params.get("security").map(|s| s.as_str()).unwrap_or("tls");
    let net = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let sni = params.get("sni").cloned().unwrap_or_else(|| server.to_string());
    let fp = params.get("fp").cloned().unwrap_or_default();
    let pb = params.get("pbk").cloned().unwrap_or_default();
    let sid = params.get("sid").cloned().unwrap_or_default();
    let path = params.get("path").cloned().unwrap_or_default();
    let host = params.get("host").cloned().unwrap_or_default();
    let service_name = params.get("serviceName").cloned().unwrap_or_default();

    let transport = build_transport(net, &path, &host, &service_name)
        .with_context(|| format!("trojan: transport {net}"))?;

    // Trojan always uses TLS; fall back to plain "tls" if param is absent/none.
    let effective_security = match security {
        "none" | "" => "tls",
        other => other,
    };
    let tls = build_tls(effective_security, &sni, &fp, &pb, &sid);

    let name = url
        .fragment()
        .map(|f| url_decode(f))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("trojan@{server}:{port}"));

    let mut outbound = json!({
        "type": "trojan",
        "tag": name,
        "server": server,
        "server_port": port,
        "password": password,
    });

    if let Some(tls_val) = tls {
        outbound["tls"] = tls_val;
    }
    if let Some(transport_val) = transport {
        outbound["transport"] = transport_val;
    }

    Ok((name, outbound))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_tcp_tls() {
        let link = "trojan://s3cr3t@example.com:443?security=tls&sni=example.com&fp=chrome#my-trojan";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "my-trojan");
        assert_eq!(ob["type"], "trojan");
        assert_eq!(ob["server"], "example.com");
        assert_eq!(ob["server_port"], 443);
        assert_eq!(ob["password"], "s3cr3t");
        assert_eq!(ob["tls"]["enabled"], true);
        assert_eq!(ob["tls"]["server_name"], "example.com");
        assert!(ob.get("transport").is_none());
    }

    #[test]
    fn test_trojan_ws() {
        let link = "trojan://pass@host.com:8443?type=ws&path=%2Fpath&host=host.com&sni=host.com#ws-trojan";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "ws-trojan");
        assert_eq!(ob["transport"]["type"], "ws");
        assert_eq!(ob["transport"]["path"], "/path");
    }

    #[test]
    fn test_trojan_tls_always_on() {
        // security param absent — TLS must still be enabled
        let link = "trojan://pass@host.com:443?sni=host.com#no-sec";
        let (_, ob) = parse(link).unwrap();
        assert_eq!(ob["tls"]["enabled"], true);
    }

    #[test]
    fn test_trojan_default_sni_from_host() {
        let link = "trojan://pass@my.server.com:443#sni-test";
        let (_, ob) = parse(link).unwrap();
        assert_eq!(ob["tls"]["server_name"], "my.server.com");
    }

    #[test]
    fn test_trojan_missing_password() {
        let link = "trojan://@host.com:443#bad";
        assert!(parse(link).is_err());
    }

    #[test]
    fn test_trojan_xhttp_rejected() {
        let link = "trojan://pass@host.com:443?type=xhttp#bad";
        assert!(parse(link).is_err());
    }

    #[test]
    fn test_trojan_default_name() {
        let link = "trojan://pass@1.2.3.4:443";
        let (name, _) = parse(link).unwrap();
        assert_eq!(name, "trojan@1.2.3.4:443");
    }
}
