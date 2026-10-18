//! Parse tuic:// share links into sing-box outbound JSON.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use url::Url;

use super::url_decode;

pub fn parse(raw: &str) -> Result<(String, Value)> {
    let url = Url::parse(raw).context("invalid tuic:// URL")?;
    let uuid = url_decode(url.username());
    let password = url.password().map(url_decode).unwrap_or_default();
    if uuid.is_empty() {
        bail!("tuic: missing UUID");
    }
    if password.is_empty() {
        bail!("tuic: missing password");
    }
    let server = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("tuic: missing host"))?
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| anyhow::anyhow!("tuic: missing port"))?;
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let name = url
        .fragment()
        .map(url_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("tuic@{server}:{port}"));
    let sni = params.get("sni").cloned().unwrap_or_else(|| server.clone());
    let insecure = matches!(
        params
            .get("allow_insecure")
            .or_else(|| params.get("insecure"))
            .map(|s| s.as_str()),
        Some("1" | "true")
    );
    let mut tls = json!({ "enabled": true, "server_name": sni, "insecure": insecure });
    if let Some(alpn) = params.get("alpn").filter(|s| !s.is_empty()) {
        tls["alpn"] = json!(alpn.split(',').map(str::trim).collect::<Vec<_>>());
    }
    let congestion = params
        .get("congestion_control")
        .or_else(|| params.get("congestion"))
        .cloned()
        .unwrap_or_else(|| "cubic".to_string());

    let mut outbound = json!({
        "type": "tuic",
        "tag": name,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "password": password,
        "congestion_control": congestion,
        "tls": tls,
    });
    if let Some(mode) = params.get("udp_relay_mode").filter(|s| !s.is_empty()) {
        outbound["udp_relay_mode"] = json!(mode);
    }

    Ok((name, outbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_link() {
        let link = "tuic://11111111-2222-3333-4444-555555555555:p%40ss@example.com:443?sni=sni.example&alpn=h3,spdy/3.1&congestion_control=bbr&udp_relay_mode=quic&allow_insecure=1#TUIC%20Node";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "TUIC Node");
        assert_eq!(ob["type"], "tuic");
        assert_eq!(ob["uuid"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(ob["password"], "p@ss");
        assert_eq!(ob["congestion_control"], "bbr");
        assert_eq!(ob["udp_relay_mode"], "quic");
        assert_eq!(ob["tls"]["alpn"][1], "spdy/3.1");
        assert_eq!(ob["tls"]["insecure"], true);
    }

    #[test]
    fn rejects_missing_password() {
        assert!(parse("tuic://uuid@example.com:443").is_err());
    }

    #[test]
    fn rejects_missing_port() {
        assert!(parse("tuic://uuid:pass@example.com").is_err());
    }
}
