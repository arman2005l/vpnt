//! Parse hysteria2:// and hy2:// share links into sing-box outbound JSON.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use url::Url;

use super::url_decode;

pub fn parse(raw: &str) -> Result<(String, Value)> {
    let normalized = if let Some(rest) = raw.strip_prefix("hy2://") {
        format!("hysteria2://{rest}")
    } else {
        raw.to_string()
    };
    let url = Url::parse(&normalized).context("invalid hysteria2:// URL")?;

    let mut password = url_decode(url.username());
    if let Some(pass) = url.password() {
        if !password.is_empty() {
            password = format!("{password}:{}", url_decode(pass));
        }
    }
    if password.is_empty() {
        bail!("hysteria2: missing password");
    }
    let server = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("hysteria2: missing host"))?
        .to_string();
    let port = url.port().unwrap_or(443);
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let name = url
        .fragment()
        .map(url_decode)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("hysteria2@{server}:{port}"));
    let sni = params.get("sni").cloned().unwrap_or_else(|| server.clone());
    let insecure = matches!(params.get("insecure").map(|s| s.as_str()), Some("1" | "true"));

    let mut tls = json!({ "enabled": true, "server_name": sni, "insecure": insecure });
    if let Some(alpn) = params.get("alpn").filter(|s| !s.is_empty()) {
        tls["alpn"] = json!(alpn.split(',').map(str::trim).collect::<Vec<_>>());
    }

    let mut outbound = json!({
        "type": "hysteria2",
        "tag": name,
        "server": server,
        "server_port": port,
        "password": password,
        "tls": tls,
    });

    match params.get("obfs").map(|s| s.as_str()) {
        None | Some("") | Some("none") => {}
        Some("salamander") => {
            let obfs_password = params.get("obfs-password").cloned().unwrap_or_default();
            if obfs_password.is_empty() {
                bail!("hysteria2: salamander obfs requires obfs-password");
            }
            outbound["obfs"] = json!({ "type": "salamander", "password": obfs_password });
        }
        Some(other) => bail!("hysteria2: unsupported obfs type {other}"),
    }

    Ok((name, outbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_link() {
        let link = "hysteria2://secret@example.com:8443?sni=sni.example&insecure=1&alpn=h3&obfs=salamander&obfs-password=ob#My%20HY2";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "My HY2");
        assert_eq!(ob["type"], "hysteria2");
        assert_eq!(ob["server"], "example.com");
        assert_eq!(ob["server_port"], 8443);
        assert_eq!(ob["password"], "secret");
        assert_eq!(ob["tls"]["server_name"], "sni.example");
        assert_eq!(ob["tls"]["insecure"], true);
        assert_eq!(ob["tls"]["alpn"][0], "h3");
        assert_eq!(ob["obfs"]["type"], "salamander");
    }

    #[test]
    fn hy2_alias_and_default_port() {
        let (name, ob) = parse("hy2://pass@1.2.3.4").unwrap();
        assert_eq!(name, "hysteria2@1.2.3.4:443");
        assert_eq!(ob["server_port"], 443);
        assert_eq!(ob["tls"]["server_name"], "1.2.3.4");
    }

    #[test]
    fn rejects_missing_password() {
        assert!(parse("hysteria2://example.com:443").is_err());
    }
}
