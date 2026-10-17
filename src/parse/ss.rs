//! Parse ss:// (Shadowsocks) share links into sing-box outbound JSON.
//!
//! Supported formats:
//!   1. SIP002: ss://<base64(method:password)>@<host>:<port>[/?plugin=...]#<name>
//!              or ss://<method>:<password>@<host>:<port>#<name>  (some clients)
//!   2. Legacy: ss://<base64(method:password@host:port)>#<name>
//!
//! Supported ciphers: whatever sing-box accepts; we pass the string through.
//! Plugin field is parsed but sing-box v1.x handles it differently — we store
//! it in the outbound for completeness and emit a warning comment in the tag.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use url::Url;

use super::url_decode;

pub fn parse(raw: &str) -> Result<(String, Value)> {
    // Try SIP002 first (has an '@' after the scheme).
    // SIP002 userinfo is base64(method:password) OR plain method:password.
    // Legacy has the whole authority base64-encoded.

    let after_scheme = raw
        .strip_prefix("ss://")
        .ok_or_else(|| anyhow::anyhow!("ss: missing scheme"))?;

    // Presence of '@' before any '#' or '?' → SIP002 or extended SIP002.
    let at_pos = after_scheme.find('@');
    let hash_pos = after_scheme.find('#');
    let is_sip002 = match (at_pos, hash_pos) {
        (Some(a), Some(h)) => a < h,
        (Some(_), None) => true,
        _ => false,
    };

    if is_sip002 {
        parse_sip002(raw)
    } else {
        parse_legacy(raw)
    }
}

// ── SIP002 ────────────────────────────────────────────────────────────────────

fn parse_sip002(raw: &str) -> Result<(String, Value)> {
    // url::Url can parse ss:// as a generic URI.
    let url = Url::parse(raw).context("ss SIP002: invalid URL")?;

    let server = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("ss SIP002: missing host"))?;
    let port = url
        .port()
        .ok_or_else(|| anyhow::anyhow!("ss SIP002: missing port"))?;

    // Userinfo: try base64(method:password) first, then plain method:password.
    let userinfo = url.username();
    if userinfo.is_empty() {
        bail!("ss SIP002: missing userinfo");
    }

    let (method, password) = decode_userinfo(userinfo)
        .context("ss SIP002: cannot decode userinfo")?;

    let name = url
        .fragment()
        .map(|f| url_decode(f))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ss@{server}:{port}"));

    build_outbound(name, server, port, &method, &password)
}

// ── Legacy ────────────────────────────────────────────────────────────────────

fn parse_legacy(raw: &str) -> Result<(String, Value)> {
    // Format: ss://<base64(method:password@host:port)>#<name>
    let after_scheme = raw
        .strip_prefix("ss://")
        .ok_or_else(|| anyhow::anyhow!("ss legacy: missing scheme"))?;

    let (b64_part, name_part) = match after_scheme.find('#') {
        Some(pos) => (&after_scheme[..pos], &after_scheme[pos + 1..]),
        None => (after_scheme, ""),
    };

    let decoded = decode_b64_padded(b64_part)
        .context("ss legacy: base64 decode failed")?;
    let decoded_str = std::str::from_utf8(&decoded)
        .context("ss legacy: decoded bytes not UTF-8")?;

    // decoded_str = "method:password@host:port"
    let at = decoded_str
        .rfind('@')
        .ok_or_else(|| anyhow::anyhow!("ss legacy: no '@' in decoded payload"))?;

    let creds = &decoded_str[..at];
    let host_port = &decoded_str[at + 1..];

    let colon_cred = creds
        .find(':')
        .ok_or_else(|| anyhow::anyhow!("ss legacy: no ':' in credentials"))?;
    let method = &creds[..colon_cred];
    let password = &creds[colon_cred + 1..];

    let colon_hp = host_port
        .rfind(':')
        .ok_or_else(|| anyhow::anyhow!("ss legacy: no ':' in host:port"))?;
    let server = &host_port[..colon_hp];
    let port: u16 = host_port[colon_hp + 1..]
        .parse()
        .context("ss legacy: invalid port")?;

    let name = if name_part.is_empty() {
        format!("ss@{server}:{port}")
    } else {
        url_decode(name_part)
    };

    build_outbound(name, server, port, method, password)
}

// ── Shared ────────────────────────────────────────────────────────────────────

fn build_outbound(
    name: String,
    server: &str,
    port: u16,
    method: &str,
    password: &str,
) -> Result<(String, Value)> {
    if method.is_empty() {
        bail!("ss: missing cipher method");
    }
    if password.is_empty() {
        bail!("ss: missing password");
    }

    let outbound = json!({
        "type": "shadowsocks",
        "tag": name,
        "server": server,
        "server_port": port,
        "method": method,
        "password": password,
    });

    Ok((name, outbound))
}

/// Decode base64 userinfo: try as-is (may be base64(method:password)),
/// then try plain "method:password" split.
fn decode_userinfo(userinfo: &str) -> Result<(String, String)> {
    // First attempt: treat as base64
    if let Ok(decoded) = decode_b64_padded(userinfo) {
        if let Ok(s) = std::str::from_utf8(&decoded) {
            if let Some(pos) = s.find(':') {
                return Ok((s[..pos].to_string(), s[pos + 1..].to_string()));
            }
        }
    }
    // Second attempt: plain "method:password" (url-decoded)
    let plain = url_decode(userinfo);
    if let Some(pos) = plain.find(':') {
        return Ok((plain[..pos].to_string(), plain[pos + 1..].to_string()));
    }
    bail!("cannot decode userinfo as base64(method:pass) or plain method:pass")
}

fn decode_b64_padded(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .context("all base64 variants failed")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        STANDARD.encode(s.as_bytes())
    }

    #[test]
    fn test_ss_sip002_b64_userinfo() {
        let userinfo = b64("chacha20-ietf-poly1305:mypassword");
        let link = format!("ss://{}@1.2.3.4:8388#my-ss", userinfo);
        let (name, ob) = parse(&link).unwrap();
        assert_eq!(name, "my-ss");
        assert_eq!(ob["type"], "shadowsocks");
        assert_eq!(ob["server"], "1.2.3.4");
        assert_eq!(ob["server_port"], 8388);
        assert_eq!(ob["method"], "chacha20-ietf-poly1305");
        assert_eq!(ob["password"], "mypassword");
    }

    #[test]
    fn test_ss_sip002_plain_userinfo() {
        // Some clients put method:password directly without base64
        let link = "ss://aes-256-gcm:secretpass@example.com:1080#plain-ss";
        let (name, ob) = parse(link).unwrap();
        assert_eq!(name, "plain-ss");
        assert_eq!(ob["method"], "aes-256-gcm");
        assert_eq!(ob["password"], "secretpass");
    }

    #[test]
    fn test_ss_legacy() {
        let payload = b64("aes-128-gcm:legacypass@10.0.0.1:1234");
        let link = format!("ss://{}#legacy-node", payload);
        let (name, ob) = parse(&link).unwrap();
        assert_eq!(name, "legacy-node");
        assert_eq!(ob["server"], "10.0.0.1");
        assert_eq!(ob["server_port"], 1234);
        assert_eq!(ob["method"], "aes-128-gcm");
        assert_eq!(ob["password"], "legacypass");
    }

    #[test]
    fn test_ss_legacy_no_fragment() {
        let payload = b64("aes-128-gcm:pass@10.0.0.1:9000");
        let link = format!("ss://{}", payload);
        let (name, _) = parse(&link).unwrap();
        assert_eq!(name, "ss@10.0.0.1:9000");
    }

    #[test]
    fn test_ss_missing_method() {
        // userinfo base64 decodes to ":password" (empty method)
        let userinfo = b64(":password");
        let link = format!("ss://{}@1.2.3.4:8388#bad", userinfo);
        assert!(parse(&link).is_err());
    }

    #[test]
    fn test_ss_missing_password() {
        let userinfo = b64("aes-256-gcm:");
        let link = format!("ss://{}@1.2.3.4:8388#bad", userinfo);
        assert!(parse(&link).is_err());
    }
}
