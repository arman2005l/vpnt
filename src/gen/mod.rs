//! Generate a sing-box configuration JSON from the application's stored state.
//!
//! The output is written to `<data_dir>/config.json` and consumed by the
//! sing-box process managed in `src/core.rs`.
//!
//! M1 scope: SOCKS5 + HTTP inbounds on localhost, single outbound proxy,
//! minimal routing (direct for private ranges, proxy for everything else),
//! and a simple DNS config that works without TUN.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::config::{DefaultMode, ProxyConfig, RuleAction, RuleKind, Settings};

/// Path relative to `data_dir` where the generated config is written.
pub const CONFIG_FILENAME: &str = "config.json";

// ── Public API ────────────────────────────────────────────────────────────────

/// Build a complete sing-box config and write it atomically to
/// `data_dir/config.json`.  Returns the path written.
pub fn write_config(
    data_dir: &Path,
    proxy: &ProxyConfig,
    settings: &Settings,
) -> Result<std::path::PathBuf> {
    let config = build(proxy, settings)?;
    let dest = data_dir.join(CONFIG_FILENAME);
    let bytes = serde_json::to_vec_pretty(&config)
        .context("failed to serialize sing-box config")?;
    crate::config::atomic_write(&dest, &bytes)
        .context("failed to write sing-box config")?;
    Ok(dest)
}

/// Build and return the sing-box config as a JSON value without writing it.
/// Useful for tests and preview.
pub fn build(proxy: &ProxyConfig, settings: &Settings) -> Result<Value> {
    let log = build_log(settings);
    let dns = build_dns();
    let inbounds = build_inbounds(settings);
    let outbounds = build_outbounds(proxy);
    let route = build_route(proxy, settings);

    Ok(json!({
        "log":       log,
        "dns":       dns,
        "inbounds":  inbounds,
        "outbounds": outbounds,
        "route":     route,
    }))
}

// ── Log ───────────────────────────────────────────────────────────────────────

fn build_log(settings: &Settings) -> Value {
    let level = if settings.log_level.is_empty() {
        "warn"
    } else {
        &settings.log_level
    };
    json!({
        "level":     level,
        "timestamp": true,
    })
}

// ── DNS ───────────────────────────────────────────────────────────────────────

fn build_dns() -> Value {
    // Simple two-server setup:
    //   - local:  system resolver for direct (private/CN) traffic
    //   - remote: DNS-over-HTTPS via the proxy for everything else
    // M1 does not use TUN so we rely on the OS resolver for local lookups.
    json!({
        "servers": [
            {
                "tag":     "dns-remote",
                "address": "https://1.1.1.1/dns-query",
                "detour":  "proxy",
            },
            {
                "tag":     "dns-local",
                "address": "https://223.5.5.5/dns-query",
                "detour":  "direct",
            },
            {
                "tag":     "dns-block",
                "address": "rcode://success",
            },
        ],
        "rules": [
            // Resolve private-range FQDNs locally.
            { "rule_set": ["geosite-private"],   "server": "dns-local" },
            // Proxy everything else.
        ],
        "final":             "dns-remote",
        "independent_cache": true,
    })
}

// ── Inbounds ──────────────────────────────────────────────────────────────────

fn build_inbounds(settings: &Settings) -> Value {
    let socks_port = settings.socks_port.unwrap_or(10808);
    let http_port = settings.http_port.unwrap_or(10809);

    json!([
        {
            "type":         "socks",
            "tag":          "socks-in",
            "listen":       "127.0.0.1",
            "listen_port":  socks_port,
            "sniff":        true,
            "sniff_override_destination": true,
            "users":        [],
        },
        {
            "type":         "http",
            "tag":          "http-in",
            "listen":       "127.0.0.1",
            "listen_port":  http_port,
            "sniff":        true,
            "sniff_override_destination": true,
            "users":        [],
        },
    ])
}

// ── Outbounds ─────────────────────────────────────────────────────────────────

fn build_outbounds(proxy: &ProxyConfig) -> Value {
    let mut list: Vec<Value> = Vec::new();

    // Primary proxy outbound (already a fully-formed sing-box outbound object).
    let mut primary = proxy.outbound.clone();
    // Ensure the tag is "proxy" so routing rules can reference it by name.
    primary["tag"] = json!("proxy");
    list.push(primary);

    // Built-in utility outbounds.
    list.push(json!({ "type": "direct", "tag": "direct" }));
    list.push(json!({ "type": "block",  "tag": "block"  }));
    list.push(json!({ "type": "dns",    "tag": "dns-out" }));

    json!(list)
}

// ── Route ─────────────────────────────────────────────────────────────────────

fn build_route(proxy: &ProxyConfig, settings: &Settings) -> Value {
    let mut rules: Vec<Value> = Vec::new();

    // 1. DNS hijack — must be first.
    rules.push(json!({ "protocol": "dns",      "outbound": "dns-out" }));

    // 2. Block ad/malware rule-sets (optional, non-fatal if absent).
    rules.push(json!({
        "rule_set":  ["geosite-category-ads-all"],
        "outbound":  "block",
    }));

    // 3. Direct: private addresses + LAN.
    rules.push(json!({
        "ip_is_private": true,
        "outbound":      "direct",
    }));

    // 4. User-defined per-domain / per-IP rules from the RulesFile list.
    for rf in &proxy.rules_files {
        for rule in &rf.rules {
            let entry = match rule.kind {
                RuleKind::Domain => json!({
                    "domain_suffix": [rule.pattern.as_str()],
                    "outbound": action_tag(&rule.action),
                }),
                RuleKind::DomainFull => json!({
                    "domain":   [rule.pattern.as_str()],
                    "outbound": action_tag(&rule.action),
                }),
                RuleKind::IpCidr => json!({
                    "ip_cidr":  [rule.pattern.as_str()],
                    "outbound": action_tag(&rule.action),
                }),
                RuleKind::GeoSite => json!({
                    "rule_set":  [format!("geosite-{}", rule.pattern)],
                    "outbound":  action_tag(&rule.action),
                }),
                RuleKind::GeoIp => json!({
                    "rule_set":  [format!("geoip-{}", rule.pattern)],
                    "outbound":  action_tag(&rule.action),
                }),
            };
            rules.push(entry);
        }
    }

    // 5. Default final rule based on DefaultMode.
    let final_tag = match settings.default_mode {
        DefaultMode::Proxy => "proxy",
        DefaultMode::Direct => "direct",
    };

    // Rule-set references for GFW-list style bypass (downloaded separately).
    // If the files don't exist sing-box skips them gracefully.
    let rule_sets = build_rule_sets();

    json!({
        "rules":     rules,
        "final":     final_tag,
        "rule_set":  rule_sets,
        "auto_detect_interface": true,
    })
}

fn action_tag(action: &RuleAction) -> &'static str {
    match action {
        RuleAction::Proxy  => "proxy",
        RuleAction::Direct => "direct",
        RuleAction::Block  => "block",
    }
}

// ── Rule-set descriptors ──────────────────────────────────────────────────────

/// Declare the remote rule-sets we reference in routing/DNS.
/// sing-box will download these on first run if `experimental.cache_file`
/// is enabled; if absent the rules that reference them are silently skipped.
fn build_rule_sets() -> Value {
    const BASE: &str =
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set";
    const GEOIP_BASE: &str =
        "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set";

    json!([
        {
            "type":         "remote",
            "tag":          "geosite-private",
            "format":       "binary",
            "url":          format!("{BASE}/geosite-private.srs"),
            "update_interval": "7d",
        },
        {
            "type":         "remote",
            "tag":          "geosite-category-ads-all",
            "format":       "binary",
            "url":          format!("{BASE}/geosite-category-ads-all.srs"),
            "update_interval": "7d",
        },
        {
            "type":         "remote",
            "tag":          "geoip-private",
            "format":       "binary",
            "url":          format!("{GEOIP_BASE}/geoip-private.srs"),
            "update_interval": "7d",
        },
    ])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{DefaultMode, ProxyConfig, Settings};

    use super::*;

    fn make_proxy() -> ProxyConfig {
        ProxyConfig {
            name: "test".into(),
            outbound: json!({
                "type": "vless",
                "tag":  "test",
                "server": "1.2.3.4",
                "server_port": 443,
                "uuid": "some-uuid",
            }),
            rules_files: vec![],
            enabled: true,
        }
    }

    fn make_settings() -> Settings {
        Settings {
            default_mode: DefaultMode::Proxy,
            socks_port: Some(10808),
            http_port: Some(10809),
            log_level: "warn".into(),
            auto_connect: false,
        }
    }

    #[test]
    fn build_produces_valid_structure() {
        let cfg = build(&make_proxy(), &make_settings()).unwrap();
        assert!(cfg["log"].is_object());
        assert!(cfg["dns"].is_object());
        assert!(cfg["inbounds"].is_array());
        assert!(cfg["outbounds"].is_array());
        assert!(cfg["route"].is_object());
    }

    #[test]
    fn proxy_tag_overwritten_to_proxy() {
        let cfg = build(&make_proxy(), &make_settings()).unwrap();
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[0]["tag"], "proxy");
    }

    #[test]
    fn inbound_ports_respected() {
        let mut s = make_settings();
        s.socks_port = Some(1080);
        s.http_port = Some(8080);
        let cfg = build(&make_proxy(), &s).unwrap();
        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert_eq!(inbounds[0]["listen_port"], 1080);
        assert_eq!(inbounds[1]["listen_port"], 8080);
    }

    #[test]
    fn direct_mode_sets_final_to_direct() {
        let mut s = make_settings();
        s.default_mode = DefaultMode::Direct;
        let cfg = build(&make_proxy(), &s).unwrap();
        assert_eq!(cfg["route"]["final"], "direct");
    }

    #[test]
    fn dns_hijack_rule_is_first() {
        let cfg = build(&make_proxy(), &make_settings()).unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["protocol"], "dns");
        assert_eq!(rules[0]["outbound"], "dns-out");
    }

    #[test]
    fn write_config_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), &make_proxy(), &make_settings()).unwrap();
        assert!(path.exists());
        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(v["inbounds"].is_array());
    }
}
