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

use crate::config::{
    load_rules, AppRuleKind, DefaultMode, ProxyConfig, RoutingMode, RuleAction, RuleKind,
    RulesConfig, Settings,
};

/// Path relative to `data_dir` where the generated config is written.
pub const CONFIG_FILENAME: &str = "config.json";

// ── Public API ────────────────────────────────────────────────────────────────

/// Build a complete sing-box config and write it atomically to
/// `data_dir/config.json`.  User rules are read from `data_dir/rules.json`.
/// Returns the path written.
pub fn write_config(
    data_dir: &Path,
    proxy: &ProxyConfig,
    settings: &Settings,
) -> Result<std::path::PathBuf> {
    let rules = load_rules(data_dir).context("failed to load rules.json")?;
    let dest = data_dir.join(CONFIG_FILENAME);
    write_config_to(&dest, proxy, settings, &rules)?;
    Ok(dest)
}

/// Build a config with explicit `rules` and write it atomically to `dest`.
pub fn write_config_to(
    dest: &Path,
    proxy: &ProxyConfig,
    settings: &Settings,
    rules: &RulesConfig,
) -> Result<()> {
    let config = build_with_rules(proxy, settings, rules)?;
    let bytes = serde_json::to_vec_pretty(&config)
        .context("failed to serialize sing-box config")?;
    crate::config::atomic_write(dest, &bytes)
        .context("failed to write sing-box config")?;
    Ok(())
}

/// Build and return the sing-box config as a JSON value without writing it,
/// using default rules (no user rules, `all_via_vpn`).
pub fn build(proxy: &ProxyConfig, settings: &Settings) -> Result<Value> {
    build_with_rules(proxy, settings, &RulesConfig::default())
}

/// Build the sing-box config with the given rules.json contents.
pub fn build_with_rules(
    proxy: &ProxyConfig,
    settings: &Settings,
    rules: &RulesConfig,
) -> Result<Value> {
    let log = build_log(settings);
    let dns = build_dns();
    let inbounds = build_inbounds(settings);
    let outbounds = build_outbounds(proxy);
    let route = build_route(proxy, settings, rules);
    let experimental = build_experimental();

    Ok(json!({
        "log":       log,
        "dns":       dns,
        "inbounds":  inbounds,
        "outbounds": outbounds,
        "route":     route,
        "experimental": experimental,
    }))
}

// ── Experimental (Clash API) ──────────────────────────────────────────────────

/// Clash API on 127.0.0.1 with a random free port and a random secret.
/// `crate::clash::ClashApi::from_config` reads these back from config.json.
fn build_experimental() -> Value {
    let port = pick_free_port().unwrap_or(9090);
    let secret = uuid::Uuid::new_v4().simple().to_string();
    json!({
        "clash_api": {
            "external_controller": format!("127.0.0.1:{port}"),
            "secret": secret,
        }
    })
}

fn pick_free_port() -> Option<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    Some(port)
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
    // New-style (sing-box >= 1.12) servers:
    //   - dns-remote: DoH through the proxy for everything else
    //   - dns-local:  DoH sent direct, used for private names and for
    //                 resolving outbound server addresses
    json!({
        "servers": [
            {
                "type":   "https",
                "tag":    "dns-remote",
                "server": "1.1.1.1",
                "detour": "proxy",
            },
            {
                "type":   "https",
                "tag":    "dns-local",
                "server": "223.5.5.5",
            },
        ],
        "rules": [
            { "rule_set": ["geosite-private"], "server": "dns-local" },
        ],
        "final": "dns-remote",
    })
}

// ── Inbounds ──────────────────────────────────────────────────────────────────

/// Sniffing is a route action since sing-box 1.11, so inbounds stay plain.
fn build_inbounds(settings: &Settings) -> Value {
    let socks_port = settings.socks_port.unwrap_or(10808);
    let http_port = settings.http_port.unwrap_or(10809);

    json!([
        {
            "type":         "socks",
            "tag":          "socks-in",
            "listen":       "127.0.0.1",
            "listen_port":  socks_port,
        },
        {
            "type":         "http",
            "tag":          "http-in",
            "listen":       "127.0.0.1",
            "listen_port":  http_port,
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

    json!(list)
}

// ── Route ─────────────────────────────────────────────────────────────────────

fn build_route(proxy: &ProxyConfig, settings: &Settings, user: &RulesConfig) -> Value {
    let mut rules: Vec<Value> = Vec::new();

    // 1. Sniff first so domain rules see the real host, then hijack DNS.
    rules.push(json!({ "action": "sniff" }));
    rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));

    // 2. Block ad/malware rule-sets.
    rules.push(json!({
        "rule_set": ["geosite-category-ads-all"],
        "action":   "reject",
    }));

    // 3. Direct: private addresses + LAN.
    rules.push(json!({
        "ip_is_private": true,
        "outbound":      "direct",
    }));

    // 4. rules.json, in order.
    for rule in &user.rules {
        let mut entry = match rule.kind {
            AppRuleKind::ProcessName => json!({ "process_name": [rule.value.as_str()] }),
            AppRuleKind::DomainSuffix => json!({ "domain_suffix": [rule.value.as_str()] }),
        };
        apply_action(&mut entry, &rule.action);
        rules.push(entry);
    }

    // 5. Legacy per-config rules from the RulesFile list.
    for rf in &proxy.rules_files {
        for rule in &rf.rules {
            let mut entry = match rule.kind {
                RuleKind::Domain => json!({ "domain_suffix": [rule.pattern.as_str()] }),
                RuleKind::DomainFull => json!({ "domain": [rule.pattern.as_str()] }),
                RuleKind::IpCidr => json!({ "ip_cidr": [rule.pattern.as_str()] }),
                RuleKind::GeoSite => json!({ "rule_set": [format!("geosite-{}", rule.pattern)] }),
                RuleKind::GeoIp => json!({ "rule_set": [format!("geoip-{}", rule.pattern)] }),
            };
            apply_action(&mut entry, &rule.action);
            rules.push(entry);
        }
    }

    // 6. Final: only_listed_via_vpn sends everything else direct; otherwise
    //    the legacy Settings.default_mode decides (Proxy by default).
    let final_action = match user.default_mode {
        RoutingMode::OnlyListedViaVpn => RuleAction::Direct,
        RoutingMode::AllViaVpn => match settings.default_mode {
            DefaultMode::Proxy => RuleAction::Proxy,
            DefaultMode::Direct => RuleAction::Direct,
            DefaultMode::Block => RuleAction::Block,
        },
    };
    let final_tag = match final_action {
        RuleAction::Proxy => "proxy",
        RuleAction::Direct | RuleAction::Block => "direct",
    };
    if final_action == RuleAction::Block {
        rules.push(json!({ "action": "reject" }));
    }

    json!({
        "rules":     rules,
        "final":     final_tag,
        "rule_set":  build_rule_sets(),
        "find_process": true,
        "auto_detect_interface": true,
        "default_domain_resolver": "dns-local",
    })
}

/// sing-box >= 1.13 has no `block` outbound: block is the `reject` action.
fn apply_action(entry: &mut Value, action: &RuleAction) {
    match action {
        RuleAction::Proxy => entry["outbound"] = json!("proxy"),
        RuleAction::Direct => entry["outbound"] = json!("direct"),
        RuleAction::Block => entry["action"] = json!("reject"),
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

    use crate::config::{AppRule, DefaultMode, ProxyConfig, Settings};

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
            ..Default::default()
        }
    }

    fn make_settings() -> Settings {
        Settings {
            default_mode: DefaultMode::Proxy,
            socks_port: Some(10808),
            http_port: Some(10809),
            log_level: "warn".into(),
            auto_connect: false,
            ..Settings::default()
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
    fn sniff_then_dns_hijack_come_first() {
        let cfg = build(&make_proxy(), &make_settings()).unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["protocol"], "dns");
        assert_eq!(rules[1]["action"], "hijack-dns");
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

    #[test]
    fn write_config_reads_rules_json() {
        let dir = tempfile::tempdir().unwrap();
        let rules = RulesConfig {
            default_mode: RoutingMode::OnlyListedViaVpn,
            rules: vec![AppRule {
                kind: AppRuleKind::ProcessName,
                value: "firefox".into(),
                action: RuleAction::Proxy,
            }],
        };
        crate::config::save_rules(dir.path(), &rules).unwrap();
        let path = write_config(dir.path(), &make_proxy(), &make_settings()).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(v["route"]["final"], "direct");
        let found = v["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["process_name"] == json!(["firefox"]) && r["outbound"] == "proxy");
        assert!(found);
    }

    // ── Golden files (src/gen/golden/*.json) ──────────────────────────────
    // Regenerate with: VPNT_UPDATE_GOLDEN=1 cargo test golden

    fn golden_proxy() -> ProxyConfig {
        ProxyConfig {
            id: "golden".into(),
            name: "golden".into(),
            outbound: json!({
                "type": "hysteria2",
                "tag": "golden",
                "server": "1.2.3.4",
                "server_port": 443,
                "password": "pw",
                "tls": { "enabled": true, "server_name": "example.com" },
            }),
            ..Default::default()
        }
    }

    fn rule(kind: AppRuleKind, value: &str, action: RuleAction) -> AppRule {
        AppRule { kind, value: value.into(), action }
    }

    fn check_golden(name: &str, rules: &RulesConfig) {
        let mut cfg = build_with_rules(&golden_proxy(), &Settings::default(), rules).unwrap();
        // Port and secret are random per build; pin them for comparison.
        cfg["experimental"]["clash_api"] = json!({
            "external_controller": "127.0.0.1:9090",
            "secret": "SECRET",
        });
        let actual = serde_json::to_string_pretty(&cfg).unwrap() + "\n";
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/gen/golden")
            .join(format!("{name}.json"));
        if std::env::var_os("VPNT_UPDATE_GOLDEN").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &actual).unwrap();
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing golden {}: {e}", path.display()));
        assert_eq!(actual, expected, "golden mismatch for {name}; rerun with VPNT_UPDATE_GOLDEN=1");
    }

    #[test]
    fn golden_default_no_rules() {
        check_golden("default_no_rules", &RulesConfig::default());
    }

    #[test]
    fn golden_all_via_vpn_with_exceptions() {
        let rules = RulesConfig {
            default_mode: RoutingMode::AllViaVpn,
            rules: vec![
                rule(AppRuleKind::ProcessName, "steam", RuleAction::Direct),
                rule(AppRuleKind::DomainSuffix, "ir", RuleAction::Direct),
                rule(AppRuleKind::DomainSuffix, "doubleclick.net", RuleAction::Block),
            ],
        };
        check_golden("all_via_vpn_exceptions", &rules);
    }

    #[test]
    fn golden_only_listed_via_vpn() {
        let rules = RulesConfig {
            default_mode: RoutingMode::OnlyListedViaVpn,
            rules: vec![
                rule(AppRuleKind::ProcessName, "telegram-desktop", RuleAction::Proxy),
                rule(AppRuleKind::ProcessName, "firefox", RuleAction::Proxy),
                rule(AppRuleKind::DomainSuffix, "youtube.com", RuleAction::Proxy),
                rule(AppRuleKind::ProcessName, "torrent", RuleAction::Block),
            ],
        };
        check_golden("only_listed_via_vpn", &rules);
    }
}
