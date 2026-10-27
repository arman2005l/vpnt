//! Generate a sing-box configuration JSON from the application's stored state.
//!
//! The output is written to `<data_dir>/config.json` and consumed by the
//! sing-box process managed in `src/core.rs`.
//!
//! TUN captures system traffic; local SOCKS5 + HTTP listeners remain available.
//! Private destinations go direct, with DNS hijacked before private-IP routing.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::config::{
    load_rules, AppRuleKind, DefaultMode, ProxyConfig, RoutingMode, RuleAction, RuleKind,
    RulesConfig, Settings,
};

/// Path relative to `data_dir` where the generated config is written.
pub const CONFIG_FILENAME: &str = "config.json";

/// Tag of the DNS server used for local names and for resolving the proxy
/// server's own hostname (sent direct, never through the proxy).
const DNS_LOCAL: &str = "dns-local";

/// Exact local host names that must never leave the machine.
const LOCAL_DOMAINS: &[&str] = &["localhost"];

/// Local / LAN suffixes routed direct and resolved by `DNS_LOCAL`.
const LOCAL_DOMAIN_SUFFIXES: &[&str] = &["localhost", "local", "lan", "internal", "home.arpa"];

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
    // New-style (sing-box >= 1.12) servers, both addressed by IP so that no
    // bootstrap lookup is needed:
    //   - dns-remote: DoH through the proxy for everything else
    //   - dns-local:  DoH sent direct, used for local names and for
    //                 resolving the proxy server's hostname (no loop)
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
                "tag":    DNS_LOCAL,
                "server": "223.5.5.5",
            },
        ],
        "rules": [
            local_names_matcher(json!({ "server": DNS_LOCAL })),
        ],
        "final": "dns-remote",
    })
}

/// Add the built-in local-name matchers (`domain` + `domain_suffix`) to `rule`.
fn local_names_matcher(mut rule: Value) -> Value {
    rule["domain"] = json!(LOCAL_DOMAINS);
    rule["domain_suffix"] = json!(LOCAL_DOMAIN_SUFFIXES);
    rule
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
        {
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1500,
            "auto_route": true,
            "auto_redirect": true,
            "strict_route": true,
            "stack": "mixed",
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
    // A hostname server must be resolved direct, never through itself.
    if primary.is_object() {
        pin_server_ip(&mut primary);
    }
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

    // 2. Direct: private addresses and local names, using built-in matchers
    //    only (no rule-sets: nothing may be downloaded at startup).
    rules.push(json!({
        "ip_is_private": true,
        "outbound":      "direct",
    }));
    rules.push(local_names_matcher(json!({ "outbound": "direct" })));

    // 3. rules.json, in order.
    for rule in &user.rules {
        let mut entry = match rule.kind {
            AppRuleKind::ProcessName => json!({ "process_name": [rule.value.as_str()] }),
            AppRuleKind::DomainSuffix => json!({ "domain_suffix": [rule.value.as_str()] }),
        };
        apply_action(&mut entry, &rule.action);
        rules.push(entry);
    }

    // 4. Legacy per-config rules from the RulesFile list.  GeoSite/GeoIp
    //    rules needed remote rule-sets and are skipped.
    for rf in &proxy.rules_files {
        for rule in &rf.rules {
            let mut entry = match rule.kind {
                RuleKind::Domain => json!({ "domain_suffix": [rule.pattern.as_str()] }),
                RuleKind::DomainFull => json!({ "domain": [rule.pattern.as_str()] }),
                RuleKind::IpCidr => json!({ "ip_cidr": [rule.pattern.as_str()] }),
                RuleKind::GeoSite | RuleKind::GeoIp => {
                    tracing::warn!("skipping {:?} rule: rule-sets are not supported", rule.kind);
                    continue;
                }
            };
            apply_action(&mut entry, &rule.action);
            rules.push(entry);
        }
    }

    // 5. Final: only_listed_via_vpn sends everything else direct; otherwise
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
        "find_process": true,
        "auto_detect_interface": true,
        "default_domain_resolver": DNS_LOCAL,
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
/// Resolve the proxy server's host name with the system resolver and pin the IP
/// in the outbound, keeping the original name as TLS SNI / WebSocket Host so the
/// handshake still matches. Runs before the tunnel exists.
fn pin_server_ip(outbound: &mut Value) {
    use std::net::{IpAddr, ToSocketAddrs};

    let host = match outbound.get("server").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };
    if host.parse::<IpAddr>().is_ok() {
        return;
    }
    let port = outbound
        .get("server_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(443) as u16;
    let ip = match (host.as_str(), port).to_socket_addrs() {
        Ok(addrs) => addrs.into_iter().find(|a| a.is_ipv4()).map(|a| a.ip()),
        Err(_) => None,
    };
    let ip = match ip {
        Some(ip) => ip,
        None => return,
    };
    outbound["server"] = json!(ip.to_string());

    if let Some(tls) = outbound.get_mut("tls").and_then(|t| t.as_object_mut()) {
        let enabled = tls.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
        if enabled && !tls.contains_key("server_name") {
            tls.insert("server_name".to_string(), json!(host));
        }
    }
    if let Some(tr) = outbound.get_mut("transport").and_then(|t| t.as_object_mut()) {
        let kind = tr.get("type").and_then(|k| k.as_str()).unwrap_or("").to_string();
        if kind == "ws" {
            let headers = tr.entry("headers").or_insert_with(|| json!({}));
            if let Some(h) = headers.as_object_mut() {
                h.entry("Host").or_insert_with(|| json!(host));
            }
        } else if kind == "httpupgrade" && !tr.contains_key("host") {
            tr.insert("host".to_string(), json!(host));
        }
    }
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
    fn tun_is_configured_without_removing_local_proxies() {
        let cfg = build(&make_proxy(), &make_settings()).unwrap();
        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 3);
        assert_eq!(inbounds[0]["type"], "socks");
        assert_eq!(inbounds[1]["type"], "http");
        for inbound in &inbounds[..2] {
            assert_eq!(inbound["listen"], "127.0.0.1");
        }
        let tun = &inbounds[2];
        assert_eq!(tun["type"], "tun");
        assert_eq!(tun["address"], json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]));
        assert_eq!(tun["auto_route"], true);
        assert_eq!(tun["auto_redirect"], true);
        assert_eq!(tun["strict_route"], true);
        assert_eq!(tun["stack"], "mixed");
        assert_eq!(cfg["route"]["auto_detect_interface"], true);
    }

    #[test]
    fn dns_hijack_precedes_private_ip_bypass() {
        let cfg = build(&make_proxy(), &make_settings()).unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        let dns = rules.iter().position(|r| r["action"] == "hijack-dns").unwrap();
        let private = rules.iter().position(|r| r["ip_is_private"] == true).unwrap();
        assert!(dns < private);
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

    /// Collect every string in `v` with its JSON path.
    fn strings_with_paths(v: &Value, path: String, out: &mut Vec<(String, String)>) {
        match v {
            Value::String(s) => out.push((path, s.clone())),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    strings_with_paths(item, format!("{path}[{i}]"), out);
                }
            }
            Value::Object(map) => {
                for (k, item) in map {
                    strings_with_paths(item, format!("{path}.{k}"), out);
                }
            }
            _ => {}
        }
    }

    fn all_rule_configs() -> Vec<RulesConfig> {
        vec![
            RulesConfig::default(),
            RulesConfig {
                default_mode: RoutingMode::OnlyListedViaVpn,
                rules: vec![rule(AppRuleKind::DomainSuffix, "ir", RuleAction::Direct)],
            },
        ]
    }

    #[test]
    fn config_is_self_contained() {
        let mut proxy = golden_proxy();
        proxy.rules_files = vec![crate::config::RulesFile {
            rules: vec![crate::config::Rule {
                kind: RuleKind::GeoSite,
                pattern: "ir".into(),
                action: RuleAction::Direct,
            }],
        }];
        for rules in all_rule_configs() {
            let cfg = build_with_rules(&proxy, &Settings::default(), &rules).unwrap();
            let text = cfg.to_string();
            assert!(!text.contains("rule_set"), "config references a rule-set: {text}");
            assert!(!text.contains("\"remote\""), "config has a remote entry: {text}");
            let mut strings = Vec::new();
            strings_with_paths(&cfg, String::new(), &mut strings);
            for (path, s) in strings {
                let lower = s.to_ascii_lowercase();
                if lower.contains("http://") || lower.contains("https://") {
                    assert!(
                        path.starts_with(".dns.servers[") && path.ends_with(".server"),
                        "URL outside DNS server address at {path}: {s}"
                    );
                }
            }
        }
    }

    #[test]
    fn dns_servers_are_ips_and_proxy_host_resolved_direct() {
        let mut proxy = golden_proxy();
        proxy.outbound["server"] = json!("proxy.example.com");
        let cfg = build(&proxy, &Settings::default()).unwrap();
        for server in cfg["dns"]["servers"].as_array().unwrap() {
            let addr = server["server"].as_str().unwrap();
            assert!(addr.parse::<std::net::IpAddr>().is_ok(), "DNS server not an IP: {addr}");
        }
        let local = cfg["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["tag"] == DNS_LOCAL)
            .unwrap();
        assert!(local.get("detour").is_none(), "local resolver must not use the proxy");
        assert_eq!(cfg["route"]["default_domain_resolver"], DNS_LOCAL);
    }

    #[test]
    fn local_names_and_private_ips_go_direct() {
        let cfg = build(&golden_proxy(), &Settings::default()).unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["ip_is_private"] == true && r["outbound"] == "direct"));
        let names = rules
            .iter()
            .find(|r| r["domain_suffix"].is_array() && r["outbound"] == "direct")
            .unwrap();
        assert_eq!(names["domain"], json!(["localhost"]));
        assert_eq!(
            names["domain_suffix"],
            json!(["localhost", "local", "lan", "internal", "home.arpa"])
        );
    }

    /// Runs `sing-box check` on generated samples when sing-box is installed.
    #[test]
    fn sing_box_check_accepts_generated_configs() {
        let bin = std::env::var_os("VPNT_SING_BOX").unwrap_or_else(|| "sing-box".into());
        let probe = std::process::Command::new(&bin).arg("version").output();
        if std::env::var_os("VPNT_SING_BOX").is_some() {
            assert!(
                probe.as_ref().is_ok_and(|p| p.status.success()),
                "VPNT_SING_BOX must point to a working sing-box binary"
            );
        }
        let Ok(probe) = probe else {
            eprintln!("sing-box not installed; skipping");
            return;
        };
        if !probe.status.success() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut proxies = vec![golden_proxy()];
        proxies[0].outbound["server"] = json!("proxy.example.com");
        for link in [
            "vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?security=tls&sni=example.com&type=ws&path=%2Fws",
            "trojan://test-password@192.0.2.1:443?sni=example.com",
            "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA==@192.0.2.1:443",
            "hy2://test-password@192.0.2.1:443?sni=example.com",
            "tuic://11111111-2222-3333-4444-555555555555:test-password@192.0.2.1:443?sni=example.com",
        ] {
            proxies.push(crate::ui::app::proxy_from_link(link).unwrap());
        }
        use base64::Engine as _;
        let vmess = base64::engine::general_purpose::STANDARD.encode(
            r#"{"add":"192.0.2.1","port":443,"id":"11111111-2222-3333-4444-555555555555","net":"tcp","tls":"tls","sni":"example.com"}"#,
        );
        proxies.push(crate::ui::app::proxy_from_link(&format!("vmess://{vmess}")).unwrap());
        for (p, proxy) in proxies.iter().enumerate() {
            for (i, rules) in all_rule_configs().iter().enumerate() {
                let path = dir.path().join(format!("sample{p}-{i}.json"));
                write_config_to(&path, proxy, &Settings::default(), rules).unwrap();
                let out = std::process::Command::new(&bin)
                    .args(["check", "--disable-color", "-c"])
                    .arg(&path)
                    .output()
                    .unwrap();
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stderr),
                    String::from_utf8_lossy(&out.stdout)
                );
                assert!(out.status.success(), "sample{p}-{i}: sing-box check failed: {text}");
                assert!(!text.contains("WARN"), "sample{p}-{i}: sing-box check warned: {text}");
            }
        }
    }

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
