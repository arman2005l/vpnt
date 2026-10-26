# vpnt design (source of truth for design decisions)

Personal TUI VPN client in Rust (ratatui, crossterm, tokio, reqwest/rustls, serde, anyhow, directories, tracing).
It imports proxy share links, generates a sing-box config and supervises a `sing-box` child process in TUN mode. It implements no proxy protocol itself. UI text is English.

## Data (OS config dir via `directories`, folder vpnt/)
- configs.json: [{id, name, raw_link, outbound, added_at, last_tcp_ms}]
- rules.json: {default_mode: "all_via_vpn" | "only_listed_via_vpn", rules: [{kind: "process_name" | "domain_suffix", value, action: "proxy" | "direct" | "block"}]}
- settings.json: {active_config_id, core_path, mixed_port}
Atomic writes, 0600 on Unix, never log secrets (uuid, password, keys).

## Generated sing-box config
inbounds: tun (auto_route, strict_route, 172.19.0.1/30, stack mixed) + mixed on 127.0.0.1:<mixed_port>.
outbounds: proxy (selected config), direct, block.
route: find_process true, auto_detect_interface true, sniff + hijack-dns, private ranges direct (`ip_is_private`) and local names direct (domain localhost; suffixes localhost, local, lan, internal, home.arpa), user rules in order, final per default_mode.
Self-contained: no rule_set (local or remote), no geoip/geosite, nothing downloaded at startup. The only URLs allowed are DNS server addresses.
dns: remote DoH through the proxy + local DoH sent direct, both addressed by IP. The proxy outbound's `domain_resolver` and `route.default_domain_resolver` point to the local resolver, so a hostname server is never resolved through itself. experimental.clash_api on 127.0.0.1, random port and secret.
Match the installed sing-box version's format. Always run `sing-box check -c` before start and show its error in the UI.
If sing-box exits during startup, show its last FATAL line on the Dashboard (Status: Error: ...) and do not retry automatically; the full output stays in the Logs tab.

## Core
Spawn `sing-box run -c <file>`, 1000-line log ring buffer, graceful stop, never call sudo. On permission error show:
sudo setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep $(which sing-box)
Config changes while connected: one-line confirmation, then restart the core.

## UI
Tabs (Tab/Shift+Tab): Dashboard, Configs, Apps, Logs. Global keys: `c` connect/disconnect, arrows or j/k, `?` help, `q` quit (disconnects first). Paste via crossterm bracketed paste.

## Conventions
Conservative Rust (simple ownership, clone liberally, no unsafe, no unwrap/expect outside tests). OS-specific code only in src/platform/ behind cfg(target_os). Linux (Ubuntu) is the only tested platform.
