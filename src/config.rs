use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub settings: serde_json::Value,
    pub stream_settings: Option<serde_json::Value>,
    #[serde(default)]
    pub outbound: serde_json::Value,
    #[serde(default)]
    pub rules_files: Vec<RulesFile>,
    #[serde(default)]
    pub last_tcp_ms: Option<u64>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: "vless".into(),
            address: "127.0.0.1".into(),
            port: 443,
            settings: serde_json::Value::Null,
            stream_settings: None,
            outbound: serde_json::Value::Null,
            rules_files: Vec::new(),
            last_tcp_ms: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum DefaultMode {
    #[default]
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleKind {
    Domain,
    DomainFull,
    IpCidr,
    GeoSite,
    GeoIp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleAction {
    Proxy,
    Direct,
    Block,
}

impl RuleAction {
    /// Lowercase name used in rules.json, the generator and the UI.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleAction::Proxy => "proxy",
            RuleAction::Direct => "direct",
            RuleAction::Block => "block",
        }
    }

    /// proxy -> direct -> block -> proxy.
    pub fn cycle(&self) -> RuleAction {
        match self {
            RuleAction::Proxy => RuleAction::Direct,
            RuleAction::Direct => RuleAction::Block,
            RuleAction::Block => RuleAction::Proxy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub kind: RuleKind,
    pub pattern: String,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesFile {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

// ── rules.json (see DESIGN.md) ────────────────────────────────────────────────

pub const RULES_FILENAME: &str = "rules.json";

/// `default_mode` in rules.json.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    #[default]
    AllViaVpn,
    OnlyListedViaVpn,
}

impl RoutingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RoutingMode::AllViaVpn => "all_via_vpn",
            RoutingMode::OnlyListedViaVpn => "only_listed_via_vpn",
        }
    }

    pub fn toggle(self) -> RoutingMode {
        match self {
            RoutingMode::AllViaVpn => RoutingMode::OnlyListedViaVpn,
            RoutingMode::OnlyListedViaVpn => RoutingMode::AllViaVpn,
        }
    }

    /// Sensible action for a newly added rule: the opposite of the default.
    pub fn new_rule_action(self) -> RuleAction {
        match self {
            RoutingMode::AllViaVpn => RuleAction::Direct,
            RoutingMode::OnlyListedViaVpn => RuleAction::Proxy,
        }
    }
}

/// `kind` of a rules.json entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppRuleKind {
    ProcessName,
    DomainSuffix,
}

impl AppRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AppRuleKind::ProcessName => "process_name",
            AppRuleKind::DomainSuffix => "domain_suffix",
        }
    }
}

/// One rules.json entry: `{kind, value, action}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRule {
    pub kind: AppRuleKind,
    pub value: String,
    #[serde(with = "lowercase_action")]
    pub action: RuleAction,
}

impl AppRule {
    /// Parse the Apps-tab input. `app:NAME` / `domain:SUFFIX` force the kind;
    /// otherwise anything that looks like a host name is a domain suffix.
    pub fn from_input(text: &str, action: RuleAction) -> Option<AppRule> {
        let text = text.trim();
        let (kind, value) = if let Some(rest) = text.strip_prefix("app:") {
            (AppRuleKind::ProcessName, rest.trim())
        } else if let Some(rest) = text.strip_prefix("domain:") {
            (AppRuleKind::DomainSuffix, rest.trim())
        } else if looks_like_domain(text) {
            (AppRuleKind::DomainSuffix, text)
        } else {
            (AppRuleKind::ProcessName, text)
        };
        let value = match kind {
            AppRuleKind::DomainSuffix => value.trim_start_matches('.').to_ascii_lowercase(),
            AppRuleKind::ProcessName => value.to_string(),
        };
        if value.is_empty() || value.contains(char::is_whitespace) {
            return None;
        }
        Some(AppRule { kind, value, action })
    }
}

fn looks_like_domain(text: &str) -> bool {
    let Some((_, tld)) = text.rsplit_once('.') else {
        return false;
    };
    !tld.is_empty()
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && !matches!(tld, "exe" | "bin" | "sh" | "py" | "AppImage" | "appimage")
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Contents of rules.json.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesConfig {
    #[serde(default)]
    pub default_mode: RoutingMode,
    #[serde(default)]
    pub rules: Vec<AppRule>,
}

/// Load `dir/rules.json`; a missing file means defaults.
pub fn load_rules(dir: &Path) -> Result<RulesConfig> {
    let path = dir.join(RULES_FILENAME);
    if !path.exists() {
        return Ok(RulesConfig::default());
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {:?}", path))?;
    serde_json::from_slice(&data).with_context(|| format!("failed to parse {:?}", path))
}

/// Atomically write `dir/rules.json`.
pub fn save_rules(dir: &Path, rules: &RulesConfig) -> Result<()> {
    let data = serde_json::to_vec_pretty(rules)?;
    atomic_write(&dir.join(RULES_FILENAME), &data)
}

mod lowercase_action {
    use super::RuleAction;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(action: &RuleAction, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(action.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<RuleAction, D::Error> {
        let raw = String::deserialize(d)?;
        match raw.to_ascii_lowercase().as_str() {
            "proxy" => Ok(RuleAction::Proxy),
            "direct" => Ok(RuleAction::Direct),
            "block" => Ok(RuleAction::Block),
            _ => Err(serde::de::Error::custom(format!("unknown rule action {raw:?}"))),
        }
    }
}

fn default_mixed_port() -> u16 {
    10808
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub active_config_id: Option<String>,
    pub core_path: Option<String>,
    #[serde(default = "default_mixed_port")]
    pub mixed_port: u16,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub default_mode: DefaultMode,
    #[serde(default)]
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub http_port: Option<u16>,
    #[serde(default)]
    pub log_level: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            active_config_id: None,
            core_path: None,
            mixed_port: default_mixed_port(),
            auto_connect: false,
            default_mode: DefaultMode::Proxy,
            socks_port: Some(10808),
            http_port: Some(10809),
            log_level: "warn".into(),
        }
    }
}


pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create dir {:?}", parent))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }
    let tmp = path.with_extension("tmp");
    write_private(&tmp, data)
        .with_context(|| format!("failed to write tmp file {:?}", tmp))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {:?} to {:?}", tmp, path))?;
    Ok(())
}

/// Write a file that only the owner can read (it may contain proxy credentials).
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `mode` only applies when the file is created, so fix a leftover tmp file too.
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub dir: PathBuf,
    pub proxies: Vec<ProxyConfig>,
    pub settings: Settings,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            dir: PathBuf::new(),
            proxies: Vec::new(),
            settings: Settings::default(),
        }
    }
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            proxies: Vec::new(),
            settings: Settings::default(),
        }
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let store_helper = Self::new(dir.to_path_buf());
        let proxies = store_helper.load_configs().unwrap_or_default();
        let settings = store_helper.load_settings().unwrap_or_default();
        Ok(Self {
            dir: dir.to_path_buf(),
            proxies,
            settings,
        })
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let store_helper = Self::new(dir.to_path_buf());
        store_helper.save_configs(&self.proxies)?;
        store_helper.save_settings(&self.settings)?;
        Ok(())
    }

    pub fn configs_path(&self) -> PathBuf {
        self.dir.join("configs.json")
    }

    pub fn settings_path(&self) -> PathBuf {
        self.dir.join("settings.json")
    }

    pub fn load_configs(&self) -> Result<Vec<ProxyConfig>> {
        let path = self.configs_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read(&path)
            .with_context(|| format!("failed to read {:?}", path))?;
        let list: Vec<ProxyConfig> = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse {:?}", path))?;
        Ok(list)
    }

    pub fn save_configs(&self, configs: &[ProxyConfig]) -> Result<()> {
        let data = serde_json::to_vec_pretty(configs)?;
        atomic_write(&self.configs_path(), &data)
    }

    pub fn load_settings(&self) -> Result<Settings> {
        let path = self.settings_path();
        if !path.exists() {
            return Ok(Settings::default());
        }
        let data = fs::read(&path)
            .with_context(|| format!("failed to read {:?}", path))?;
        let s: Settings = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse {:?}", path))?;
        Ok(s)
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        let data = serde_json::to_vec_pretty(settings)?;
        atomic_write(&self.settings_path(), &data)
    }
}

#[cfg(test)]
mod tests {
    use super::atomic_write;

    #[cfg(unix)]
    #[test]
    fn atomic_write_creates_private_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("secret.json");

        atomic_write(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // overwriting an existing file must keep it private too
        atomic_write(&path, b"{\"a\":1}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // the directory created by atomic_write must be owner-only
        let dmode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
    }
}
