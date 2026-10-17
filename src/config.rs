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
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create dir {:?}", parent))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)
        .with_context(|| format!("failed to write tmp file {:?}", tmp))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {:?} to {:?}", tmp, path))?;
    Ok(())
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
