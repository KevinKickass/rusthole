use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen_addr: String,
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    #[serde(default = "default_upstream")]
    pub upstream: Vec<UpstreamConfig>,
    #[serde(default)]
    pub blocklists: Vec<BlocklistSource>,
    #[serde(default)]
    pub custom_block: Vec<String>,
    #[serde(default)]
    pub custom_allow: Vec<String>,
    #[serde(default)]
    pub wildcard_block: Vec<String>,
    #[serde(default)]
    pub regex_filters: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default = "default_update_interval")]
    pub blocklist_update_interval_secs: u64,
    #[serde(default)]
    pub dhcp: Option<DhcpConfig>,
    #[serde(default)]
    pub doh_server: Option<DohServerConfig>,
    #[serde(default)]
    pub dot_server: Option<DotServerConfig>,
    #[serde(default)]
    pub dns_rewrites: Vec<DnsRewriteEntry>,
    #[serde(default)]
    pub group_policies: Vec<GroupPolicy>,
    #[serde(default)]
    pub scheduled_rules: Vec<ScheduledRule>,
    #[serde(default)]
    pub api: ApiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohServerConfig {
    pub enabled: bool,
    #[serde(default = "default_doh_port")]
    pub port: u16,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotServerConfig {
    pub enabled: bool,
    #[serde(default = "default_dot_port")]
    pub port: u16,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub url: String,
    #[serde(default = "default_upstream_type")]
    pub kind: UpstreamKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamKind {
    Doh,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSource {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub interface: String,
    pub range_start: String,
    pub range_end: String,
    pub subnet_mask: String,
    pub gateway: String,
    pub dns_server: String,
    pub lease_time_secs: u32,
    #[serde(default)]
    pub static_leases: Vec<StaticLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticLease {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRewriteEntry {
    pub domain: String,
    #[serde(default = "default_record_type")]
    pub record_type: String,
    pub value: String,
}

fn default_record_type() -> String {
    "A".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub name: String,
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub blocklists: Vec<String>,
    #[serde(default)]
    pub extra_block: Vec<String>,
    #[serde(default)]
    pub extra_allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRule {
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub blocklist_names: Vec<String>,
    pub schedule: ScheduleSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleSpec {
    #[serde(default)]
    pub days: Vec<String>,
    pub start_hour: u8,
    pub start_minute: u8,
    pub end_hour: u8,
    pub end_minute: u8,
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

fn default_timezone() -> String {
    "UTC".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default = "default_api_enabled")]
    pub enabled: bool,
}

fn default_api_enabled() -> bool {
    true
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            token: None,
            enabled: true,
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:53".into()
}
fn default_web_port() -> u16 {
    8080
}
fn default_upstream_type() -> UpstreamKind {
    UpstreamKind::Doh
}
fn default_db_path() -> PathBuf {
    PathBuf::from("rusthole.db")
}
fn default_update_interval() -> u64 {
    86400
}
fn default_doh_port() -> u16 {
    443
}
fn default_dot_port() -> u16 {
    853
}

fn default_upstream() -> Vec<UpstreamConfig> {
    vec![
        UpstreamConfig {
            url: "https://cloudflare-dns.com/dns-query".into(),
            kind: UpstreamKind::Doh,
        },
        UpstreamConfig {
            url: "https://dns.google/dns-query".into(),
            kind: UpstreamKind::Doh,
        },
    ]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
            web_port: default_web_port(),
            upstream: default_upstream(),
            blocklists: vec![
                BlocklistSource {
                    name: "Steven Black Unified".into(),
                    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
                    enabled: true,
                },
                BlocklistSource {
                    name: "AdGuard DNS".into(),
                    url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
                        .into(),
                    enabled: true,
                },
            ],
            custom_block: vec![],
            custom_allow: vec![],
            wildcard_block: vec![],
            regex_filters: vec![],
            whitelist: vec![],
            db_path: default_db_path(),
            blocklist_update_interval_secs: default_update_interval(),
            dhcp: None,
            doh_server: None,
            dot_server: None,
            dns_rewrites: vec![],
            group_policies: vec![],
            scheduled_rules: vec![],
            api: ApiConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        if std::path::Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&content)?)
        } else {
            let config = Config::default();
            let content = toml::to_string_pretty(&config)?;
            std::fs::write(path, &content)?;
            tracing::info!("Created default config at {path}");
            Ok(config)
        }
    }
}
