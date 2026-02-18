use anyhow::Result;
use dashmap::DashSet;
use regex::Regex;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::{BlocklistSource, Config};

/// The blocklist engine: checks domains against loaded blocklists, custom rules, wildcards, regex, and whitelist.
pub struct BlocklistEngine {
    blocked_domains: Arc<DashSet<String>>,
    allowed_domains: Arc<DashSet<String>>,
    whitelist: Arc<DashSet<String>>,
    wildcard_blocks: Arc<RwLock<Vec<String>>>,
    regex_filters: Arc<RwLock<Vec<CompiledRegex>>>,
    sources: Arc<RwLock<Vec<BlocklistSource>>>,
}

struct CompiledRegex {
    pattern: String,
    regex: Regex,
}

impl BlocklistEngine {
    pub fn new(config: &Config) -> Self {
        let allowed = Arc::new(DashSet::new());
        for d in &config.custom_allow {
            allowed.insert(d.to_lowercase());
        }
        let blocked = Arc::new(DashSet::new());
        for d in &config.custom_block {
            blocked.insert(d.to_lowercase());
        }
        let whitelist = Arc::new(DashSet::new());
        for d in &config.whitelist {
            whitelist.insert(d.to_lowercase());
        }
        // Also add custom_allow to whitelist for unified behavior
        for d in &config.custom_allow {
            whitelist.insert(d.to_lowercase());
        }
        let wildcards: Vec<String> = config.wildcard_block.iter().map(|w| w.to_lowercase()).collect();

        let mut compiled_regex = Vec::new();
        for pattern in &config.regex_filters {
            match Regex::new(pattern) {
                Ok(regex) => compiled_regex.push(CompiledRegex {
                    pattern: pattern.clone(),
                    regex,
                }),
                Err(e) => tracing::warn!("Invalid regex filter '{pattern}': {e}"),
            }
        }

        Self {
            blocked_domains: blocked,
            allowed_domains: allowed,
            whitelist,
            wildcard_blocks: Arc::new(RwLock::new(wildcards)),
            regex_filters: Arc::new(RwLock::new(compiled_regex)),
            sources: Arc::new(RwLock::new(config.blocklists.clone())),
        }
    }

    /// Is this domain blocked?
    pub async fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let domain = domain.trim_end_matches('.');

        // Whitelist takes highest priority — always allow
        if self.whitelist.contains(domain) {
            return false;
        }

        // Legacy allowlist also takes priority
        if self.allowed_domains.contains(domain) {
            return false;
        }

        // Exact block match
        if self.blocked_domains.contains(domain) {
            return true;
        }

        // Wildcard matching: check if domain or any parent matches
        let wildcards = self.wildcard_blocks.read().await;
        for wc in wildcards.iter() {
            let pattern = wc.trim_start_matches("*.");
            if domain == pattern || domain.ends_with(&format!(".{pattern}")) {
                return true;
            }
        }

        // Regex filter matching
        let regexes = self.regex_filters.read().await;
        for cr in regexes.iter() {
            if cr.regex.is_match(domain) {
                return true;
            }
        }

        false
    }

    /// Check if a CNAME target domain is blocked (for CNAME cloaking detection)
    pub async fn is_cname_cloaked(&self, original_domain: &str, cname_target: &str) -> bool {
        let original = original_domain.to_lowercase();
        let target = cname_target.to_lowercase().trim_end_matches('.').to_string();

        // If the original domain is whitelisted, don't flag CNAME cloaking
        if self.whitelist.contains(original.as_str()) || self.allowed_domains.contains(original.as_str()) {
            return false;
        }

        // If the CNAME target resolves to a known tracker/ad domain, it's cloaking
        if self.blocked_domains.contains(&target) {
            tracing::info!("CNAME cloaking detected: {original} -> {target}");
            return true;
        }

        // Check wildcards against the CNAME target
        let wildcards = self.wildcard_blocks.read().await;
        for wc in wildcards.iter() {
            let pattern = wc.trim_start_matches("*.");
            if target == pattern || target.ends_with(&format!(".{pattern}")) {
                tracing::info!("CNAME cloaking (wildcard) detected: {original} -> {target}");
                return true;
            }
        }

        // Check regex filters against the CNAME target
        let regexes = self.regex_filters.read().await;
        for cr in regexes.iter() {
            if cr.regex.is_match(&target) {
                tracing::info!("CNAME cloaking (regex) detected: {original} -> {target}");
                return true;
            }
        }

        false
    }

    /// Load/refresh all enabled blocklists from their URLs.
    pub async fn refresh(&self) -> Result<usize> {
        let sources = self.sources.read().await.clone();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let mut total = 0usize;
        for source in &sources {
            if !source.enabled {
                continue;
            }
            tracing::info!("Downloading blocklist: {} from {}", source.name, source.url);
            match client.get(&source.url).send().await {
                Ok(resp) => {
                    if let Ok(text) = resp.text().await {
                        let count = self.parse_blocklist(&text);
                        tracing::info!("  Loaded {} domains from {}", count, source.name);
                        total += count;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to download {}: {e}", source.name);
                }
            }
        }
        tracing::info!("Total blocked domains: {}", self.blocked_domains.len());
        Ok(total)
    }

    fn parse_blocklist(&self, text: &str) -> usize {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            // hosts file format: "0.0.0.0 domain" or "127.0.0.1 domain"
            if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
                if let Some(domain) = line.split_whitespace().nth(1) {
                    let domain = domain.to_lowercase();
                    if domain != "localhost" && domain != "localhost.localdomain" && !domain.is_empty() {
                        self.blocked_domains.insert(domain);
                        count += 1;
                    }
                }
                continue;
            }

            // AdGuard/ABP format: ||domain^
            if line.starts_with("||") && line.ends_with('^') {
                let domain = &line[2..line.len()-1];
                if !domain.is_empty() && !domain.contains('/') {
                    self.blocked_domains.insert(domain.to_lowercase());
                    count += 1;
                }
                continue;
            }

            // Plain domain format
            if !line.contains(' ') && !line.contains('/') && line.contains('.') {
                self.blocked_domains.insert(line.to_lowercase());
                count += 1;
            }
        }
        count
    }

    pub fn domain_count(&self) -> usize {
        self.blocked_domains.len()
    }

    pub fn add_blocked(&self, domain: &str) {
        self.blocked_domains.insert(domain.to_lowercase());
    }

    pub fn add_allowed(&self, domain: &str) {
        self.allowed_domains.insert(domain.to_lowercase());
    }

    pub fn remove_blocked(&self, domain: &str) {
        self.blocked_domains.remove(&domain.to_lowercase());
    }

    pub fn remove_allowed(&self, domain: &str) {
        self.allowed_domains.remove(&domain.to_lowercase());
    }

    // Whitelist management
    pub fn add_whitelist(&self, domain: &str) {
        self.whitelist.insert(domain.to_lowercase());
    }

    pub fn remove_whitelist(&self, domain: &str) {
        self.whitelist.remove(&domain.to_lowercase());
    }

    pub fn get_whitelist(&self) -> Vec<String> {
        self.whitelist.iter().map(|r| r.key().clone()).collect()
    }

    // Regex filter management
    pub async fn add_regex_filter(&self, pattern: &str) -> Result<()> {
        let regex = Regex::new(pattern)?;
        self.regex_filters.write().await.push(CompiledRegex {
            pattern: pattern.to_string(),
            regex,
        });
        Ok(())
    }

    pub async fn remove_regex_filter(&self, pattern: &str) -> bool {
        let mut filters = self.regex_filters.write().await;
        let before = filters.len();
        filters.retain(|cr| cr.pattern != pattern);
        filters.len() < before
    }

    pub async fn get_regex_filters(&self) -> Vec<String> {
        self.regex_filters.read().await.iter().map(|cr| cr.pattern.clone()).collect()
    }

    pub async fn get_sources(&self) -> Vec<BlocklistSource> {
        self.sources.read().await.clone()
    }

    pub async fn add_source(&self, source: BlocklistSource) {
        self.sources.write().await.push(source);
    }

    pub async fn remove_source(&self, name: &str) -> bool {
        let mut sources = self.sources.write().await;
        let before = sources.len();
        sources.retain(|s| s.name != name);
        sources.len() < before
    }

    pub async fn toggle_source(&self, name: &str, enabled: bool) -> bool {
        let mut sources = self.sources.write().await;
        for s in sources.iter_mut() {
            if s.name == name {
                s.enabled = enabled;
                return true;
            }
        }
        false
    }
}
