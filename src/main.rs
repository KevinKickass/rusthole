mod api;
mod blocklist;
mod config;
mod db;
mod dhcp;
mod dns;
mod dns_rewrite;
mod group_policy;
mod schedule;
mod upstream_health;
mod web;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use tower_http::cors::CorsLayer;

use crate::api::AppState;
use crate::blocklist::BlocklistEngine;
use crate::config::Config;
use crate::db::Database;
use crate::dhcp::DhcpServer;
use crate::dns::{DnsServer, DohServer, DohUpstream, DotServer};
use crate::dns_rewrite::DnsRewriteEngine;
use crate::group_policy::GroupPolicyEngine;
use crate::schedule::ScheduleEngine;
use crate::upstream_health::UpstreamHealthMonitor;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rusthole=info".parse().unwrap()),
        )
        .init();

    let config_path = std::env::args().nth(1).unwrap_or_else(|| "rusthole.toml".into());
    let config = Config::load(&config_path)?;

    tracing::info!("🕳️  rusthole v0.3.0 starting up");

    let db = Arc::new(Database::open(&config.db_path)?);
    tracing::info!("Database opened at {:?}", config.db_path);

    let blocklist = Arc::new(BlocklistEngine::new(&config));

    tracing::info!("Downloading blocklists...");
    match blocklist.refresh().await {
        Ok(count) => tracing::info!("Loaded {count} blocked domains"),
        Err(e) => tracing::warn!("Failed to load blocklists: {e}"),
    }

    // Initialize upstream health monitor
    let health = Arc::new(UpstreamHealthMonitor::new(&config.upstream));

    // Start background health checks
    let health_check = health.clone();
    let upstreams_for_health = config.upstream.clone();
    tokio::spawn(async move {
        health_check.run_health_checks(upstreams_for_health).await;
    });

    let upstream = Arc::new(DohUpstream::new(config.upstream.clone(), health.clone())?);

    // Initialize DNS rewrites
    let rewrites = Arc::new(DnsRewriteEngine::new(&config.dns_rewrites));
    if !config.dns_rewrites.is_empty() {
        tracing::info!("Loaded {} DNS rewrite rules", config.dns_rewrites.len());
    }

    // Initialize group policies
    let groups = Arc::new(GroupPolicyEngine::new(&config.group_policies));
    if !config.group_policies.is_empty() {
        tracing::info!("Loaded {} group policies", config.group_policies.len());
    }

    // Initialize scheduled blocking
    let schedules = Arc::new(ScheduleEngine::new(&config.scheduled_rules));
    if !config.scheduled_rules.is_empty() {
        tracing::info!("Loaded {} scheduled rules", config.scheduled_rules.len());
    }

    let blocking_enabled = Arc::new(AtomicBool::new(true));

    // Start DNS server
    let dns_server = DnsServer::new(
        blocklist.clone(), upstream.clone(), db.clone(),
        rewrites.clone(), groups.clone(), schedules.clone(),
    );
    let listen_addr = config.listen_addr.clone();
    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_server.run(&listen_addr).await {
            tracing::error!("DNS server error: {e}");
        }
    });

    // Start DoH server if configured
    if let Some(ref doh_config) = config.doh_server {
        if doh_config.enabled {
            let doh = DohServer::new(
                blocklist.clone(), upstream.clone(), db.clone(),
                rewrites.clone(), groups.clone(), schedules.clone(),
            );
            let port = doh_config.port;
            let cert = doh_config.cert_path.clone();
            let key = doh_config.key_path.clone();
            tokio::spawn(async move {
                if let Err(e) = doh.run(port, cert.as_deref(), key.as_deref()).await {
                    tracing::error!("DoH server error: {e}");
                }
            });
        }
    }

    // Start DoT server if configured
    if let Some(ref dot_config) = config.dot_server {
        if dot_config.enabled {
            let dot = DotServer::new(
                blocklist.clone(), upstream.clone(), db.clone(),
                rewrites.clone(), groups.clone(), schedules.clone(),
            );
            let port = dot_config.port;
            let cert = dot_config.cert_path.clone();
            let key = dot_config.key_path.clone();
            tokio::spawn(async move {
                if let Err(e) = dot.run(port, cert.as_deref(), key.as_deref()).await {
                    tracing::error!("DoT server error: {e}");
                }
            });
        }
    }

    // Optional DHCP server
    let dhcp_server: Option<Arc<DhcpServer>> = if let Some(dhcp_config) = config.dhcp {
        if dhcp_config.enabled {
            let dhcp = Arc::new(DhcpServer::new(dhcp_config));
            let dhcp_run = dhcp.clone();
            tokio::spawn(async move {
                if let Err(e) = dhcp_run.run().await {
                    tracing::error!("DHCP server error: {e}");
                }
            });
            Some(dhcp)
        } else {
            None
        }
    } else {
        None
    };

    // Start web server (API + dashboard)
    let state = AppState {
        db: db.clone(),
        blocklist: blocklist.clone(),
        rewrites: rewrites.clone(),
        groups: groups.clone(),
        schedules: schedules.clone(),
        upstream_health: health.clone(),
        dhcp: dhcp_server,
        api_token: config.api.token.clone(),
        blocking_enabled,
    };
    let app = web::router()
        .merge(api::router(state))
        .layer(CorsLayer::permissive());

    let web_addr = format!("0.0.0.0:{}", config.web_port);
    tracing::info!("Web dashboard at http://{web_addr}");
    if config.api.token.is_some() {
        tracing::info!("API authentication enabled");
    }
    let listener = tokio::net::TcpListener::bind(&web_addr).await?;
    let web_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Web server error: {e}");
        }
    });

    // Auto-update blocklists
    let update_bl = blocklist.clone();
    let update_interval = config.blocklist_update_interval_secs;
    let _update_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(update_interval));
        interval.tick().await;
        loop {
            interval.tick().await;
            tracing::info!("Auto-refreshing blocklists...");
            match update_bl.refresh().await {
                Ok(count) => tracing::info!("Refreshed: {count} domains"),
                Err(e) => tracing::warn!("Blocklist refresh failed: {e}"),
            }
        }
    });

    tokio::select! {
        r = dns_handle => { r?; }
        r = web_handle => { r?; }
    }

    Ok(())
}
