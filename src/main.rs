mod api;
mod blocklist;
mod config;
mod db;
mod dhcp;
mod dns;
mod web;

use std::sync::Arc;

use anyhow::Result;
use tower_http::cors::CorsLayer;

use crate::api::AppState;
use crate::blocklist::BlocklistEngine;
use crate::config::Config;
use crate::db::Database;
use crate::dhcp::DhcpServer;
use crate::dns::{DnsServer, DohServer, DohUpstream, DotServer};

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

    tracing::info!("🕳️  rusthole starting up");

    // Initialize database
    let db = Arc::new(Database::open(&config.db_path)?);
    tracing::info!("Database opened at {:?}", config.db_path);

    // Initialize blocklist engine
    let blocklist = Arc::new(BlocklistEngine::new(&config));

    // Download blocklists
    tracing::info!("Downloading blocklists...");
    match blocklist.refresh().await {
        Ok(count) => tracing::info!("Loaded {count} blocked domains"),
        Err(e) => tracing::warn!("Failed to load blocklists: {e}"),
    }

    // Initialize upstream resolver
    let upstream = Arc::new(DohUpstream::new(config.upstream.clone())?);

    // Start DNS server
    let dns_server = DnsServer::new(blocklist.clone(), upstream.clone(), db.clone());
    let listen_addr = config.listen_addr.clone();
    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_server.run(&listen_addr).await {
            tracing::error!("DNS server error: {e}");
        }
    });

    // Start DoH server if configured
    if let Some(ref doh_config) = config.doh_server {
        if doh_config.enabled {
            let doh = DohServer::new(blocklist.clone(), upstream.clone(), db.clone());
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
            let dot = DotServer::new(blocklist.clone(), upstream.clone(), db.clone());
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

    // Start web server (API + dashboard)
    let state = AppState {
        db: db.clone(),
        blocklist: blocklist.clone(),
    };
    let app = web::router()
        .merge(api::router(state))
        .layer(CorsLayer::permissive());

    let web_addr = format!("0.0.0.0:{}", config.web_port);
    tracing::info!("Web dashboard at http://{web_addr}");
    let listener = tokio::net::TcpListener::bind(&web_addr).await?;
    let web_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Web server error: {e}");
        }
    });

    // Auto-update blocklists periodically
    let update_bl = blocklist.clone();
    let update_interval = config.blocklist_update_interval_secs;
    let _update_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(update_interval));
        interval.tick().await; // skip first immediate tick
        loop {
            interval.tick().await;
            tracing::info!("Auto-refreshing blocklists...");
            match update_bl.refresh().await {
                Ok(count) => tracing::info!("Refreshed: {count} domains"),
                Err(e) => tracing::warn!("Blocklist refresh failed: {e}"),
            }
        }
    });

    // Optional DHCP server
    if let Some(dhcp_config) = config.dhcp {
        if dhcp_config.enabled {
            let dhcp = DhcpServer::new(dhcp_config);
            tokio::spawn(async move {
                if let Err(e) = dhcp.run().await {
                    tracing::error!("DHCP server error: {e}");
                }
            });
        }
    }

    tokio::select! {
        r = dns_handle => { r?; }
        r = web_handle => { r?; }
    }

    Ok(())
}
