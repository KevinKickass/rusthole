use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::blocklist::BlocklistEngine;
use crate::db::Database;
use crate::dns::DohUpstream;
use crate::dns::tls;
use crate::dns_rewrite::DnsRewriteEngine;
use crate::group_policy::GroupPolicyEngine;
use crate::schedule::ScheduleEngine;

#[derive(Clone)]
struct DohState {
    blocklist: Arc<BlocklistEngine>,
    upstream: Arc<DohUpstream>,
    db: Arc<Database>,
    rewrites: Arc<DnsRewriteEngine>,
    groups: Arc<GroupPolicyEngine>,
    schedules: Arc<ScheduleEngine>,
}

pub struct DohServer {
    blocklist: Arc<BlocklistEngine>,
    upstream: Arc<DohUpstream>,
    db: Arc<Database>,
    rewrites: Arc<DnsRewriteEngine>,
    groups: Arc<GroupPolicyEngine>,
    schedules: Arc<ScheduleEngine>,
}

impl DohServer {
    pub fn new(
        blocklist: Arc<BlocklistEngine>,
        upstream: Arc<DohUpstream>,
        db: Arc<Database>,
        rewrites: Arc<DnsRewriteEngine>,
        groups: Arc<GroupPolicyEngine>,
        schedules: Arc<ScheduleEngine>,
    ) -> Self {
        Self {
            blocklist,
            upstream,
            db,
            rewrites,
            groups,
            schedules,
        }
    }

    pub async fn run(
        &self,
        port: u16,
        cert_path: Option<&str>,
        key_path: Option<&str>,
    ) -> Result<()> {
        let tls_config = tls::load_tls_config(cert_path, key_path)?;

        let state = DohState {
            blocklist: self.blocklist.clone(),
            upstream: self.upstream.clone(),
            db: self.db.clone(),
            rewrites: self.rewrites.clone(),
            groups: self.groups.clone(),
            schedules: self.schedules.clone(),
        };

        let app = Router::new()
            .route("/dns-query", get(doh_get))
            .route("/dns-query", post(doh_post))
            .with_state(state);

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("DoH server listening on https://{addr}/dns-query");

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let listener = tokio::net::TcpListener::bind(addr).await?;

        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = tls_acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        let service = hyper_util::service::TowerToHyperService::new(app);
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, service)
                        .await
                        {
                            tracing::debug!("DoH connection error from {peer}: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::debug!("DoH TLS handshake error from {peer}: {e}");
                    }
                }
            });
        }
    }
}

#[derive(serde::Deserialize)]
struct DohGetParams {
    dns: String,
}

async fn doh_get(
    State(state): State<DohState>,
    headers: HeaderMap,
    Query(params): Query<DohGetParams>,
) -> Result<(StatusCode, HeaderMap, Vec<u8>), StatusCode> {
    let query_bytes = URL_SAFE_NO_PAD
        .decode(&params.dns)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    process_doh(state, &query_bytes, &headers).await
}

async fn doh_post(
    State(state): State<DohState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Vec<u8>), StatusCode> {
    process_doh(state, &body, &headers).await
}

async fn process_doh(
    state: DohState,
    query_bytes: &[u8],
    _headers: &HeaderMap,
) -> Result<(StatusCode, HeaderMap, Vec<u8>), StatusCode> {
    let client_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let response = super::handle_query(
        query_bytes,
        client_addr,
        &state.blocklist,
        &state.upstream,
        &state.db,
        &state.rewrites,
        &state.groups,
        &state.schedules,
    )
    .await
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("content-type", "application/dns-message".parse().unwrap());
    resp_headers.insert("cache-control", "max-age=300".parse().unwrap());

    Ok((StatusCode::OK, resp_headers, response))
}
