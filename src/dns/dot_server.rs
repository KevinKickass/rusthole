use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::blocklist::BlocklistEngine;
use crate::db::Database;
use crate::dns::DohUpstream;
use crate::dns::tls;
use crate::dns_rewrite::DnsRewriteEngine;
use crate::group_policy::GroupPolicyEngine;
use crate::schedule::ScheduleEngine;

pub struct DotServer {
    blocklist: Arc<BlocklistEngine>,
    upstream: Arc<DohUpstream>,
    db: Arc<Database>,
    rewrites: Arc<DnsRewriteEngine>,
    groups: Arc<GroupPolicyEngine>,
    schedules: Arc<ScheduleEngine>,
}

impl DotServer {
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
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("DoT server listening on {addr}");

        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = tls_acceptor.clone();
            let bl = self.blocklist.clone();
            let up = self.upstream.clone();
            let db = self.db.clone();
            let rw = self.rewrites.clone();
            let gp = self.groups.clone();
            let sc = self.schedules.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(mut tls_stream) => loop {
                        let mut len_buf = [0u8; 2];
                        if tls_stream.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                        if msg_len == 0 || msg_len > 65535 {
                            break;
                        }
                        let mut data = vec![0u8; msg_len];
                        if tls_stream.read_exact(&mut data).await.is_err() {
                            break;
                        }

                        match super::handle_query(&data, peer, &bl, &up, &db, &rw, &gp, &sc).await {
                            Ok(response) => {
                                let len = (response.len() as u16).to_be_bytes();
                                if tls_stream.write_all(&len).await.is_err() {
                                    break;
                                }
                                if tls_stream.write_all(&response).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::debug!("DoT query error from {peer}: {e}");
                                break;
                            }
                        }
                    },
                    Err(e) => {
                        tracing::debug!("DoT TLS handshake error from {peer}: {e}");
                    }
                }
            });
        }
    }
}
