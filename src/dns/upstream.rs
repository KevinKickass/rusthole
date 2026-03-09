use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Result;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use reqwest::Client;

use crate::config::{UpstreamConfig, UpstreamKind};
use crate::upstream_health::UpstreamHealthMonitor;

pub struct DohUpstream {
    client: Client,
    upstreams: Vec<UpstreamConfig>,
    next: AtomicUsize,
    health: Arc<UpstreamHealthMonitor>,
}

impl DohUpstream {
    pub fn new(upstreams: Vec<UpstreamConfig>, health: Arc<UpstreamHealthMonitor>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        Ok(Self {
            client,
            upstreams,
            next: AtomicUsize::new(0),
            health,
        })
    }

    /// Forward a raw DNS query and return the raw response bytes.
    /// Uses health-aware upstream selection with auto-failover.
    pub async fn resolve(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let counter = self.next.fetch_add(1, Ordering::Relaxed);

        // Try the health-picked upstream first, then failover to others
        let primary_idx = self.health.pick_upstream(counter).unwrap_or(0);

        match self.try_resolve(primary_idx, query_bytes).await {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                tracing::warn!(
                    "Primary upstream {} failed: {e}, trying failover",
                    self.upstreams[primary_idx].url
                );
                // Try all other upstreams
                for idx in 0..self.upstreams.len() {
                    if idx == primary_idx {
                        continue;
                    }
                    match self.try_resolve(idx, query_bytes).await {
                        Ok(bytes) => return Ok(bytes),
                        Err(e) => {
                            tracing::warn!(
                                "Failover upstream {} failed: {e}",
                                self.upstreams[idx].url
                            );
                        }
                    }
                }
                anyhow::bail!("All upstreams failed")
            }
        }
    }

    async fn try_resolve(&self, idx: usize, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let upstream = &self.upstreams[idx];
        let start = Instant::now();

        let result = match upstream.kind {
            UpstreamKind::Doh => self.resolve_doh(&upstream.url, query_bytes).await,
            UpstreamKind::Udp => self.resolve_udp(&upstream.url, query_bytes).await,
        };

        match &result {
            Ok(_) => self.health.record_success(idx, start.elapsed()),
            Err(_) => self.health.record_failure(idx),
        }

        result
    }

    pub fn upstream_name(&self) -> &str {
        let idx = self.next.load(Ordering::Relaxed).wrapping_sub(1) % self.upstreams.len();
        &self.upstreams[idx].url
    }

    #[allow(dead_code)]
    pub fn health_monitor(&self) -> &Arc<UpstreamHealthMonitor> {
        &self.health
    }

    async fn resolve_doh(&self, url: &str, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let resp = self
            .client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query_bytes.to_vec())
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("DoH upstream returned {}", resp.status());
        }

        let bytes = resp.bytes().await?;
        let _ = Message::from_bytes(&bytes)?;
        Ok(bytes.to_vec())
    }

    async fn resolve_udp(&self, addr: &str, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query_bytes, addr).await?;
        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        )
        .await??;
        buf.truncate(len);
        Ok(buf)
    }
}
