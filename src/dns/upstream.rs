use anyhow::Result;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{UpstreamConfig, UpstreamKind};

pub struct DohUpstream {
    client: Client,
    upstreams: Vec<UpstreamConfig>,
    next: AtomicUsize,
}

impl DohUpstream {
    pub fn new(upstreams: Vec<UpstreamConfig>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        Ok(Self {
            client,
            upstreams,
            next: AtomicUsize::new(0),
        })
    }

    /// Forward a raw DNS query and return the raw response bytes.
    pub async fn resolve(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.upstreams.len();
        let upstream = &self.upstreams[idx];

        match upstream.kind {
            UpstreamKind::Doh => self.resolve_doh(&upstream.url, query_bytes).await,
            UpstreamKind::Udp => self.resolve_udp(&upstream.url, query_bytes).await,
        }
    }

    pub fn upstream_name(&self) -> &str {
        let idx = self.next.load(Ordering::Relaxed).wrapping_sub(1) % self.upstreams.len();
        &self.upstreams[idx].url
    }

    async fn resolve_doh(&self, url: &str, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let resp = self.client
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
        // Validate it's a valid DNS message
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
        ).await??;
        buf.truncate(len);
        Ok(buf)
    }
}
