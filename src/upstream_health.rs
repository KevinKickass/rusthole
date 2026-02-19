use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::Serialize;

use crate::config::UpstreamConfig;

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatus {
    pub url: String,
    pub healthy: bool,
    pub latency_ms: Option<f64>,
    pub last_check: Option<String>,
    pub consecutive_failures: u32,
    pub total_queries: u64,
    pub total_failures: u64,
}

struct UpstreamState {
    url: String,
    healthy: bool,
    latency_ms: Option<f64>,
    last_check: Option<Instant>,
    consecutive_failures: u32,
    total_queries: u64,
    total_failures: u64,
    kind: crate::config::UpstreamKind,
}

pub struct UpstreamHealthMonitor {
    states: Arc<RwLock<Vec<UpstreamState>>>,
}

impl UpstreamHealthMonitor {
    pub fn new(upstreams: &[UpstreamConfig]) -> Self {
        let states = upstreams
            .iter()
            .map(|u| UpstreamState {
                url: u.url.clone(),
                healthy: true,
                latency_ms: None,
                last_check: None,
                consecutive_failures: 0,
                total_queries: 0,
                total_failures: 0,
                kind: u.kind.clone(),
            })
            .collect();
        Self {
            states: Arc::new(RwLock::new(states)),
        }
    }

    /// Get the index of the best healthy upstream (round-robin among healthy ones).
    pub fn pick_upstream(&self, counter: usize) -> Option<usize> {
        let states = self.states.read();
        let healthy_indices: Vec<usize> = states
            .iter()
            .enumerate()
            .filter(|(_, s)| s.healthy)
            .map(|(i, _)| i)
            .collect();

        if healthy_indices.is_empty() {
            // Fallback: try all upstreams if all are "unhealthy"
            if states.is_empty() {
                None
            } else {
                Some(counter % states.len())
            }
        } else {
            Some(healthy_indices[counter % healthy_indices.len()])
        }
    }

    /// Record a successful query to an upstream.
    pub fn record_success(&self, idx: usize, latency: Duration) {
        let mut states = self.states.write();
        if let Some(state) = states.get_mut(idx) {
            state.healthy = true;
            state.latency_ms = Some(latency.as_secs_f64() * 1000.0);
            state.last_check = Some(Instant::now());
            state.consecutive_failures = 0;
            state.total_queries += 1;
        }
    }

    /// Record a failed query to an upstream.
    pub fn record_failure(&self, idx: usize) {
        let mut states = self.states.write();
        if let Some(state) = states.get_mut(idx) {
            state.consecutive_failures += 1;
            state.total_failures += 1;
            state.total_queries += 1;
            state.last_check = Some(Instant::now());
            // Mark unhealthy after 3 consecutive failures
            if state.consecutive_failures >= 3 {
                state.healthy = false;
                tracing::warn!("Upstream {} marked unhealthy after {} failures", state.url, state.consecutive_failures);
            }
        }
    }

    /// Get status of all upstreams for the dashboard.
    pub fn get_status(&self) -> Vec<UpstreamStatus> {
        let states = self.states.read();
        states
            .iter()
            .map(|s| {
                let last_check = s.last_check.map(|t| {
                    let elapsed = t.elapsed();
                    format!("{}s ago", elapsed.as_secs())
                });
                UpstreamStatus {
                    url: s.url.clone(),
                    healthy: s.healthy,
                    latency_ms: s.latency_ms,
                    last_check,
                    consecutive_failures: s.consecutive_failures,
                    total_queries: s.total_queries,
                    total_failures: s.total_failures,
                }
            })
            .collect()
    }

    /// Background health check task — probe each upstream with a simple DNS query.
    pub async fn run_health_checks(self: Arc<Self>, upstreams: Vec<UpstreamConfig>) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Simple DNS query for "." (root) as a health probe
        let probe_query = build_probe_query();

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            for (idx, upstream) in upstreams.iter().enumerate() {
                let start = Instant::now();
                let result = match upstream.kind {
                    crate::config::UpstreamKind::Doh => {
                        client
                            .post(&upstream.url)
                            .header("content-type", "application/dns-message")
                            .header("accept", "application/dns-message")
                            .body(probe_query.clone())
                            .send()
                            .await
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    }
                    crate::config::UpstreamKind::Udp => {
                        match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                            Ok(socket) => {
                                if socket.send_to(&probe_query, &upstream.url).await.is_err() {
                                    Err("send failed".into())
                                } else {
                                    let mut buf = vec![0u8; 512];
                                    match tokio::time::timeout(
                                        Duration::from_secs(5),
                                        socket.recv_from(&mut buf),
                                    )
                                    .await
                                    {
                                        Ok(Ok(_)) => Ok(()),
                                        _ => Err("timeout".into()),
                                    }
                                }
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                };
                let latency = start.elapsed();
                match result {
                    Ok(()) => self.record_success(idx, latency),
                    Err(_) => self.record_failure(idx),
                }
            }
        }
    }
}

/// Build a minimal DNS query for "." type NS as a health probe.
fn build_probe_query() -> Vec<u8> {
    use hickory_proto::op::{Header, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;

    let mut msg = Message::new();
    let mut header = Header::new();
    header.set_id(0x1234);
    header.set_message_type(MessageType::Query);
    header.set_op_code(OpCode::Query);
    header.set_recursion_desired(true);
    msg.set_header(header);

    let mut query = Query::new();
    query.set_name(Name::root());
    query.set_query_type(RecordType::NS);
    msg.add_query(query);

    msg.to_bytes().unwrap_or_default()
}
