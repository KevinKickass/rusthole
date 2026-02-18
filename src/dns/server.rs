use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::blocklist::BlocklistEngine;
use crate::db::Database;
use crate::dns::DohUpstream;

pub struct DnsServer {
    blocklist: Arc<BlocklistEngine>,
    upstream: Arc<DohUpstream>,
    db: Arc<Database>,
}

impl DnsServer {
    pub fn new(
        blocklist: Arc<BlocklistEngine>,
        upstream: Arc<DohUpstream>,
        db: Arc<Database>,
    ) -> Self {
        Self { blocklist, upstream, db }
    }

    pub async fn run(&self, listen_addr: &str) -> Result<()> {
        let udp_socket = UdpSocket::bind(listen_addr).await?;
        let tcp_listener = TcpListener::bind(listen_addr).await?;
        tracing::info!("DNS server listening on {listen_addr} (UDP+TCP)");

        let udp_bl = self.blocklist.clone();
        let udp_up = self.upstream.clone();
        let udp_db = self.db.clone();

        let tcp_bl = self.blocklist.clone();
        let tcp_up = self.upstream.clone();
        let tcp_db = self.db.clone();

        let udp_socket = Arc::new(udp_socket);

        // UDP handler
        let udp_handle = tokio::spawn({
            let socket = udp_socket.clone();
            async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, src)) => {
                            let data = buf[..len].to_vec();
                            let bl = udp_bl.clone();
                            let up = udp_up.clone();
                            let db = udp_db.clone();
                            let sock = socket.clone();
                            tokio::spawn(async move {
                                match handle_query(&data, src, &bl, &up, &db).await {
                                    Ok(response) => {
                                        let _ = sock.send_to(&response, src).await;
                                    }
                                    Err(e) => {
                                        tracing::debug!("UDP query error from {src}: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("UDP recv error: {e}");
                        }
                    }
                }
            }
        });

        // TCP handler
        let tcp_handle = tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((mut stream, src)) => {
                        let bl = tcp_bl.clone();
                        let up = tcp_up.clone();
                        let db = tcp_db.clone();
                        tokio::spawn(async move {
                            // DNS over TCP: 2-byte length prefix
                            let mut len_buf = [0u8; 2];
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                return;
                            }
                            let msg_len = u16::from_be_bytes(len_buf) as usize;
                            let mut data = vec![0u8; msg_len];
                            if stream.read_exact(&mut data).await.is_err() {
                                return;
                            }
                            match handle_query(&data, src, &bl, &up, &db).await {
                                Ok(response) => {
                                    let len = (response.len() as u16).to_be_bytes();
                                    let _ = stream.write_all(&len).await;
                                    let _ = stream.write_all(&response).await;
                                }
                                Err(e) => {
                                    tracing::debug!("TCP query error from {src}: {e}");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("TCP accept error: {e}");
                    }
                }
            }
        });

        tokio::select! {
            r = udp_handle => { r?; }
            r = tcp_handle => { r?; }
        }
        Ok(())
    }
}

/// Handle a DNS query — shared by plain DNS, DoH, and DoT servers.
pub async fn handle_query(
    data: &[u8],
    client: SocketAddr,
    blocklist: &BlocklistEngine,
    upstream: &DohUpstream,
    db: &Database,
) -> Result<Vec<u8>> {
    let start = Instant::now();
    let request = Message::from_bytes(data)?;

    let question = match request.queries().first() {
        Some(q) => q,
        None => return build_error_response(&request, ResponseCode::FormErr),
    };

    let domain = question.name().to_string();
    let domain_clean = domain.trim_end_matches('.');
    let qtype = question.query_type();
    let qtype_str = format!("{qtype}");

    // Check blocklist
    let blocked = blocklist.is_blocked(domain_clean).await;
    let mut cname_cloaked = false;

    let response_bytes = if blocked {
        // Return 0.0.0.0 for A, :: for AAAA, NXDOMAIN for others
        build_blocked_response(&request, question.name(), qtype)?
    } else {
        // Forward to upstream
        match upstream.resolve(data).await {
            Ok(bytes) => {
                // CNAME cloaking detection: inspect response for CNAME records
                if let Ok(response_msg) = Message::from_bytes(&bytes) {
                    for answer in response_msg.answers() {
                        if let RData::CNAME(cname) = answer.data() {
                            let cname_str = cname.0.to_string();
                            let cname_clean = cname_str.trim_end_matches('.');
                            if blocklist.is_cname_cloaked(domain_clean, cname_clean).await {
                                cname_cloaked = true;
                                // Block this response — the CNAME points to a tracker
                                let blocked_resp = build_blocked_response(&request, question.name(), qtype)?;
                                let elapsed = start.elapsed();
                                let db2 = db.clone();
                                let client_ip = client.ip().to_string();
                                let domain_log = domain_clean.to_string();
                                let qtype_log = qtype_str.clone();
                                tokio::spawn(async move {
                                    let _ = db2.log_query(&client_ip, &domain_log, &qtype_log, true, elapsed.as_micros() as i64, None, true);
                                });
                                tracing::debug!("CNAME CLOAKED {domain_clean} -> {cname_clean} from {client}");
                                return Ok(blocked_resp);
                            }
                        }
                    }
                }
                bytes
            }
            Err(e) => {
                tracing::warn!("Upstream error for {domain_clean}: {e}");
                build_error_response(&request, ResponseCode::ServFail)?
            }
        }
    };

    let elapsed = start.elapsed();
    let upstream_name: Option<String> = if blocked { None } else { Some(upstream.upstream_name().to_string()) };

    // Log to DB (fire and forget)
    let db = db.clone();
    let client_ip = client.ip().to_string();
    let domain_log = domain_clean.to_string();
    let qtype_log = qtype_str.clone();
    tokio::spawn(async move {
        if let Err(e) = db.log_query(
            &client_ip,
            &domain_log,
            &qtype_log,
            blocked,
            elapsed.as_micros() as i64,
            upstream_name.as_deref(),
            cname_cloaked,
        ) {
            tracing::debug!("Failed to log query: {e}");
        }
    });

    if blocked {
        tracing::debug!("BLOCKED {domain_clean} ({qtype_str}) from {client}");
    }

    Ok(response_bytes)
}

pub fn build_blocked_response(request: &Message, name: &Name, qtype: RecordType) -> Result<Vec<u8>> {
    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(false);
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);

    response.add_queries(request.queries().iter().cloned());

    match qtype {
        RecordType::A => {
            let rdata = RData::A("0.0.0.0".parse().unwrap());
            let record = Record::from_rdata(name.clone(), 300, rdata);
            response.add_answer(record);
        }
        RecordType::AAAA => {
            let rdata = RData::AAAA("::".parse().unwrap());
            let record = Record::from_rdata(name.clone(), 300, rdata);
            response.add_answer(record);
        }
        _ => {
            header.set_response_code(ResponseCode::NXDomain);
            response.set_header(header);
        }
    }

    Ok(response.to_bytes()?)
}

pub fn build_error_response(request: &Message, rcode: ResponseCode) -> Result<Vec<u8>> {
    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_message_type(MessageType::Response);
    header.set_response_code(rcode);
    header.set_recursion_available(true);
    response.set_header(header);
    response.add_queries(request.queries().iter().cloned());
    Ok(response.to_bytes()?)
}
