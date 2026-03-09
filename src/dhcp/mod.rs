use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::net::UdpSocket;

use crate::config::DhcpConfig;

#[derive(Debug, Clone, Serialize)]
pub struct LeaseInfo {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub expires_in_secs: u64,
    pub is_static: bool,
}

#[derive(Debug, Clone)]
struct Lease {
    mac: [u8; 6],
    ip: Ipv4Addr,
    hostname: Option<String>,
    expires: std::time::Instant,
    is_static: bool,
}

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;

pub struct DhcpServer {
    config: DhcpConfig,
    leases: Arc<Mutex<HashMap<[u8; 6], Lease>>>,
}

impl DhcpServer {
    pub fn new(config: DhcpConfig) -> Self {
        let leases = Arc::new(Mutex::new(HashMap::new()));

        // Pre-populate static leases
        for sl in &config.static_leases {
            if let (Some(mac), Some(ip)) = (parse_mac(&sl.mac), sl.ip.parse::<Ipv4Addr>().ok()) {
                leases.lock().insert(
                    mac,
                    Lease {
                        mac,
                        ip,
                        hostname: sl.hostname.clone(),
                        expires: std::time::Instant::now()
                            + std::time::Duration::from_secs(u64::MAX / 2),
                        is_static: true,
                    },
                );
            }
        }

        Self { config, leases }
    }

    pub fn get_leases(&self) -> Vec<LeaseInfo> {
        let now = std::time::Instant::now();
        self.leases
            .lock()
            .values()
            .filter(|l| l.is_static || l.expires > now)
            .map(|l| LeaseInfo {
                mac: format_mac(&l.mac),
                ip: l.ip.to_string(),
                hostname: l.hostname.clone(),
                expires_in_secs: if l.is_static {
                    u64::MAX
                } else {
                    l.expires.duration_since(now).as_secs()
                },
                is_static: l.is_static,
            })
            .collect()
    }

    pub fn add_static_lease(&self, mac_str: &str, ip_str: &str, hostname: Option<String>) -> bool {
        if let (Some(mac), Ok(ip)) = (parse_mac(mac_str), ip_str.parse::<Ipv4Addr>()) {
            self.leases.lock().insert(
                mac,
                Lease {
                    mac,
                    ip,
                    hostname,
                    expires: std::time::Instant::now()
                        + std::time::Duration::from_secs(u64::MAX / 2),
                    is_static: true,
                },
            );
            true
        } else {
            false
        }
    }

    pub fn remove_static_lease(&self, mac_str: &str) -> bool {
        if let Some(mac) = parse_mac(mac_str) {
            let mut leases = self.leases.lock();
            if let Some(l) = leases.get(&mac)
                && l.is_static
            {
                leases.remove(&mac);
                return true;
            }
        }
        false
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:67").await?;
        socket.set_broadcast(true)?;
        tracing::info!("DHCP server listening on 0.0.0.0:67");

        let mut buf = vec![0u8; 1500];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, _src)) => {
                    if len < 240 {
                        continue;
                    }
                    let data = &buf[..len];
                    if let Some(response) = self.handle_dhcp_packet(data) {
                        let _ = socket.send_to(&response, "255.255.255.255:68").await;
                    }
                }
                Err(e) => {
                    tracing::warn!("DHCP recv error: {e}");
                }
            }
        }
    }

    fn handle_dhcp_packet(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data[0] != 1 {
            return None;
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[28..34]);

        let msg_type = self.find_option(data, 53)?;
        let msg_type = *msg_type.first()?;

        // Extract hostname from option 12 if present
        let hostname = self
            .find_option(data, 12)
            .and_then(|h| String::from_utf8(h.to_vec()).ok());

        match msg_type {
            DHCPDISCOVER => {
                let offer_ip = self.allocate_ip(&mac, hostname)?;
                Some(self.build_response(data, &mac, offer_ip, DHCPOFFER))
            }
            DHCPREQUEST => {
                let ip = {
                    let leases = self.leases.lock();
                    leases.get(&mac)?.ip
                };
                {
                    let mut leases = self.leases.lock();
                    if let Some(lease) = leases.get_mut(&mac) {
                        if !lease.is_static {
                            lease.expires = std::time::Instant::now()
                                + std::time::Duration::from_secs(
                                    self.config.lease_time_secs as u64,
                                );
                        }
                        if hostname.is_some() {
                            lease.hostname = hostname;
                        }
                    }
                }
                Some(self.build_response(data, &mac, ip, DHCPACK))
            }
            _ => None,
        }
    }

    fn find_option<'a>(&self, data: &'a [u8], option: u8) -> Option<&'a [u8]> {
        let mut i = 240;
        while i < data.len() {
            if data[i] == 255 {
                break;
            }
            if data[i] == 0 {
                i += 1;
                continue;
            }
            if i + 1 >= data.len() {
                break;
            }
            let opt = data[i];
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }
            if opt == option {
                return Some(&data[i + 2..i + 2 + len]);
            }
            i += 2 + len;
        }
        None
    }

    fn allocate_ip(&self, mac: &[u8; 6], hostname: Option<String>) -> Option<Ipv4Addr> {
        let mut leases = self.leases.lock();

        if let Some(lease) = leases.get(mac)
            && (lease.is_static || lease.expires > std::time::Instant::now())
        {
            return Some(lease.ip);
        }

        let start: Ipv4Addr = self.config.range_start.parse().ok()?;
        let end: Ipv4Addr = self.config.range_end.parse().ok()?;
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        let now = std::time::Instant::now();
        leases.retain(|_, l| l.is_static || l.expires > now);

        let used: std::collections::HashSet<Ipv4Addr> = leases.values().map(|l| l.ip).collect();

        for ip_u32 in start_u32..=end_u32 {
            let ip = Ipv4Addr::from(ip_u32);
            if !used.contains(&ip) {
                leases.insert(
                    *mac,
                    Lease {
                        mac: *mac,
                        ip,
                        hostname,
                        expires: now
                            + std::time::Duration::from_secs(self.config.lease_time_secs as u64),
                        is_static: false,
                    },
                );
                return Some(ip);
            }
        }
        None
    }

    fn build_response(
        &self,
        request: &[u8],
        mac: &[u8; 6],
        offer_ip: Ipv4Addr,
        msg_type: u8,
    ) -> Vec<u8> {
        let mut resp = vec![0u8; 576];
        resp[0] = 2;
        resp[1] = request[1];
        resp[2] = request[2];
        resp[3] = 0;
        resp[4..8].copy_from_slice(&request[4..8]);
        resp[16..20].copy_from_slice(&offer_ip.octets());
        if let Ok(server_ip) = self.config.dns_server.parse::<Ipv4Addr>() {
            resp[20..24].copy_from_slice(&server_ip.octets());
        }
        resp[28..34].copy_from_slice(mac);
        resp[236..240].copy_from_slice(&[99, 130, 83, 99]);

        let mut i = 240;
        resp[i] = 53;
        resp[i + 1] = 1;
        resp[i + 2] = msg_type;
        i += 3;
        if let Ok(mask) = self.config.subnet_mask.parse::<Ipv4Addr>() {
            resp[i] = 1;
            resp[i + 1] = 4;
            resp[i + 2..i + 6].copy_from_slice(&mask.octets());
            i += 6;
        }
        if let Ok(gw) = self.config.gateway.parse::<Ipv4Addr>() {
            resp[i] = 3;
            resp[i + 1] = 4;
            resp[i + 2..i + 6].copy_from_slice(&gw.octets());
            i += 6;
        }
        if let Ok(dns) = self.config.dns_server.parse::<Ipv4Addr>() {
            resp[i] = 6;
            resp[i + 1] = 4;
            resp[i + 2..i + 6].copy_from_slice(&dns.octets());
            i += 6;
        }
        resp[i] = 51;
        resp[i + 1] = 4;
        resp[i + 2..i + 6].copy_from_slice(&self.config.lease_time_secs.to_be_bytes());
        i += 6;
        resp[i] = 255;

        resp
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
