use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::config::DhcpConfig;

#[derive(Debug, Clone)]
struct Lease {
    mac: [u8; 6],
    ip: Ipv4Addr,
    expires: std::time::Instant,
}

pub struct DhcpServer {
    config: DhcpConfig,
    leases: Arc<Mutex<HashMap<[u8; 6], Lease>>>,
}

// DHCP message types
const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;

impl DhcpServer {
    pub fn new(config: DhcpConfig) -> Self {
        Self {
            config,
            leases: Arc::new(Mutex::new(HashMap::new())),
        }
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
        // Basic DHCP packet parsing
        if data[0] != 1 { return None; } // Must be BOOTREQUEST

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[28..34]);

        // Find DHCP message type in options (starting at byte 240)
        let msg_type = self.find_option(data, 53)?;
        let msg_type = *msg_type.first()?;

        match msg_type {
            DHCPDISCOVER => {
                let offer_ip = self.allocate_ip(&mac)?;
                Some(self.build_response(data, &mac, offer_ip, DHCPOFFER))
            }
            DHCPREQUEST => {
                let ip = {
                    let leases = self.leases.lock();
                    leases.get(&mac)?.ip
                };
                // Renew/confirm lease
                {
                    let mut leases = self.leases.lock();
                    if let Some(lease) = leases.get_mut(&mac) {
                        lease.expires = std::time::Instant::now()
                            + std::time::Duration::from_secs(self.config.lease_time_secs as u64);
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
            if data[i] == 255 { break; }
            if data[i] == 0 { i += 1; continue; }
            if i + 1 >= data.len() { break; }
            let opt = data[i];
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() { break; }
            if opt == option {
                return Some(&data[i+2..i+2+len]);
            }
            i += 2 + len;
        }
        None
    }

    fn allocate_ip(&self, mac: &[u8; 6]) -> Option<Ipv4Addr> {
        let mut leases = self.leases.lock();

        // Return existing lease if valid
        if let Some(lease) = leases.get(mac) {
            if lease.expires > std::time::Instant::now() {
                return Some(lease.ip);
            }
        }

        let start: Ipv4Addr = self.config.range_start.parse().ok()?;
        let end: Ipv4Addr = self.config.range_end.parse().ok()?;
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        // Clean expired leases
        let now = std::time::Instant::now();
        leases.retain(|_, l| l.expires > now);

        let used: std::collections::HashSet<Ipv4Addr> = leases.values().map(|l| l.ip).collect();

        for ip_u32 in start_u32..=end_u32 {
            let ip = Ipv4Addr::from(ip_u32);
            if !used.contains(&ip) {
                leases.insert(*mac, Lease {
                    mac: *mac,
                    ip,
                    expires: now + std::time::Duration::from_secs(self.config.lease_time_secs as u64),
                });
                return Some(ip);
            }
        }
        None
    }

    fn build_response(&self, request: &[u8], mac: &[u8; 6], offer_ip: Ipv4Addr, msg_type: u8) -> Vec<u8> {
        let mut resp = vec![0u8; 576];
        resp[0] = 2; // BOOTREPLY
        resp[1] = request[1]; // htype
        resp[2] = request[2]; // hlen
        resp[3] = 0; // hops
        resp[4..8].copy_from_slice(&request[4..8]); // xid
        // yiaddr = offered IP
        resp[16..20].copy_from_slice(&offer_ip.octets());
        // siaddr = server IP
        if let Ok(server_ip) = self.config.dns_server.parse::<Ipv4Addr>() {
            resp[20..24].copy_from_slice(&server_ip.octets());
        }
        // chaddr
        resp[28..34].copy_from_slice(mac);
        // Magic cookie
        resp[236..240].copy_from_slice(&[99, 130, 83, 99]);

        let mut i = 240;
        // Option 53: DHCP Message Type
        resp[i] = 53; resp[i+1] = 1; resp[i+2] = msg_type; i += 3;
        // Option 1: Subnet Mask
        if let Ok(mask) = self.config.subnet_mask.parse::<Ipv4Addr>() {
            resp[i] = 1; resp[i+1] = 4; resp[i+2..i+6].copy_from_slice(&mask.octets()); i += 6;
        }
        // Option 3: Router
        if let Ok(gw) = self.config.gateway.parse::<Ipv4Addr>() {
            resp[i] = 3; resp[i+1] = 4; resp[i+2..i+6].copy_from_slice(&gw.octets()); i += 6;
        }
        // Option 6: DNS
        if let Ok(dns) = self.config.dns_server.parse::<Ipv4Addr>() {
            resp[i] = 6; resp[i+1] = 4; resp[i+2..i+6].copy_from_slice(&dns.octets()); i += 6;
        }
        // Option 51: Lease time
        resp[i] = 51; resp[i+1] = 4;
        resp[i+2..i+6].copy_from_slice(&self.config.lease_time_secs.to_be_bytes()); i += 6;
        // End
        resp[i] = 255;

        resp
    }
}
