# 🕳️ rusthole

Lightweight DNS sinkhole / Pi-hole alternative written in Rust.

## Features

- **DNS Server** — Async UDP + TCP on port 53 via tokio + hickory-dns
- **Blocklists** — Downloads and parses hosts files (Steven Black) and AdGuard filter lists
- **Custom Rules** — Allow/block specific domains via config or API
- **Wildcard Blocking** — Block `*.ads.example.com` patterns
- **DNS-over-HTTPS** — Forwards queries to Cloudflare/Google DoH upstreams
- **Query Log** — SQLite-backed log with client IP, domain, blocked/allowed, response time
- **Statistics** — Total queries, blocked %, top domains, top clients
- **Web Dashboard** — Real-time stats, query log viewer, blocklist management (embedded in binary)
- **REST API** — Full API for all operations
- **Auto-update** — Periodic blocklist refresh
- **DHCP** — Optional DHCP server
- **Performance** — Async per-query handling, DashMap for lock-free blocklist lookups

## Quick Start

```bash
cargo build --release
sudo ./target/release/rusthole          # needs root for port 53
```

Config is auto-created as `rusthole.toml`. Dashboard at `http://localhost:8080`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/stats` | Query statistics |
| GET | `/api/queries?limit=100&offset=0&blocked=true` | Query log |
| GET | `/api/blocklist/sources` | List blocklist sources |
| POST | `/api/blocklist/sources` | Add blocklist source |
| POST | `/api/blocklist/refresh` | Refresh all blocklists |
| GET | `/api/blocklist/count` | Blocked domain count |
| POST | `/api/custom/block` | Block a domain |
| POST | `/api/custom/allow` | Allow a domain |
| POST | `/api/custom/block/remove` | Remove block rule |
| POST | `/api/custom/allow/remove` | Remove allow rule |

## Configuration

See `rusthole.toml` for all options. Key settings:

```toml
listen_addr = "0.0.0.0:53"
web_port = 8080

[[upstream]]
url = "https://cloudflare-dns.com/dns-query"
kind = "doh"

[[blocklists]]
name = "Steven Black Unified"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
enabled = true
```
