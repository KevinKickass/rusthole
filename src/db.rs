use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Serialize, Clone)]
pub struct QueryLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub blocked: bool,
    pub response_time_us: i64,
    pub upstream: Option<String>,
    pub cname_cloaked: bool,
}

#[derive(Debug, Serialize, Default)]
pub struct Stats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub allowed_queries: u64,
    pub blocked_percentage: f64,
    pub top_blocked: Vec<(String, u64)>,
    pub top_allowed: Vec<(String, u64)>,
    pub top_clients: Vec<(String, u64)>,
    pub queries_last_24h: Vec<(String, u64)>,
}

#[derive(Debug, Serialize, Default)]
pub struct ClientStats {
    pub client_ip: String,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub allowed_queries: u64,
    pub top_domains: Vec<(String, u64)>,
    pub top_blocked_domains: Vec<(String, u64)>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA cache_size=-8000;
            PRAGMA busy_timeout=5000;

            CREATE TABLE IF NOT EXISTS query_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                blocked INTEGER NOT NULL,
                response_time_us INTEGER NOT NULL,
                upstream TEXT,
                cname_cloaked INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);
            CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client_ip);
            CREATE INDEX IF NOT EXISTS idx_query_log_blocked ON query_log(blocked);
        ")?;

        // Add cname_cloaked column if missing (migration)
        let has_cname: bool = conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('query_log') WHERE name='cname_cloaked'")?
            .query_row([], |r| r.get::<_, i64>(0))
            .unwrap_or(0) > 0;
        if !has_cname {
            let _ = conn.execute("ALTER TABLE query_log ADD COLUMN cname_cloaked INTEGER NOT NULL DEFAULT 0", []);
        }

        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    pub fn log_query(
        &self,
        client_ip: &str,
        domain: &str,
        query_type: &str,
        blocked: bool,
        response_time_us: i64,
        upstream: Option<&str>,
        cname_cloaked: bool,
    ) -> Result<()> {
        let now: DateTime<Utc> = Utc::now();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO query_log (timestamp, client_ip, domain, query_type, blocked, response_time_us, upstream, cname_cloaked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![now.to_rfc3339(), client_ip, domain, query_type, blocked as i32, response_time_us, upstream, cname_cloaked as i32],
        )?;
        Ok(())
    }

    pub fn get_queries(&self, limit: u32, offset: u32, filter_blocked: Option<bool>) -> Result<Vec<QueryLogEntry>> {
        let conn = self.conn.lock();
        let sql = match filter_blocked {
            Some(true) => "SELECT id,timestamp,client_ip,domain,query_type,blocked,response_time_us,upstream,cname_cloaked FROM query_log WHERE blocked=1 ORDER BY id DESC LIMIT ?1 OFFSET ?2",
            Some(false) => "SELECT id,timestamp,client_ip,domain,query_type,blocked,response_time_us,upstream,cname_cloaked FROM query_log WHERE blocked=0 ORDER BY id DESC LIMIT ?1 OFFSET ?2",
            None => "SELECT id,timestamp,client_ip,domain,query_type,blocked,response_time_us,upstream,cname_cloaked FROM query_log ORDER BY id DESC LIMIT ?1 OFFSET ?2",
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok(QueryLogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                client_ip: row.get(2)?,
                domain: row.get(3)?,
                query_type: row.get(4)?,
                blocked: row.get::<_, i32>(5)? != 0,
                response_time_us: row.get(6)?,
                upstream: row.get(7)?,
                cname_cloaked: row.get::<_, i32>(8).unwrap_or(0) != 0,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Full-text search through query log with filters
    pub fn search_queries(
        &self,
        query: Option<&str>,
        client_ip: Option<&str>,
        query_type: Option<&str>,
        blocked: Option<bool>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<QueryLogEntry>> {
        let conn = self.conn.lock();
        let mut sql = String::from(
            "SELECT id,timestamp,client_ip,domain,query_type,blocked,response_time_us,upstream,cname_cloaked FROM query_log WHERE 1=1"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(q) = query {
            sql.push_str(" AND domain LIKE ?");
            param_values.push(Box::new(format!("%{q}%")));
        }
        if let Some(ip) = client_ip {
            sql.push_str(" AND client_ip = ?");
            param_values.push(Box::new(ip.to_string()));
        }
        if let Some(qt) = query_type {
            sql.push_str(" AND query_type = ?");
            param_values.push(Box::new(qt.to_string()));
        }
        if let Some(b) = blocked {
            sql.push_str(" AND blocked = ?");
            param_values.push(Box::new(b as i32));
        }

        sql.push_str(" ORDER BY id DESC LIMIT ? OFFSET ?");
        param_values.push(Box::new(limit));
        param_values.push(Box::new(offset));

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            Ok(QueryLogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                client_ip: row.get(2)?,
                domain: row.get(3)?,
                query_type: row.get(4)?,
                blocked: row.get::<_, i32>(5)? != 0,
                response_time_us: row.get(6)?,
                upstream: row.get(7)?,
                cname_cloaked: row.get::<_, i32>(8).unwrap_or(0) != 0,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_stats(&self) -> Result<Stats> {
        let conn = self.conn.lock();
        let total: u64 = conn.query_row("SELECT COUNT(*) FROM query_log", [], |r| r.get(0))?;
        let blocked: u64 = conn.query_row("SELECT COUNT(*) FROM query_log WHERE blocked=1", [], |r| r.get(0))?;

        let mut stats = Stats {
            total_queries: total,
            blocked_queries: blocked,
            allowed_queries: total - blocked,
            blocked_percentage: if total > 0 { (blocked as f64 / total as f64) * 100.0 } else { 0.0 },
            ..Default::default()
        };

        let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM query_log WHERE blocked=1 GROUP BY domain ORDER BY c DESC LIMIT 10")?;
        stats.top_blocked = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,u64>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;

        let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM query_log WHERE blocked=0 GROUP BY domain ORDER BY c DESC LIMIT 10")?;
        stats.top_allowed = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,u64>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;

        let mut stmt = conn.prepare("SELECT client_ip, COUNT(*) as c FROM query_log GROUP BY client_ip ORDER BY c DESC LIMIT 10")?;
        stats.top_clients = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,u64>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;

        Ok(stats)
    }

    /// Get per-client detailed stats
    pub fn get_client_stats(&self, client_ip: &str) -> Result<ClientStats> {
        let conn = self.conn.lock();
        let total: u64 = conn.query_row(
            "SELECT COUNT(*) FROM query_log WHERE client_ip=?1", params![client_ip], |r| r.get(0)
        )?;
        let blocked: u64 = conn.query_row(
            "SELECT COUNT(*) FROM query_log WHERE client_ip=?1 AND blocked=1", params![client_ip], |r| r.get(0)
        )?;

        let mut stmt = conn.prepare(
            "SELECT domain, COUNT(*) as c FROM query_log WHERE client_ip=?1 GROUP BY domain ORDER BY c DESC LIMIT 20"
        )?;
        let top_domains = stmt.query_map(params![client_ip], |r| Ok((r.get::<_,String>(0)?, r.get::<_,u64>(1)?)))?
            .collect::<std::result::Result<Vec<_>,_>>()?;

        let mut stmt = conn.prepare(
            "SELECT domain, COUNT(*) as c FROM query_log WHERE client_ip=?1 AND blocked=1 GROUP BY domain ORDER BY c DESC LIMIT 20"
        )?;
        let top_blocked_domains = stmt.query_map(params![client_ip], |r| Ok((r.get::<_,String>(0)?, r.get::<_,u64>(1)?)))?
            .collect::<std::result::Result<Vec<_>,_>>()?;

        Ok(ClientStats {
            client_ip: client_ip.to_string(),
            total_queries: total,
            blocked_queries: blocked,
            allowed_queries: total - blocked,
            top_domains,
            top_blocked_domains,
        })
    }

    /// Get all unique client IPs with query counts
    pub fn get_all_clients(&self) -> Result<Vec<(String, u64, u64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT client_ip, COUNT(*) as total, SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END) as blocked_count FROM query_log GROUP BY client_ip ORDER BY total DESC"
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,u64>(1)?, r.get::<_,u64>(2)?))
        })?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(rows)
    }
}
