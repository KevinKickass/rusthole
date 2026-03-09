use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::DnsRewriteEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRule {
    pub domain: String,
    pub record_type: String,
    pub value: String,
}

pub struct DnsRewriteEngine {
    rules: Arc<RwLock<Vec<RewriteRule>>>,
}

impl DnsRewriteEngine {
    pub fn new(entries: &[DnsRewriteEntry]) -> Self {
        let rules: Vec<RewriteRule> = entries
            .iter()
            .map(|e| RewriteRule {
                domain: e.domain.to_lowercase().trim_end_matches('.').to_string(),
                record_type: e.record_type.to_uppercase(),
                value: e.value.clone(),
            })
            .collect();
        Self {
            rules: Arc::new(RwLock::new(rules)),
        }
    }

    /// Try to resolve a query from local rewrites. Returns Some(response bytes) if matched.
    pub fn resolve(&self, request: &Message, domain: &str, qtype: RecordType) -> Option<Vec<u8>> {
        let domain_lower = domain.to_lowercase();
        let domain_clean = domain_lower.trim_end_matches('.');
        let rules = self.rules.read();

        let matching: Vec<&RewriteRule> = rules
            .iter()
            .filter(|r| self.domain_matches(domain_clean, &r.domain))
            .filter(|r| self.type_matches(&r.record_type, qtype))
            .collect();

        if matching.is_empty() {
            return None;
        }

        let mut response = Message::new();
        let mut header = Header::response_from_request(request.header());
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_authoritative(true);
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);
        response.add_queries(request.queries().iter().cloned());

        let name = request.queries().first()?.name().clone();

        for rule in &matching {
            if let Some(rdata) = self.make_rdata(rule, &name) {
                let record = Record::from_rdata(name.clone(), 300, rdata);
                response.add_answer(record);
            }
        }

        response.to_bytes().ok()
    }

    fn domain_matches(&self, query: &str, pattern: &str) -> bool {
        if query == pattern {
            return true;
        }
        // Wildcard: *.example.com matches sub.example.com
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return query.ends_with(&format!(".{suffix}")) || query == suffix;
        }
        false
    }

    fn type_matches(&self, rule_type: &str, qtype: RecordType) -> bool {
        matches!(
            (rule_type, qtype),
            ("A", RecordType::A)
                | ("AAAA", RecordType::AAAA)
                | ("CNAME", RecordType::CNAME)
                | ("CNAME", RecordType::A)
                | ("CNAME", RecordType::AAAA)
        )
    }

    fn make_rdata(&self, rule: &RewriteRule, _name: &Name) -> Option<RData> {
        match rule.record_type.as_str() {
            "A" => {
                let ip: Ipv4Addr = rule.value.parse().ok()?;
                Some(RData::A(ip.into()))
            }
            "AAAA" => {
                let ip: Ipv6Addr = rule.value.parse().ok()?;
                Some(RData::AAAA(ip.into()))
            }
            "CNAME" => {
                let target: Name = rule.value.parse().ok()?;
                Some(RData::CNAME(hickory_proto::rr::rdata::CNAME(target)))
            }
            _ => None,
        }
    }

    pub fn get_rules(&self) -> Vec<RewriteRule> {
        self.rules.read().clone()
    }

    pub fn add_rule(&self, rule: RewriteRule) {
        self.rules.write().push(RewriteRule {
            domain: rule.domain.to_lowercase().trim_end_matches('.').to_string(),
            record_type: rule.record_type.to_uppercase(),
            value: rule.value,
        });
    }

    pub fn remove_rule(&self, domain: &str, record_type: &str) -> bool {
        let mut rules = self.rules.write();
        let domain = domain.to_lowercase();
        let rt = record_type.to_uppercase();
        let before = rules.len();
        rules.retain(|r| !(r.domain == domain && r.record_type == rt));
        rules.len() < before
    }
}
