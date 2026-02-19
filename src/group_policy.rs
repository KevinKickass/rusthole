use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::GroupPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub clients: Vec<String>,
    pub blocklists: Vec<String>,
    pub extra_block: Vec<String>,
    pub extra_allow: Vec<String>,
}

pub struct GroupPolicyEngine {
    /// client identifier (IP or MAC) -> group name
    client_map: Arc<RwLock<HashMap<String, String>>>,
    /// group name -> policy details
    groups: Arc<RwLock<HashMap<String, GroupInfo>>>,
}

impl GroupPolicyEngine {
    pub fn new(policies: &[GroupPolicy]) -> Self {
        let mut client_map = HashMap::new();
        let mut groups = HashMap::new();

        for p in policies {
            let info = GroupInfo {
                name: p.name.clone(),
                clients: p.clients.clone(),
                blocklists: p.blocklists.clone(),
                extra_block: p.extra_block.clone(),
                extra_allow: p.extra_allow.clone(),
            };
            for client in &p.clients {
                client_map.insert(client.to_lowercase(), p.name.clone());
            }
            groups.insert(p.name.clone(), info);
        }

        Self {
            client_map: Arc::new(RwLock::new(client_map)),
            groups: Arc::new(RwLock::new(groups)),
        }
    }

    /// Check if a domain should be blocked for a specific client, considering group policies.
    /// Returns Some(true) if group says block, Some(false) if group says allow, None if no group policy applies.
    pub fn check_domain(&self, client_ip: &str, domain: &str) -> Option<bool> {
        let client_map = self.client_map.read();
        let group_name = client_map.get(&client_ip.to_lowercase())?;
        let groups = self.groups.read();
        let group = groups.get(group_name)?;

        let domain_lower = domain.to_lowercase();

        // Extra allow takes priority within group
        if group.extra_allow.iter().any(|d| d.to_lowercase() == domain_lower) {
            return Some(false);
        }

        // Extra block domains
        if group.extra_block.iter().any(|d| d.to_lowercase() == domain_lower) {
            return Some(true);
        }

        // If group has specific blocklists, we defer to the blocklist engine
        // (the caller should check which blocklists apply)
        None
    }

    /// Get the blocklist names that should apply to a specific client.
    /// Returns None if no group policy, Some(list) if client has a group.
    pub fn get_client_blocklists(&self, client_ip: &str) -> Option<Vec<String>> {
        let client_map = self.client_map.read();
        let group_name = client_map.get(&client_ip.to_lowercase())?;
        let groups = self.groups.read();
        let group = groups.get(group_name)?;
        if group.blocklists.is_empty() {
            None
        } else {
            Some(group.blocklists.clone())
        }
    }

    pub fn get_groups(&self) -> Vec<GroupInfo> {
        self.groups.read().values().cloned().collect()
    }

    pub fn add_group(&self, info: GroupInfo) {
        let mut client_map = self.client_map.write();
        for client in &info.clients {
            client_map.insert(client.to_lowercase(), info.name.clone());
        }
        self.groups.write().insert(info.name.clone(), info);
    }

    pub fn remove_group(&self, name: &str) -> bool {
        let mut groups = self.groups.write();
        if let Some(group) = groups.remove(name) {
            let mut client_map = self.client_map.write();
            for client in &group.clients {
                client_map.remove(&client.to_lowercase());
            }
            true
        } else {
            false
        }
    }

    pub fn add_client_to_group(&self, client: &str, group_name: &str) -> bool {
        let mut groups = self.groups.write();
        if let Some(group) = groups.get_mut(group_name) {
            group.clients.push(client.to_string());
            self.client_map.write().insert(client.to_lowercase(), group_name.to_string());
            true
        } else {
            false
        }
    }

    pub fn remove_client_from_group(&self, client: &str, group_name: &str) -> bool {
        let mut groups = self.groups.write();
        if let Some(group) = groups.get_mut(group_name) {
            let lower = client.to_lowercase();
            group.clients.retain(|c| c.to_lowercase() != lower);
            self.client_map.write().remove(&lower);
            true
        } else {
            false
        }
    }
}
