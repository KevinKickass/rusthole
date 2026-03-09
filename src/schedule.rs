use std::sync::Arc;

use chrono::{Datelike, Local, Timelike};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::ScheduledRule;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleInfo {
    pub name: String,
    pub domains: Vec<String>,
    pub blocklist_names: Vec<String>,
    pub days: Vec<String>,
    pub start_hour: u8,
    pub start_minute: u8,
    pub end_hour: u8,
    pub end_minute: u8,
}

pub struct ScheduleEngine {
    rules: Arc<RwLock<Vec<ScheduleInfo>>>,
}

impl ScheduleEngine {
    pub fn new(rules: &[ScheduledRule]) -> Self {
        let infos = rules
            .iter()
            .map(|r| ScheduleInfo {
                name: r.name.clone(),
                domains: r.domains.iter().map(|d| d.to_lowercase()).collect(),
                blocklist_names: r.blocklist_names.clone(),
                days: r.schedule.days.clone(),
                start_hour: r.schedule.start_hour,
                start_minute: r.schedule.start_minute,
                end_hour: r.schedule.end_hour,
                end_minute: r.schedule.end_minute,
            })
            .collect();
        Self {
            rules: Arc::new(RwLock::new(infos)),
        }
    }

    /// Check if a domain is blocked by any active schedule right now.
    pub fn is_blocked_now(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let now = Local::now();
        let rules = self.rules.read();

        for rule in rules.iter() {
            if !self.is_active_now(rule, &now) {
                continue;
            }
            // Check domain match
            for d in &rule.domains {
                if domain == *d || domain.ends_with(&format!(".{d}")) {
                    return true;
                }
            }
        }
        false
    }

    fn is_active_now(&self, rule: &ScheduleInfo, now: &chrono::DateTime<Local>) -> bool {
        // Check day of week
        if !rule.days.is_empty() {
            let today = match now.weekday() {
                chrono::Weekday::Mon => "mon",
                chrono::Weekday::Tue => "tue",
                chrono::Weekday::Wed => "wed",
                chrono::Weekday::Thu => "thu",
                chrono::Weekday::Fri => "fri",
                chrono::Weekday::Sat => "sat",
                chrono::Weekday::Sun => "sun",
            };
            let matches = rule.days.iter().any(|d| {
                let d = d.to_lowercase();
                d == today
                    || d == "weekday" && matches!(today, "mon" | "tue" | "wed" | "thu" | "fri")
                    || d == "weekend" && matches!(today, "sat" | "sun")
            });
            if !matches {
                return false;
            }
        }

        // Check time range
        let current_minutes = now.hour() as u16 * 60 + now.minute() as u16;
        let start_minutes = rule.start_hour as u16 * 60 + rule.start_minute as u16;
        let end_minutes = rule.end_hour as u16 * 60 + rule.end_minute as u16;

        if start_minutes <= end_minutes {
            current_minutes >= start_minutes && current_minutes < end_minutes
        } else {
            // Wraps midnight
            current_minutes >= start_minutes || current_minutes < end_minutes
        }
    }

    pub fn get_rules(&self) -> Vec<ScheduleInfo> {
        self.rules.read().clone()
    }

    pub fn add_rule(&self, rule: ScheduleInfo) {
        self.rules.write().push(rule);
    }

    pub fn remove_rule(&self, name: &str) -> bool {
        let mut rules = self.rules.write();
        let before = rules.len();
        rules.retain(|r| r.name != name);
        rules.len() < before
    }
}
