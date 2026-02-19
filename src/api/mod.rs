use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    middleware::{self, Next},
};
use serde::{Deserialize, Serialize};

use crate::blocklist::BlocklistEngine;
use crate::config::BlocklistSource;
use crate::db::Database;
use crate::dhcp::DhcpServer;
use crate::dns_rewrite::{DnsRewriteEngine, RewriteRule};
use crate::group_policy::{GroupPolicyEngine, GroupInfo};
use crate::schedule::{ScheduleEngine, ScheduleInfo};
use crate::upstream_health::UpstreamHealthMonitor;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub blocklist: Arc<BlocklistEngine>,
    pub rewrites: Arc<DnsRewriteEngine>,
    pub groups: Arc<GroupPolicyEngine>,
    pub schedules: Arc<ScheduleEngine>,
    pub upstream_health: Arc<UpstreamHealthMonitor>,
    pub dhcp: Option<Arc<DhcpServer>>,
    pub api_token: Option<String>,
    pub blocking_enabled: Arc<std::sync::atomic::AtomicBool>,
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        // Stats & queries
        .route("/api/stats", get(get_stats))
        .route("/api/queries", get(get_queries))
        .route("/api/queries/search", get(search_queries))
        .route("/api/clients", get(get_clients))
        .route("/api/clients/{ip}", get(get_client_stats))
        // Blocklist management
        .route("/api/blocklist/sources", get(get_sources))
        .route("/api/blocklist/sources", post(add_source))
        .route("/api/blocklist/sources/remove", post(remove_source))
        .route("/api/blocklist/sources/toggle", post(toggle_source))
        .route("/api/blocklist/refresh", post(refresh_blocklists))
        .route("/api/blocklist/count", get(get_blocklist_count))
        .route("/api/custom/block", post(add_custom_block))
        .route("/api/custom/allow", post(add_custom_allow))
        .route("/api/custom/block/remove", post(remove_custom_block))
        .route("/api/custom/allow/remove", post(remove_custom_allow))
        // Whitelist
        .route("/api/whitelist", get(get_whitelist))
        .route("/api/whitelist", post(add_whitelist))
        .route("/api/whitelist/remove", post(remove_whitelist))
        // Regex
        .route("/api/regex", get(get_regex_filters))
        .route("/api/regex", post(add_regex_filter))
        .route("/api/regex/remove", post(remove_regex_filter))
        // DNS Rewrites
        .route("/api/rewrites", get(get_rewrites))
        .route("/api/rewrites", post(add_rewrite))
        .route("/api/rewrites/remove", post(remove_rewrite))
        // Group Policies
        .route("/api/groups", get(get_groups))
        .route("/api/groups", post(add_group))
        .route("/api/groups/remove", post(remove_group))
        .route("/api/groups/client", post(add_client_to_group))
        .route("/api/groups/client/remove", post(remove_client_from_group))
        // Scheduled Blocking
        .route("/api/schedules", get(get_schedules))
        .route("/api/schedules", post(add_schedule))
        .route("/api/schedules/remove", post(remove_schedule))
        // Upstream Health
        .route("/api/upstream/health", get(get_upstream_health))
        // DHCP
        .route("/api/dhcp/leases", get(get_dhcp_leases))
        .route("/api/dhcp/static", post(add_static_lease))
        .route("/api/dhcp/static/remove", post(remove_static_lease))
        // Global controls
        .route("/api/blocking/status", get(get_blocking_status))
        .route("/api/blocking/enable", post(enable_blocking))
        .route("/api/blocking/disable", post(disable_blocking))
        .with_state(state);

    api
}

/// Check API token if configured. Returns Err(401) if token is required but missing/wrong.
fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if let Some(ref token) = state.api_token {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match provided {
            Some(t) if t == token => Ok(()),
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        Ok(())
    }
}

// ===== Stats & Queries =====

async fn get_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let stats = state.db.get_stats().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(stats).unwrap()))
}

#[derive(Deserialize)]
struct QueryParams {
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
    blocked: Option<bool>,
}

fn default_limit() -> u32 { 100 }

async fn get_queries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<QueryParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let queries = state.db.get_queries(params.limit, params.offset, params.blocked)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(queries).unwrap()))
}

#[derive(Deserialize)]
struct SearchParams {
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
    #[serde(rename = "q")]
    query: Option<String>,
    client: Option<String>,
    #[serde(rename = "type")]
    query_type: Option<String>,
    blocked: Option<bool>,
}

async fn search_queries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SearchParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let queries = state.db.search_queries(
        params.query.as_deref(),
        params.client.as_deref(),
        params.query_type.as_deref(),
        params.blocked,
        params.limit,
        params.offset,
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(queries).unwrap()))
}

async fn get_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let clients = state.db.get_all_clients().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(clients).unwrap()))
}

async fn get_client_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let stats = state.db.get_client_stats(&ip).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(stats).unwrap()))
}

// ===== Blocklist Management =====

async fn get_sources(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<BlocklistSource>>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(state.blocklist.get_sources().await))
}

#[derive(Deserialize)]
struct NewSource {
    name: String,
    url: String,
}

async fn add_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewSource>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocklist.add_source(BlocklistSource {
        name: body.name,
        url: body.url,
        enabled: true,
    }).await;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct SourceName {
    name: String,
}

async fn remove_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SourceName>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.blocklist.remove_source(&body.name).await {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
struct ToggleSource {
    name: String,
    enabled: bool,
}

async fn toggle_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ToggleSource>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.blocklist.toggle_source(&body.name, body.enabled).await {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

async fn refresh_blocklists(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CountResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let count = state.blocklist.refresh().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(CountResponse { count }))
}

#[derive(Serialize)]
struct CountResponse {
    count: usize,
}

async fn get_blocklist_count(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CountResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(CountResponse { count: state.blocklist.domain_count() }))
}

#[derive(Deserialize)]
struct DomainBody {
    domain: String,
}

async fn add_custom_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocklist.add_blocked(&body.domain);
    Ok(StatusCode::OK)
}

async fn add_custom_allow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocklist.add_allowed(&body.domain);
    Ok(StatusCode::OK)
}

async fn remove_custom_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocklist.remove_blocked(&body.domain);
    Ok(StatusCode::OK)
}

async fn remove_custom_allow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocklist.remove_allowed(&body.domain);
    Ok(StatusCode::OK)
}

// ===== Whitelist =====

async fn get_whitelist(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(state.blocklist.get_whitelist()))
}

async fn add_whitelist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocklist.add_whitelist(&body.domain);
    Ok(StatusCode::OK)
}

async fn remove_whitelist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DomainBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocklist.remove_whitelist(&body.domain);
    Ok(StatusCode::OK)
}

// ===== Regex =====

async fn get_regex_filters(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(state.blocklist.get_regex_filters().await))
}

#[derive(Deserialize)]
struct PatternBody {
    pattern: String,
}

async fn add_regex_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PatternBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    check_auth(&state, &headers).map_err(|s| (s, "Unauthorized".into()))?;
    state.blocklist.add_regex_filter(&body.pattern).await
        .map(|_| StatusCode::OK)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid regex: {e}")))
}

async fn remove_regex_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PatternBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.blocklist.remove_regex_filter(&body.pattern).await {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ===== DNS Rewrites =====

async fn get_rewrites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RewriteRule>>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(state.rewrites.get_rules()))
}

async fn add_rewrite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RewriteRule>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.rewrites.add_rule(body);
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct RemoveRewrite {
    domain: String,
    record_type: String,
}

async fn remove_rewrite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RemoveRewrite>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.rewrites.remove_rule(&body.domain, &body.record_type) {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ===== Group Policies =====

async fn get_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GroupInfo>>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(state.groups.get_groups()))
}

async fn add_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GroupInfo>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.groups.add_group(body);
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct GroupName {
    name: String,
}

async fn remove_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GroupName>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.groups.remove_group(&body.name) {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
struct ClientGroup {
    client: String,
    group: String,
}

async fn add_client_to_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ClientGroup>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.groups.add_client_to_group(&body.client, &body.group) {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

async fn remove_client_from_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ClientGroup>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.groups.remove_client_from_group(&body.client, &body.group) {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ===== Scheduled Blocking =====

async fn get_schedules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ScheduleInfo>>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(state.schedules.get_rules()))
}

async fn add_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScheduleInfo>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    state.schedules.add_rule(body);
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct ScheduleName {
    name: String,
}

async fn remove_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScheduleName>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    if state.schedules.remove_rule(&body.name) {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ===== Upstream Health =====

async fn get_upstream_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::upstream_health::UpstreamStatus>>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(state.upstream_health.get_status()))
}

// ===== DHCP =====

async fn get_dhcp_leases(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::dhcp::LeaseInfo>>, StatusCode> {
    check_auth(&state, &headers)?;
    match &state.dhcp {
        Some(dhcp) => Ok(Json(dhcp.get_leases())),
        None => Ok(Json(vec![])),
    }
}

#[derive(Deserialize)]
struct StaticLeaseBody {
    mac: String,
    ip: String,
    hostname: Option<String>,
}

async fn add_static_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<StaticLeaseBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    match &state.dhcp {
        Some(dhcp) => {
            if dhcp.add_static_lease(&body.mac, &body.ip, body.hostname) {
                Ok(StatusCode::CREATED)
            } else {
                Ok(StatusCode::BAD_REQUEST)
            }
        }
        None => Ok(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct MacBody {
    mac: String,
}

async fn remove_static_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MacBody>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&state, &headers)?;
    match &state.dhcp {
        Some(dhcp) => {
            if dhcp.remove_static_lease(&body.mac) {
                Ok(StatusCode::OK)
            } else {
                Ok(StatusCode::NOT_FOUND)
            }
        }
        None => Ok(StatusCode::NOT_FOUND),
    }
}

// ===== Global Controls =====

#[derive(Serialize)]
struct BlockingStatus {
    enabled: bool,
    blocked_domains: usize,
}

async fn get_blocking_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BlockingStatus>, StatusCode> {
    check_auth(&state, &headers)?;
    Ok(Json(BlockingStatus {
        enabled: state.blocking_enabled.load(std::sync::atomic::Ordering::Relaxed),
        blocked_domains: state.blocklist.domain_count(),
    }))
}

async fn enable_blocking(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BlockingStatus>, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocking_enabled.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(Json(BlockingStatus {
        enabled: true,
        blocked_domains: state.blocklist.domain_count(),
    }))
}

async fn disable_blocking(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BlockingStatus>, StatusCode> {
    check_auth(&state, &headers)?;
    state.blocking_enabled.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(Json(BlockingStatus {
        enabled: false,
        blocked_domains: state.blocklist.domain_count(),
    }))
}
