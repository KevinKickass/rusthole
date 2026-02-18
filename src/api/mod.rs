use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::blocklist::BlocklistEngine;
use crate::config::BlocklistSource;
use crate::db::Database;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub blocklist: Arc<BlocklistEngine>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/queries", get(get_queries))
        .route("/api/queries/search", get(search_queries))
        .route("/api/clients", get(get_clients))
        .route("/api/clients/{ip}", get(get_client_stats))
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
        .route("/api/whitelist", get(get_whitelist))
        .route("/api/whitelist", post(add_whitelist))
        .route("/api/whitelist/remove", post(remove_whitelist))
        .route("/api/regex", get(get_regex_filters))
        .route("/api/regex", post(add_regex_filter))
        .route("/api/regex/remove", post(remove_regex_filter))
        .with_state(state)
}

async fn get_stats(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
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
    Query(params): Query<QueryParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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
    Query(params): Query<SearchParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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

async fn get_clients(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let clients = state.db.get_all_clients().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(clients).unwrap()))
}

async fn get_client_stats(
    State(state): State<AppState>,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let stats = state.db.get_client_stats(&ip).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(stats).unwrap()))
}

async fn get_sources(State(state): State<AppState>) -> Json<Vec<BlocklistSource>> {
    Json(state.blocklist.get_sources().await)
}

#[derive(Deserialize)]
struct NewSource {
    name: String,
    url: String,
}

async fn add_source(
    State(state): State<AppState>,
    Json(body): Json<NewSource>,
) -> StatusCode {
    state.blocklist.add_source(BlocklistSource {
        name: body.name,
        url: body.url,
        enabled: true,
    }).await;
    StatusCode::CREATED
}

#[derive(Deserialize)]
struct SourceName {
    name: String,
}

async fn remove_source(
    State(state): State<AppState>,
    Json(body): Json<SourceName>,
) -> StatusCode {
    if state.blocklist.remove_source(&body.name).await {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Deserialize)]
struct ToggleSource {
    name: String,
    enabled: bool,
}

async fn toggle_source(
    State(state): State<AppState>,
    Json(body): Json<ToggleSource>,
) -> StatusCode {
    if state.blocklist.toggle_source(&body.name, body.enabled).await {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn refresh_blocklists(State(state): State<AppState>) -> Result<Json<CountResponse>, StatusCode> {
    let count = state.blocklist.refresh().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(CountResponse { count }))
}

#[derive(Serialize)]
struct CountResponse {
    count: usize,
}

async fn get_blocklist_count(State(state): State<AppState>) -> Json<CountResponse> {
    Json(CountResponse { count: state.blocklist.domain_count() })
}

#[derive(Deserialize)]
struct DomainBody {
    domain: String,
}

async fn add_custom_block(State(state): State<AppState>, Json(body): Json<DomainBody>) -> StatusCode {
    state.blocklist.add_blocked(&body.domain);
    StatusCode::OK
}

async fn add_custom_allow(State(state): State<AppState>, Json(body): Json<DomainBody>) -> StatusCode {
    state.blocklist.add_allowed(&body.domain);
    StatusCode::OK
}

async fn remove_custom_block(State(state): State<AppState>, Json(body): Json<DomainBody>) -> StatusCode {
    state.blocklist.remove_blocked(&body.domain);
    StatusCode::OK
}

async fn remove_custom_allow(State(state): State<AppState>, Json(body): Json<DomainBody>) -> StatusCode {
    state.blocklist.remove_allowed(&body.domain);
    StatusCode::OK
}

// Whitelist endpoints
async fn get_whitelist(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.blocklist.get_whitelist())
}

async fn add_whitelist(State(state): State<AppState>, Json(body): Json<DomainBody>) -> StatusCode {
    state.blocklist.add_whitelist(&body.domain);
    StatusCode::OK
}

async fn remove_whitelist(State(state): State<AppState>, Json(body): Json<DomainBody>) -> StatusCode {
    state.blocklist.remove_whitelist(&body.domain);
    StatusCode::OK
}

// Regex filter endpoints
async fn get_regex_filters(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.blocklist.get_regex_filters().await)
}

#[derive(Deserialize)]
struct PatternBody {
    pattern: String,
}

async fn add_regex_filter(State(state): State<AppState>, Json(body): Json<PatternBody>) -> Result<StatusCode, (StatusCode, String)> {
    state.blocklist.add_regex_filter(&body.pattern).await
        .map(|_| StatusCode::OK)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid regex: {e}")))
}

async fn remove_regex_filter(State(state): State<AppState>, Json(body): Json<PatternBody>) -> StatusCode {
    if state.blocklist.remove_regex_filter(&body.pattern).await {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}
