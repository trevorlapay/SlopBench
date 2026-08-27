//! The SlopShop search service.

mod index;
mod query;
mod ranking;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use axum::extract::{Query as AxumQuery, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::index::{Document, Index};

const MAX_BODY_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_LIMIT: usize = 20;

type SharedIndex = Arc<RwLock<Index>>;

/// Service token every non-health route must present, read once at start-up.
static SERVICE_TOKEN: OnceLock<String> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct SearchParams {
    q: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct SearchResult {
    product_id: String,
    score_millis: u32,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Debug, Deserialize)]
struct IngestRequest {
    id: u32,
    product_id: String,
    title: String,
    body: String,
}

async fn search(
    State(state): State<SharedIndex>,
    AxumQuery(params): AxumQuery<SearchParams>,
) -> Result<Json<SearchResponse>, (StatusCode, Json<ErrorResponse>)> {
    let parsed = query::parse(&params.q).map_err(|err| {
        let code = match err {
            query::QueryError::TooLong { .. } => "query_too_long",
            query::QueryError::Empty => "query_empty",
        };
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: code }))
    })?;

    let guard = state.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "index_unavailable",
            }),
        )
    })?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT);
    let results = guard
        .search(&parsed, limit)
        .into_iter()
        .filter_map(|hit| {
            guard.product_id(hit.document_id).map(|product_id| SearchResult {
                product_id: product_id.to_owned(),
                score_millis: hit.score_millis,
            })
        })
        .collect();

    Ok(Json(SearchResponse { results }))
}

async fn ingest(
    State(state): State<SharedIndex>,
    Json(body): Json<IngestRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let document = Document {
        id: body.id,
        product_id: body.product_id,
        title: body.title,
        body: body.body,
    };

    let mut guard = state.write().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "index_unavailable",
            }),
        )
    })?;

    match guard.ingest(&document) {
        Ok(()) => Ok(StatusCode::CREATED),
        Err(index::IngestError::DuplicateId) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "duplicate_document_id",
            }),
        )),
        Err(index::IngestError::IndexFull) => Err((
            StatusCode::INSUFFICIENT_STORAGE,
            Json(ErrorResponse {
                error: "index_full",
            }),
        )),
    }
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Compares two tokens without an early exit on the first differing byte.
fn tokens_match(presented: &[u8], expected: &[u8]) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in presented.iter().zip(expected.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Rejects any request that does not present the mesh service token.
async fn require_service_token(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let expected = SERVICE_TOKEN.get().map(String::as_str).unwrap_or_default();
    if expected.is_empty() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();

    if !tokens_match(presented.as_bytes(), expected.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

fn router(state: SharedIndex) -> Router {
    let protected: Router<SharedIndex> = Router::new()
        .route("/v1/search", get(search))
        .route("/v1/documents", post(ingest))
        .route_layer(axum::middleware::from_fn(require_service_token));

    Router::new()
        .merge(protected)
        .route("/healthz", get(healthz))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::new(REQUEST_TIMEOUT))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().json().init();

    // The mesh sidecar terminates TLS in front of this listener.
    let addr: SocketAddr = std::env::var("SEARCH_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8083".to_owned())
        .parse()?;

    let token = std::env::var("SEARCH_SERVICE_TOKEN")
        .map_err(|_| "SEARCH_SERVICE_TOKEN is not configured")?;
    if token.len() < 32 {
        return Err("SEARCH_SERVICE_TOKEN must be at least 32 characters".into());
    }
    let _ = SERVICE_TOKEN.set(token);

    let state: SharedIndex = Arc::new(RwLock::new(Index::new()));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!(%addr, "search listening");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
