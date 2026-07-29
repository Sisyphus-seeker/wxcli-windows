use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub enum ServeError {
    Db(String),
    Internal(String),
    InvalidParam(String),
    NotFound(String),
    UnsupportedMedia(String),
    Upstream(String),
}

impl IntoResponse for ServeError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ServeError::Db(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ServeError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ServeError::InvalidParam(msg) => (StatusCode::BAD_REQUEST, msg),
            ServeError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ServeError::UnsupportedMedia(msg) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, msg),
            ServeError::Upstream(msg) => (StatusCode::BAD_GATEWAY, msg),
        };
        let body = axum::Json(json!({ "error": message }));
        (status, body).into_response()
    }
}
