use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use url::Url;

pub const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:9100";
const CONNECT_TIMEOUT_MS: u64 = 250;
const READ_TIMEOUT_MS: u64 = 1_500;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThinClientCliArgs {
    pub server_url: Option<String>,
    pub server_token: Option<String>,
    pub server_only: bool,
    pub no_server: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerMode {
    Auto,
    ServerOnly,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThinClientOptions {
    pub base_url: String,
    pub token: Option<String>,
    pub mode: ServerMode,
}

impl ThinClientOptions {
    pub fn resolve(
        cli: ThinClientCliArgs,
        env_url: Option<String>,
        env_token: Option<String>,
    ) -> Self {
        let base_url = cli
            .server_url
            .or(env_url)
            .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());
        let token = cli.server_token.or(env_token);
        let mode = if cli.no_server {
            ServerMode::Disabled
        } else if cli.server_only {
            ServerMode::ServerOnly
        } else {
            ServerMode::Auto
        };
        Self {
            base_url,
            token,
            mode,
        }
    }

    pub fn resolve_from_process_env(cli: ThinClientCliArgs) -> Self {
        Self::resolve(
            cli,
            std::env::var("WECHAT_CLI_SERVER_URL").ok(),
            std::env::var("WECHAT_CLI_SERVER_TOKEN").ok(),
        )
    }

    pub fn is_enabled(&self) -> bool {
        self.mode != ServerMode::Disabled
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThinClientErrorKind {
    Unavailable,
    Unauthorized,
    BadRequest,
    Server,
    Decode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThinClientDecision {
    FallbackToLocal,
    Fail,
}

impl ThinClientDecision {
    pub fn from_error(mode: ServerMode, kind: ThinClientErrorKind) -> Self {
        if mode == ServerMode::ServerOnly {
            return Self::Fail;
        }
        match kind {
            ThinClientErrorKind::Unavailable | ThinClientErrorKind::Unauthorized => {
                Self::FallbackToLocal
            }
            ThinClientErrorKind::BadRequest
            | ThinClientErrorKind::Server
            | ThinClientErrorKind::Decode => Self::Fail,
        }
    }
}

#[derive(Debug)]
pub struct ThinClientError {
    pub kind: ThinClientErrorKind,
    message: String,
}

impl ThinClientError {
    fn new(kind: ThinClientErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn should_fallback(&self, mode: ServerMode) -> bool {
        ThinClientDecision::from_error(mode, self.kind) == ThinClientDecision::FallbackToLocal
    }

    pub fn fallback_detail(&self) -> &str {
        match self.kind {
            ThinClientErrorKind::Unavailable => simplify_unavailable_message(&self.message),
            ThinClientErrorKind::Unauthorized => {
                if self.message.trim().is_empty() {
                    "unauthorized"
                } else {
                    &self.message
                }
            }
            ThinClientErrorKind::BadRequest
            | ThinClientErrorKind::Server
            | ThinClientErrorKind::Decode => &self.message,
        }
    }
}

impl fmt::Display for ThinClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ThinClientError {}

#[derive(serde::Deserialize)]
struct HealthPayload {
    ready: bool,
}

pub struct ThinClient {
    options: ThinClientOptions,
    agent: ureq::Agent,
}

impl ThinClient {
    pub fn new(options: ThinClientOptions) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_millis(CONNECT_TIMEOUT_MS))
            .timeout_read(Duration::from_millis(READ_TIMEOUT_MS))
            .build();
        Self { options, agent }
    }

    pub fn probe_health(&self) -> Result<(), ThinClientError> {
        let query: Vec<(String, String)> = Vec::new();
        let health: HealthPayload = self.get_json("/api/v1/health", &query)?;
        if !health.ready {
            return Err(ThinClientError::new(
                ThinClientErrorKind::Unavailable,
                "server health check reported ready=false",
            ));
        }
        Ok(())
    }

    pub fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> Result<T, ThinClientError> {
        let url = build_url(&self.options.base_url, path, query)?;
        let mut request = self.agent.get(url.as_str());
        if let Some(token) = &self.options.token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }

        let response = request.call().map_err(classify_ureq_error)?;
        response
            .into_json::<T>()
            .map_err(|err| ThinClientError::new(ThinClientErrorKind::Decode, err.to_string()))
    }
}

fn build_url(
    base_url: &str,
    path: &str,
    query: &[(String, String)],
) -> Result<Url, ThinClientError> {
    let base = Url::parse(base_url)
        .map_err(|err| ThinClientError::new(ThinClientErrorKind::BadRequest, err.to_string()))?;
    let mut url = base
        .join(path.trim_start_matches('/'))
        .map_err(|err| ThinClientError::new(ThinClientErrorKind::BadRequest, err.to_string()))?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

fn classify_ureq_error(err: ureq::Error) -> ThinClientError {
    match err {
        ureq::Error::Status(code, response) => {
            let body = response
                .into_string()
                .unwrap_or_else(|_| String::from("request failed"));
            match code {
                401 => ThinClientError::new(ThinClientErrorKind::Unauthorized, body),
                400..=499 => ThinClientError::new(ThinClientErrorKind::BadRequest, body),
                _ => ThinClientError::new(ThinClientErrorKind::Server, body),
            }
        }
        ureq::Error::Transport(transport) => {
            ThinClientError::new(ThinClientErrorKind::Unavailable, transport.to_string())
        }
    }
}

fn simplify_unavailable_message(message: &str) -> &str {
    let detail = if message.starts_with("http://") || message.starts_with("https://") {
        message
            .split_once(": ")
            .map(|(_, rest)| rest)
            .unwrap_or(message)
    } else {
        message
    };

    detail
        .strip_prefix("Connection Failed: ")
        .unwrap_or(detail)
        .strip_prefix("Connect error: ")
        .unwrap_or(detail.strip_prefix("Connection Failed: ").unwrap_or(detail))
}
