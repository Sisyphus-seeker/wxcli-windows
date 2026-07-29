use super::thin_client::{
    ServerMode, ThinClient, ThinClientCliArgs, ThinClientDecision, ThinClientErrorKind,
    ThinClientOptions,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn resolve_prefers_cli_over_env_and_defaults_to_loopback() {
    let args = ThinClientCliArgs {
        server_url: Some("http://127.0.0.1:9200".into()),
        server_token: Some("cli-token".into()),
        server_only: true,
        no_server: false,
    };
    let options = ThinClientOptions::resolve(
        args,
        Some("http://127.0.0.1:9300".into()),
        Some("env-token".into()),
    );

    assert_eq!(options.base_url, "http://127.0.0.1:9200");
    assert_eq!(options.token.as_deref(), Some("cli-token"));
    assert_eq!(options.mode, ServerMode::ServerOnly);
}

#[test]
fn resolve_uses_env_when_cli_missing() {
    let options = ThinClientOptions::resolve(
        ThinClientCliArgs::default(),
        Some("http://127.0.0.1:9400".into()),
        Some("env-token".into()),
    );

    assert_eq!(options.base_url, "http://127.0.0.1:9400");
    assert_eq!(options.token.as_deref(), Some("env-token"));
    assert_eq!(options.mode, ServerMode::Auto);
}

#[test]
fn resolve_respects_no_server() {
    let options = ThinClientOptions::resolve(
        ThinClientCliArgs {
            server_url: None,
            server_token: None,
            server_only: false,
            no_server: true,
        },
        None,
        None,
    );

    assert_eq!(options.mode, ServerMode::Disabled);
    assert_eq!(options.base_url, "http://127.0.0.1:9100");
}

#[test]
fn fallback_policy_distinguishes_retryable_and_terminal_errors() {
    assert_eq!(
        ThinClientDecision::from_error(ServerMode::Auto, ThinClientErrorKind::Unavailable),
        ThinClientDecision::FallbackToLocal
    );
    assert_eq!(
        ThinClientDecision::from_error(ServerMode::Auto, ThinClientErrorKind::Unauthorized),
        ThinClientDecision::FallbackToLocal
    );
    assert_eq!(
        ThinClientDecision::from_error(ServerMode::Auto, ThinClientErrorKind::BadRequest),
        ThinClientDecision::Fail
    );
    assert_eq!(
        ThinClientDecision::from_error(ServerMode::ServerOnly, ThinClientErrorKind::Unavailable),
        ThinClientDecision::Fail
    );
}

#[test]
fn probe_health_requires_ready_true() {
    let (base_url, handle) = spawn_mock_server(|request| {
        assert!(request.starts_with("GET /api/v1/health"));
        http_response("200 OK", "{\"ready\":false}")
    });

    let client = ThinClient::new(ThinClientOptions {
        base_url,
        token: None,
        mode: ServerMode::Auto,
    });
    let err = client.probe_health().expect_err("health probe should fail");
    assert_eq!(err.kind, ThinClientErrorKind::Unavailable);
    handle.join().unwrap();
}

#[test]
fn probe_health_does_not_append_empty_query_marker() {
    let (base_url, handle) = spawn_mock_server(|request| {
        assert!(request.starts_with("GET /api/v1/health HTTP/1.1\r\n"));
        http_response("200 OK", "{\"ready\":true}")
    });

    let client = ThinClient::new(ThinClientOptions {
        base_url,
        token: None,
        mode: ServerMode::Auto,
    });
    client.probe_health().expect("health probe should succeed");
    handle.join().unwrap();
}

#[test]
fn get_json_sends_bearer_token() {
    let (base_url, handle) = spawn_mock_server(|request| {
        assert!(request.starts_with("GET /api/v1/contacts?limit=10"));
        assert!(request.contains("Authorization: Bearer secret-token\r\n"));
        http_response("200 OK", "{\"ok\":true}")
    });

    let client = ThinClient::new(ThinClientOptions {
        base_url,
        token: Some("secret-token".into()),
        mode: ServerMode::Auto,
    });
    let query = vec![("limit".to_string(), "10".to_string())];
    let value: serde_json::Value = client
        .get_json("/api/v1/contacts", &query)
        .expect("request should succeed");
    assert_eq!(value["ok"], true);
    handle.join().unwrap();
}

#[test]
fn get_json_classifies_unauthorized() {
    let (base_url, handle) = spawn_mock_server(|request| {
        assert!(request.starts_with("GET /api/v1/sessions"));
        http_response("401 Unauthorized", "{\"error\":\"unauthorized\"}")
    });

    let client = ThinClient::new(ThinClientOptions {
        base_url,
        token: None,
        mode: ServerMode::Auto,
    });
    let err = client
        .get_json::<serde_json::Value>("/api/v1/sessions", &Vec::new())
        .expect_err("request should fail");
    assert_eq!(err.kind, ThinClientErrorKind::Unauthorized);
    assert!(err.should_fallback(ServerMode::Auto));
    handle.join().unwrap();
}

fn spawn_mock_server(
    responder: impl FnOnce(String) -> String + Send + 'static,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().expect("mock server addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0_u8; 8192];
        let n = stream.read(&mut buf).expect("read request");
        let request = String::from_utf8_lossy(&buf[..n]).into_owned();
        let response = responder(request);
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });
    (format!("http://{}", addr), handle)
}

fn http_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
