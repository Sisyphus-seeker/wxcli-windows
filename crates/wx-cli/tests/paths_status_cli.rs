use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_wx-cli")
}

#[test]
fn paths_json_outputs_valid_json_with_expected_fields() {
    let output = Command::new(bin())
        .args(["paths", "--json"])
        .output()
        .expect("run paths --json");
    assert!(output.status.success(), "paths --json failed: {output:?}");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from paths --json");
    let obj = json.as_object().expect("JSON is an object");

    let expected_fields = [
        "platform",
        "config_dir",
        "keys_file",
        "settings_file",
        "cache_root",
        "state_root",
        "logs_dir",
        "server_state_dir",
        "server_stdout_log",
        "server_stderr_log",
        "temp_root",
    ];
    for field in &expected_fields {
        assert!(
            obj.contains_key(*field),
            "missing field '{field}' in paths --json output"
        );
    }
}

#[test]
fn paths_text_contains_expected_labels() {
    let output = Command::new(bin())
        .args(["paths"])
        .output()
        .expect("run paths");
    assert!(output.status.success(), "paths failed: {output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Platform header should be present
    assert!(
        stdout.contains("Platform:"),
        "paths text output should contain 'Platform:' header"
    );

    let expected_labels = [
        "config_dir",
        "keys_file",
        "settings_file",
        "cache_root",
        "state_root",
        "logs_dir",
        "server_state_dir",
        "server_stdout_log",
        "server_stderr_log",
        "temp_root",
    ];
    for label in &expected_labels {
        assert!(
            stdout.contains(label),
            "missing label '{label}' in paths text output"
        );
    }
}

#[test]
fn status_outputs_paths_line_even_without_accounts() {
    let output = Command::new(bin())
        .args(["status"])
        .output()
        .expect("run status");
    // status may fail if WeChat version check fails, but stdout should still have Paths:
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Paths:"),
        "status output should contain 'Paths:' line, got: {stdout}"
    );
}
