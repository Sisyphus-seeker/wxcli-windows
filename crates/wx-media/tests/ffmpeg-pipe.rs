use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static CHILD_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn run_ffmpeg_drains_stdout_while_streaming_stdin() {
    let _guard = CHILD_LOCK.lock().unwrap();

    let output = run_child("ffmpeg", Duration::from_secs(3));
    assert!(
        output.status.success(),
        "child failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("ffmpeg-ok"));
}

#[test]
fn run_ffprobe_drains_stdout_while_streaming_stdin() {
    let _guard = CHILD_LOCK.lock().unwrap();

    let output = run_child("ffprobe", Duration::from_secs(3));
    assert!(
        output.status.success(),
        "child failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("ffprobe-ok"));
}

#[test]
fn ffmpeg_pipe_child_mode() {
    let Ok(mode) = std::env::var("WECHAT_MEDIA_PIPE_CHILD_MODE") else {
        return;
    };

    let temp = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    let tool_path = temp.path().join("fake-ffmpeg.py");
    #[cfg(windows)]
    let tool_path = temp.path().join("fake-ffmpeg.cmd");
    std::fs::write(&tool_path, fake_ffmpeg_script()).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tool_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool_path, perms).unwrap();
    }

    unsafe {
        std::env::set_var("FFMPEG_PATH", &tool_path);
        std::env::set_var("FFPROBE_PATH", &tool_path);
    }
    wx_media::reset_ffmpeg_cache();

    let input = vec![b'i'; 1024 * 1024];
    match mode.as_str() {
        "ffmpeg" => {
            let output = wx_media::run_ffmpeg(&input, &["-i", "pipe:0", "pipe:1"]).unwrap();
            assert_eq!(output.len(), 262_144);
            println!("ffmpeg-ok {}", output.len());
        }
        "ffprobe" => {
            let output = wx_media::run_ffprobe(&input, &["-i", "pipe:0"]).unwrap();
            assert_eq!(output.len(), 262_144);
            println!("ffprobe-ok {}", output.len());
        }
        other => panic!("unexpected child mode: {other}"),
    }
}

fn run_child(mode: &str, timeout: Duration) -> Output {
    let current_exe = std::env::current_exe().unwrap();
    let mut child = Command::new(current_exe)
        .arg("--exact")
        .arg("ffmpeg_pipe_child_mode")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("WECHAT_MEDIA_PIPE_CHILD_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "child timed out after {:?}: stdout={}\nstderr={}",
                timeout,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn fake_ffmpeg_script() -> &'static str {
    r#"#!/usr/bin/env python3
import os
import sys

if "-version" in sys.argv:
    sys.stdout.write("fake ffmpeg 1.0\n")
    sys.exit(0)

chunk = b"x" * 4096
remaining = 262144
while remaining > 0:
    piece = chunk if remaining >= len(chunk) else b"x" * remaining
    os.write(1, piece)
    remaining -= len(piece)

sys.stdin.buffer.read()
"#
}

#[cfg(windows)]
fn fake_ffmpeg_script() -> &'static str {
    r#"@echo off
if "%~1"=="-version" (
  echo fake ffmpeg 1.0
  exit /b 0
)
powershell.exe -NoProfile -NonInteractive -Command "$out=[Console]::OpenStandardOutput(); $chunk=[Text.Encoding]::ASCII.GetBytes(('x' * 4096)); for($i=0; $i -lt 64; $i++){ $out.Write($chunk,0,$chunk.Length) }; $out.Flush(); [Console]::OpenStandardInput().CopyTo([IO.Stream]::Null)"
"#
}
