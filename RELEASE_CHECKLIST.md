# Release Checklist

## Repository Setup

- Create a new repository or fork the upstream repository.
- Preserve `LICENSE` and the original copyright notice.
- Confirm repository URLs point to `Sisyphus-seeker/wxcli-windows`.
- Mark the project as an unofficial Windows-compatible distribution when it
  is not published by the upstream maintainer.

## Privacy Review

- Do not add WeChat databases, decrypted caches, logs, media, `keys.toml`, or
  `settings.toml`.
- Run a secret scanner and inspect `git diff --cached` before every push.
- Confirm that examples contain only synthetic account IDs and keys.

## Verification

```text
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p wx-cli
```

- Run `wx-cli doctor` on the supported Windows and WeChat versions.
- Verify that `wx-cli query --help` does not list removed or unsupported
  features.
- Document tested Windows and WeChat versions in the release notes.

## Publishing

- Publish from GitHub Actions instead of uploading a local `target` binary.
- Use a prerelease tag for the first Windows build, such as
  `v0.7.4-windows.1`.
- Publish the generated SHA256 files with the release archives.
- State that unsigned binaries may trigger Microsoft Defender or SmartScreen
  because the tool reads WeChat process memory.
