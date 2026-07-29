# Contributing

Contributions are welcome! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/Sisyphus-seeker/wxcli-windows.git
cd wxcli-windows

# Build
cargo build

# Run tests
cargo test

# Format & lint
cargo fmt --check
cargo clippy -- -D warnings
```

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Make your changes with clear, focused commits.
3. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
4. Open a pull request with a description of what changed and why.

## Bug Reports

Open an [issue](https://github.com/Sisyphus-seeker/wxcli-windows/issues) with:

- wx-cli version (`wx-cli --version`)
- Windows or macOS version
- WeChat version
- Steps to reproduce
- Expected vs actual behavior

## Feature Requests

Open an issue describing the use case and proposed solution. Discussion before implementation is encouraged for larger changes.

## Code Style

- Follow standard Rust conventions (`cargo fmt`).
- Keep changes minimal and focused.
- Add tests for new functionality when feasible.
