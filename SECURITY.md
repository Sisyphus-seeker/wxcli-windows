# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in wx-cli, please report it responsibly:

1. **Do NOT open a public issue.**
2. Use [GitHub Private Vulnerability Reporting](https://github.com/Sisyphus-seeker/wxcli-windows/security/advisories/new) to submit your report.
3. Include steps to reproduce, affected versions, and potential impact.

You should receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

wx-cli handles sensitive data including:

- WeChat database encryption keys
- Decrypted chat messages and media
- Local keystore files

Security issues in any of these areas are treated with high priority.
