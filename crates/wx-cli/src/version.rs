use std::sync::OnceLock;

pub(crate) fn cli_version_long() -> &'static str {
    static CLI_VERSION: OnceLock<String> = OnceLock::new();
    CLI_VERSION
        .get_or_init(|| {
            let version = env!("CARGO_PKG_VERSION");
            let sha = option_env!("VERGEN_GIT_SHA").unwrap_or("unknown");
            let sha_short = if sha.len() >= 7 { &sha[..7] } else { sha };
            let date = option_env!("VERGEN_BUILD_DATE").unwrap_or("unknown");
            format!("{version} ({sha_short} {date})")
        })
        .as_str()
}

pub(crate) fn cli_version_string() -> String {
    cli_version_long().to_string()
}
