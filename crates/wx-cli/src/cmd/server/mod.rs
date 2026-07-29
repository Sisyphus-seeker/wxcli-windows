pub mod manager;
pub mod runtime;
pub mod types;

use runtime::RuntimeReporter;
pub use types::{ServerAction, ServerWorkerArgs};

use crate::cmd::serve;

pub async fn cmd_server(action: ServerAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ServerAction::Run(args) => manager::cmd_server_run(args).await,
        ServerAction::Status(args) => manager::cmd_server_status(args),
        ServerAction::Stop(args) => manager::cmd_server_stop(args).await,
        ServerAction::Restart(args) => manager::cmd_server_restart(args).await,
        ServerAction::Worker(args) => cmd_server_worker(args).await,
    }
}

async fn cmd_server_worker(args: ServerWorkerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let ap = match args.runtime_root.clone() {
        Some(root) => wx_paths::AppPaths::with_runtime_root(root)?,
        None => wx_paths::AppPaths::new()?,
    };
    ap.ensure_server_dirs()?;

    let config = types::ServerLaunchConfig::from(args.clone());
    let reporter = RuntimeReporter::new(ap, config.clone());
    serve::cmd_serve(
        config.key,
        config.data_dir,
        config.account,
        config.poll,
        config.fsnotify,
        config.poll_ms,
        config.host,
        config.port,
        config.token,
        args.worker_id,
        Some(reporter),
    )
    .await
}
