use std::path::{Path, PathBuf};

use crate::PathsError;

pub(crate) struct PlatformBaseDirs {
    pub config_root: PathBuf,
    pub cache_root: PathBuf,
    pub state_root: PathBuf,
    pub logs_root: PathBuf,
}

impl PlatformBaseDirs {
    pub(crate) fn resolve(home: &Path) -> Result<Self, PathsError> {
        let _ = home;
        let config_root = dirs::config_dir()
            .ok_or(PathsError::NoConfig)?
            .join("wx-cli");
        let cache_root = dirs::cache_dir().ok_or(PathsError::NoCache)?.join("wx-cli");
        let local_data = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or(PathsError::NoState)?
            .join("wx-cli");
        let state_root = local_data.join("state");
        let logs_root = local_data.join("logs");
        Ok(Self {
            config_root,
            cache_root,
            state_root,
            logs_root,
        })
    }
}
