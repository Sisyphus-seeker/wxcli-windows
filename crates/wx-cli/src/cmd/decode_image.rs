use std::path::PathBuf;

use crate::MediaAction;

pub fn cmd_decode_image(
    input: PathBuf,
    output: Option<PathBuf>,
    account: Option<String>,
    data_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let action = MediaAction::DecryptDat {
        input,
        output,
        v2_key: None,
        account,
        data_dir,
        xor_key: None,
    };
    super::media::cmd_media(action)
}
