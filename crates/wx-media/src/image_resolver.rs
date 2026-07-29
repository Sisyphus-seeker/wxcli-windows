use std::path::{Path, PathBuf};

use crate::error::MediaError;
use crate::resource;
use crate::types::MediaLookupResult;

/// Resolve an image file from `local_id` through the full lookup chain:
///
/// `local_id` → `message_resource.db(packed_info)` → MD5 → `attach/<md5(username)>/*/Img/<md5>*.dat`
///
/// # Arguments
/// - `resource_db`: Path to `message_resource.db`
/// - `local_id`: Message local ID
/// - `username`: Chat partner username (for hashing to directory name)
/// - `attach_dir`: Root `attach/` directory
pub fn resolve_image(
    resource_db: &Path,
    local_id: i64,
    username: &str,
    attach_dir: &Path,
) -> Result<MediaLookupResult, MediaError> {
    // Step 1: Get packed_info from DB
    let packed_info = resource::get_packed_info(resource_db, local_id)?;

    // Step 2: Extract MD5
    let file_md5 = resource::extract_md5_from_packed_info(&packed_info).ok_or_else(|| {
        MediaError::PackedInfoParseFailed {
            local_id,
            reason: "no MD5 found in packed_info blob".into(),
        }
    })?;

    // Step 3: Locate .dat files
    let username_hash = format!("{:x}", md5::compute(username.as_bytes()));
    let search_base = attach_dir.join(&username_hash);

    let candidates = find_dat_files(&search_base, &file_md5);

    if candidates.is_empty() {
        return Err(MediaError::NoDatFiles {
            md5: file_md5,
            path: search_base,
        });
    }

    // Step 4: Recommend best file (original > _h > _t)
    let recommended = pick_recommended(&candidates, &file_md5);

    Ok(MediaLookupResult {
        file_md5,
        candidates,
        recommended,
    })
}

/// Resolve image .dat files by MD5 directly (without local_id).
/// Used when caller already has MD5 from MessageContent::Image.
pub fn resolve_image_by_md5(
    username: &str,
    attach_dir: &Path,
    file_md5: &str,
) -> Result<MediaLookupResult, MediaError> {
    let username_hash = format!("{:x}", md5::compute(username.as_bytes()));
    let search_base = attach_dir.join(&username_hash);
    let candidates = find_dat_files(&search_base, file_md5);

    if candidates.is_empty() {
        return Err(MediaError::NoDatFiles {
            md5: file_md5.to_string(),
            path: search_base,
        });
    }

    let recommended = pick_recommended(&candidates, file_md5);

    Ok(MediaLookupResult {
        file_md5: file_md5.to_string(),
        candidates,
        recommended,
    })
}

/// Find all `.dat` files matching `<md5>*.dat` under `<base>/*/Img/`.
fn find_dat_files(base: &Path, file_md5: &str) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let img_dir = entry.path().join("Img");
        if !img_dir.is_dir() {
            continue;
        }
        let inner = match std::fs::read_dir(&img_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for file_entry in inner.flatten() {
            let name = file_entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(file_md5) && name_str.ends_with(".dat") {
                results.push(file_entry.path());
            }
        }
    }

    results.sort();
    results
}

/// Pick the recommended file: prefer `_h.dat` > exact `md5.dat` > `_t.dat`.
fn pick_recommended(candidates: &[PathBuf], file_md5: &str) -> Option<PathBuf> {
    let exact = format!("{}.dat", file_md5);
    let hd = format!("{}_h.dat", file_md5);

    // Prefer _h (high quality/original download)
    if let Some(p) = candidates
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == hd))
    {
        return Some(p.clone());
    }

    // Then exact match
    if let Some(p) = candidates
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == exact))
    {
        return Some(p.clone());
    }

    // Fallback to first available
    candidates.first().cloned()
}
