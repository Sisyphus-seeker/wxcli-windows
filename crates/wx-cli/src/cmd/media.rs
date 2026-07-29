use std::path::PathBuf;

use crate::util::walkdir_dat_files;
use crate::MediaAction;

pub fn cmd_media(action: MediaAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        MediaAction::DecryptDat {
            input,
            output,
            v2_key,
            account,
            data_dir,
            xor_key,
        } => {
            let v2_aes_key = if let Some(ref k) = v2_key {
                let bytes = k.as_bytes();
                if bytes.len() != 16 {
                    return Err(format!("V2 key must be 16 bytes, got {}", bytes.len()).into());
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Some(arr)
            } else if let Some(ref acct) = account {
                let store = wx_keychain::KeyStore::load_default()?;
                let entry = store
                    .get(acct)
                    .ok_or_else(|| format!("no key entry for account '{acct}' in KeyStore"))?;
                let hex = entry
                    .image_aes_key
                    .as_ref()
                    .ok_or_else(|| format!("no V2 image key stored for account '{acct}' — use `key set-image` or `--data-dir` instead"))?;
                let raw = hex::decode(hex)
                    .map_err(|e| format!("invalid image_aes_key hex in KeyStore: {e}"))?;
                if raw.len() != 16 {
                    return Err(format!(
                        "stored image_aes_key is {} bytes, expected 16",
                        raw.len()
                    )
                    .into());
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&raw);
                eprintln!("Using V2 key from KeyStore for account '{acct}'");
                Some(arr)
            } else if let Some(ref dir) = data_dir {
                let key = wx_media::derive_v2_key_from_dir(dir)
                    .map_err(|e| format!("V2 key derivation from --data-dir failed: {e}"))?;
                let key_preview = String::from_utf8_lossy(&key[..8]);
                eprintln!("Derived V2 key from UIN+WXID: {key_preview}...");
                Some(key)
            } else {
                None
            };

            let explicit_xor = xor_key
                .map(|s| u8::from_str_radix(&s, 16))
                .transpose()
                .map_err(|e| format!("invalid xor_key hex: {e}"))?;

            if input.is_dir() {
                let out_dir = output.unwrap_or_else(|| input.join("decrypted"));
                std::fs::create_dir_all(&out_dir)?;

                let xor = explicit_xor.or_else(|| {
                    let detected = wx_media::detect_xor_key(&input);
                    if let Some(k) = detected {
                        eprintln!("Auto-detected XOR key: 0x{k:02x}");
                    }
                    detected
                });

                let opts = wx_media::DatDecryptOptions {
                    v2_aes_key,
                    xor_key: xor,
                };

                let mut ok_count = 0usize;
                let mut err_count = 0usize;
                let mut skip_count = 0usize;

                for entry in walkdir_dat_files(&input) {
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();

                    if name.ends_with("_t.dat") {
                        skip_count += 1;
                        continue;
                    }

                    let data = match std::fs::read(&path) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("  Skip {}: {e}", path.display());
                            err_count += 1;
                            continue;
                        }
                    };

                    match wx_media::decrypt_dat(&data, &opts) {
                        Ok(result) => {
                            let (final_data, final_ext) =
                                maybe_transcode_wxgf(result.data, &result.ext, &name);
                            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                            let out_path = out_dir.join(format!("{}.{}", stem, final_ext));
                            std::fs::write(&out_path, &final_data)?;
                            ok_count += 1;
                        }
                        Err(e) => {
                            eprintln!("  Failed {}: {e}", name);
                            err_count += 1;
                        }
                    }
                }

                if skip_count > 0 {
                    eprintln!("Batch decrypt: {ok_count} succeeded, {err_count} failed, {skip_count} skipped");
                } else {
                    eprintln!("Batch decrypt: {ok_count} succeeded, {err_count} failed");
                }
            } else {
                let data = std::fs::read(&input)?;

                let xor = explicit_xor.or_else(|| {
                    input.parent().and_then(|dir| {
                        let detected = wx_media::detect_xor_key(dir);
                        if let Some(k) = detected {
                            eprintln!("Auto-detected XOR key: 0x{k:02x}");
                        }
                        detected
                    })
                });

                let opts = wx_media::DatDecryptOptions {
                    v2_aes_key,
                    xor_key: xor,
                };

                let result = wx_media::decrypt_dat(&data, &opts)?;
                let display_name = input.display().to_string();
                let (final_data, final_ext) =
                    maybe_transcode_wxgf(result.data, &result.ext, &display_name);

                let out_path = if let Some(user_path) = output {
                    // Auto-correct suffix if user-specified extension doesn't match actual format
                    let user_ext = user_path
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !user_ext.is_empty() && user_ext != final_ext {
                        let corrected = user_path.with_extension(&final_ext);
                        eprintln!(
                            "warning: requested .{} but actual format is .{}, writing to {}",
                            user_ext,
                            final_ext,
                            corrected.display(),
                        );
                        corrected
                    } else {
                        user_path
                    }
                } else {
                    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
                    input.with_file_name(format!("{}.{}", stem, final_ext))
                };

                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out_path, &final_data)?;

                eprintln!(
                    "Decrypted: {} -> {} ({:?}, {} bytes, {})",
                    input.display(),
                    out_path.display(),
                    result.format,
                    final_data.len(),
                    final_ext,
                );
            }
        }
        MediaAction::ResolvePath {
            db,
            media_type,
            key,
        } => {
            let entries = wx_media::query_hardlink(&db, &media_type, &key)?;
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        MediaAction::ExtractVoice {
            media_dir,
            svr_id,
            output,
            raw,
        } => {
            let blob = wx_media::extract_voice(&media_dir, &svr_id)?;

            if raw {
                // Raw SILK output
                let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.silk", svr_id)));
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out_path, &blob.data)?;
                eprintln!(
                    "Extracted voice (raw SILK): svr_id={}, {} bytes -> {}",
                    blob.svr_id,
                    blob.data.len(),
                    out_path.display(),
                );
            } else {
                // Transcode to MP3
                match wx_media::transcode_silk_to_mp3(&blob.data) {
                    Ok(result) => {
                        if !result.transcoded {
                            return Err(voice_extract_requires_ffmpeg_message(&svr_id).into());
                        }

                        let out_path = if let Some(user_path) = output {
                            // Auto-correct suffix if user output does not match the actual format.
                            let user_ext = user_path
                                .extension()
                                .map(|e| e.to_string_lossy().to_string())
                                .unwrap_or_default();
                            if !user_ext.is_empty() && user_ext != result.ext {
                                let corrected = user_path.with_extension(result.ext);
                                eprintln!(
                                    "warning: requested .{} but actual format is .{}, writing to {}",
                                    user_ext, result.ext, corrected.display(),
                                );
                                corrected
                            } else {
                                user_path
                            }
                        } else {
                            PathBuf::from(format!("{}.{}", svr_id, result.ext))
                        };
                        if let Some(parent) = out_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(&out_path, &result.data)?;
                        eprintln!(
                            "Extracted voice: svr_id={}, {} bytes -> {} ({})",
                            blob.svr_id,
                            result.data.len(),
                            out_path.display(),
                            result.ext,
                        );
                    }
                    Err(wx_media::MediaError::AudioFeatureDisabled) => {
                        return Err(voice_extract_audio_feature_message(&svr_id).into());
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        MediaAction::DecryptVideo {
            input,
            seed,
            output,
        } => {
            let seed_val = parse_seed(&seed)?;
            let ciphertext = std::fs::read(&input)?;
            let result = wx_media::decrypt_video(&ciphertext, seed_val);

            let out_path = output.unwrap_or_else(|| {
                let stem = input.file_stem().unwrap_or_default().to_string_lossy();
                input.with_file_name(format!("{}.mp4", stem))
            });

            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out_path, &result.data)?;

            if !result.is_valid_mp4 {
                eprintln!("warning: 'ftyp' signature not found, output may not be a valid MP4");
            }
            eprintln!(
                "Decrypted video: {} -> {} ({} bytes)",
                input.display(),
                out_path.display(),
                result.data.len(),
            );
        }
    }
    Ok(())
}

/// Try to transcode WXGF data to a standard image format.
/// Returns the (possibly transcoded) data and extension.
fn maybe_transcode_wxgf(data: Vec<u8>, ext: &str, display_name: &str) -> (Vec<u8>, String) {
    if ext != "wxgf" {
        return (data, ext.to_string());
    }

    match wx_media::transcode_wxgf(&data) {
        Ok(result) => {
            if !result.transcoded {
                eprintln!(
                    "warning: ffmpeg missing, writing raw HEVC for {} ({})",
                    display_name,
                    wx_media::MediaError::ffmpeg_install_hint()
                );
            }
            (result.data, result.ext.to_string())
        }
        Err(e) => {
            eprintln!("warning: WXGF transcode failed for {}: {}", display_name, e);
            (data, "wxgf".to_string())
        }
    }
}

fn voice_extract_requires_ffmpeg_message(svr_id: &str) -> String {
    format!(
        "voice extraction for svr_id={svr_id} requires ffmpeg to produce MP3; {}. To export raw SILK instead, rerun with --raw",
        wx_media::MediaError::ffmpeg_install_hint()
    )
}

fn voice_extract_audio_feature_message(svr_id: &str) -> String {
    format!(
        "voice extraction for svr_id={svr_id} requires audio transcoding support; rebuild wx-cli with the 'audio' feature, or rerun with --raw"
    )
}

/// Parse a seed string as either decimal or hex (with 0x prefix).
fn parse_seed(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(s.parse::<u64>()?)
    }
}
