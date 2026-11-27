use std::{collections::HashSet, io::Read, path::PathBuf, time::Duration};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BYTES: u64 = 32 * 1024 * 1024;

#[derive(clap::Args)]
pub struct StickerArgs {
    /// Existing JSON sticker list (compatible with fav_stickers.json)
    #[arg(long, conflicts_with = "db")]
    manifest: Option<PathBuf>,
    /// Decrypted emoticon.db; otherwise resolve the account and refresh its cache
    #[arg(long)]
    db: Option<PathBuf>,
    #[arg(long)]
    account: Option<String>,
    #[arg(short, long)]
    data_dir: Option<PathBuf>,
    /// Destination directory; repeat runs skip valid existing images
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Deserialize)]
struct Sticker {
    md5: String,
    #[serde(default)]
    cdn_url: Option<String>,
    #[serde(default)]
    extern_url: Option<String>,
    #[serde(default)]
    encrypt_url: Option<String>,
    #[serde(default)]
    aes_key: Option<String>,
}

#[derive(Serialize)]
struct Entry {
    md5: String,
    status: &'static str,
    file: Option<String>,
    error: Option<String>,
}

fn load(args: &StickerArgs) -> Result<Vec<Sticker>> {
    if let Some(path) = &args.manifest {
        return Ok(serde_json::from_reader(std::fs::File::open(path)?)?);
    }
    let path = if let Some(path) = &args.db {
        path.clone()
    } else {
        let account = wx_context::AccountContext::resolve(&wx_context::ResolveParams {
            account: args.account.as_deref(),
            data_dir: args.data_dir.as_deref(),
            key_hex: None,
        })?;
        let cache =
            wx_context::PersistentCache::new(&account, wx_decrypt::platform_default_params())?;
        let stats = cache.ensure_decrypted_scoped(
            &wx_context::DecryptScope::Paths(vec![PathBuf::from("emoticon/emoticon.db")]),
            |_| {},
        )?;
        if stats.errors != 0 {
            return Err("Database refresh failed; decrypt the emoticon database and pass --db, or use --manifest".into());
        }
        cache.decrypted_root().join("emoticon/emoticon.db")
    };
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = db.prepare(
        "SELECT e.md5, e.cdn_url, e.extern_url, e.encrypt_url, e.aes_key
         FROM kNonStoreEmoticonTable e
         WHERE e.md5 IN (SELECT md5 FROM kFavEmoticonOrderTable)
         ORDER BY e.rowid",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Sticker {
            md5: row.get(0)?,
            cdn_url: row.get(1)?,
            extern_url: row.get(2)?,
            encrypt_url: row.get(3)?,
            aes_key: row.get(4)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn extension(data: &[u8]) -> Option<&'static str> {
    let kind = wx_media::detect_image_type(data);
    (kind != wx_media::ImageType::Unknown).then(|| kind.ext())
}

fn download(agent: &ureq::Agent, item: &Sticker) -> Result<Vec<u8>> {
    let mut reason = "No usable download URL".to_string();
    for (url, encrypted) in [
        (&item.cdn_url, false),
        (&item.extern_url, false),
        (&item.encrypt_url, true),
    ] {
        let Some(url) = url.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        let Ok(parsed) = url::Url::parse(url) else {
            reason = "Invalid download URL".into();
            continue;
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            reason = "Unsupported URL scheme".into();
            continue;
        }
        for attempt in 0..3 {
            let result = (|| -> Result<Vec<u8>> {
                // Keep transport details out of the report: CDN URLs can contain tokens.
                let response = agent
                    .get(url)
                    .call()
                    .map_err(|_| "Download request failed")?;
                let mut data = Vec::new();
                response
                    .into_body()
                    .into_reader()
                    .take(MAX_BYTES + 1)
                    .read_to_end(&mut data)?;
                if data.len() as u64 > MAX_BYTES {
                    return Err("Image exceeds 32 MiB limit".into());
                }
                if extension(&data).is_none() || encrypted {
                    let key = hex::decode(item.aes_key.as_deref().unwrap_or(""))
                        .map_err(|_| "Invalid sticker AES key")?;
                    let key: [u8; 16] = key
                        .try_into()
                        .map_err(|_| "Sticker AES key must be 16 bytes")?;
                    data = wx_media::aes_ecb_decrypt(&data, &key)?;
                }
                if extension(&data).is_none() {
                    return Err("Response is not a supported image".into());
                }
                Ok(data)
            })();
            match result {
                Ok(data) => return Ok(data),
                Err(error) => reason = error.to_string(),
            }
            if attempt < 2 {
                std::thread::sleep(Duration::from_secs(1 << attempt));
            }
        }
    }
    Err(reason.into())
}

pub fn run(args: StickerArgs) -> Result<()> {
    let items = load(&args)?;
    std::fs::create_dir_all(&args.output)?;
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent();
    let mut seen = HashSet::new();
    let mut report = Vec::new();
    let mut failed = 0;
    for item in items {
        if item.md5.len() != 32 || !item.md5.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Sticker MD5 must contain exactly 32 hexadecimal characters".into());
        }
        let name = item.md5.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            continue;
        }
        let existing = ["gif", "png", "jpg", "webp", "bmp", "tif", "wxgf"]
            .iter()
            .map(|ext| args.output.join(format!("{name}.{ext}")))
            .find(|path| {
                std::fs::read(path)
                    .ok()
                    .is_some_and(|data| extension(&data).is_some())
            });
        let result = if let Some(path) = existing {
            Ok(("skipped", path))
        } else {
            download(&agent, &item).and_then(|data| {
                let path = args
                    .output
                    .join(format!("{name}.{}", extension(&data).unwrap()));
                // tempfile avoids exposing partial images and supports concurrent exporters.
                let mut temporary = tempfile::NamedTempFile::new_in(&args.output)?;
                std::io::Write::write_all(&mut temporary, &data)?;
                temporary.persist(&path)?;
                Ok(("exported", path))
            })
        };
        let entry = match result {
            Ok((status, file)) => Entry {
                md5: name,
                status,
                file: Some(file.display().to_string()),
                error: None,
            },
            Err(error) => {
                failed += 1;
                Entry {
                    md5: name,
                    status: "failed",
                    file: None,
                    error: Some(error.to_string()),
                }
            }
        };
        eprintln!("{}: {}", entry.md5, entry.status);
        report.push(entry);
    }
    let mut file = tempfile::NamedTempFile::new_in(&args.output)?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    file.persist(args.output.join("stickers-report.json"))?;
    eprintln!("{} stickers, {} failed", report.len(), failed);
    if failed != 0 {
        return Err("Some stickers failed; see stickers-report.json and rerun to retry".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_falls_back_from_invalid_url() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nGIF89a\x01\0\x01\0").unwrap();
        });
        let item = Sticker {
            md5: "a".repeat(32),
            cdn_url: Some("invalid".into()),
            extern_url: Some(format!("http://{address}/image")),
            encrypt_url: None,
            aes_key: None,
        };
        assert_eq!(
            download(
                &ureq::Agent::config_builder()
                    .proxy(None)
                    .build()
                    .new_agent(),
                &item
            )
            .unwrap(),
            b"GIF89a\x01\0\x01\0"
        );
        server.join().unwrap();
    }

    #[test]
    fn database_exports_only_favorites_and_existing_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("emoticon.db");
        let db = Connection::open(&db_path).unwrap();
        db.execute_batch(
            "CREATE TABLE kNonStoreEmoticonTable
            (md5 TEXT, cdn_url TEXT, extern_url TEXT, encrypt_url TEXT, aes_key TEXT);
            CREATE TABLE kFavEmoticonOrderTable (md5 TEXT);
            INSERT INTO kNonStoreEmoticonTable VALUES
            ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', NULL, NULL, NULL, NULL),
            ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', NULL, NULL, NULL, NULL);
            INSERT INTO kFavEmoticonOrderTable VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
        )
        .unwrap();
        let args = StickerArgs {
            manifest: None,
            db: Some(db_path),
            account: None,
            data_dir: None,
            output: dir.path().join("out"),
        };
        assert_eq!(load(&args).unwrap().len(), 1);
        std::fs::create_dir(&args.output).unwrap();
        std::fs::write(
            args.output.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.gif"),
            b"GIF89a\x01\0\x01\0",
        )
        .unwrap();
        let report = args.output.join("stickers-report.json");
        run(args).unwrap();
        let entries: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(entries[0]["status"], "skipped");
    }

    #[test]
    fn missing_urls_report_failure_and_return_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("input.json");
        std::fs::write(&manifest, r#"[{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#).unwrap();
        let output = dir.path().join("out");
        assert!(run(StickerArgs {
            manifest: Some(manifest),
            db: None,
            account: None,
            data_dir: None,
            output: output.clone()
        })
        .is_err());
        let report = std::fs::read_to_string(output.join("stickers-report.json")).unwrap();
        assert!(report.contains("failed"));
        assert!(!report.contains("aes_key"));
    }
}
