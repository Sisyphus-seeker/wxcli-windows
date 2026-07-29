pub fn cmd_info(db_file: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let metadata = std::fs::metadata(db_file)?;
    let mut f = std::fs::File::open(db_file)?;
    let mut header = [0u8; 16];
    f.read_exact(&mut header)?;

    let is_sqlite = &header[..] == b"SQLite format 3\0";
    let salt_hex = hex::encode(header);
    let page_count = metadata.len() / 4096;

    println!("File:       {}", db_file.display());
    println!(
        "Size:       {} bytes ({} pages)",
        metadata.len(),
        page_count
    );
    if is_sqlite {
        println!("Status:     decrypted (SQLite header detected)");
    } else {
        println!("Status:     encrypted");
        println!("Salt:       {salt_hex}");
    }

    Ok(())
}
