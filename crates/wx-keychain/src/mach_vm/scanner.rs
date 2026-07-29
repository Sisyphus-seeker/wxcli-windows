#[cfg(windows)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

use crate::error::KeychainError;
use crate::mach_vm::pattern::{scan_bare_hex_keys, scan_chunk, FoundKey, MAX_PATTERN_BYTES};
use crate::mach_vm::reader::MemoryReader;

/// The maximum supported pattern is `x'<192 hex>'` = 195 bytes.
/// Keep `MAX_PATTERN_BYTES - 1` bytes so chunk-boundary matches are not missed.
const OVERLAP: usize = MAX_PATTERN_BYTES - 1;

/// Default chunk size for reading memory regions.
const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

#[cfg(windows)]
const WEIXIN_4_1_KEY_MASK: [u8; 32] = [
    0x55, 0xE8, 0x9C, 0x9F, 0xCC, 0x23, 0xE3, 0x38, 0x2F, 0x46, 0x54, 0xD4, 0xF9, 0xD7, 0x23, 0x7E,
    0x4A, 0xCC, 0x82, 0xE5, 0xCA, 0xD1, 0x41, 0x2C, 0x7F, 0xC6, 0x59, 0xCB, 0x2A, 0x33, 0xAD, 0xAF,
];

/// A validated scan result: enc_key + salt matched to a specific DB file.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub enc_key: [u8; 32],
    pub salt: [u8; 16],
    pub db_path: std::path::PathBuf,
}

/// Scan process memory for enc_key candidates, match them against known DB salts,
/// and HMAC-validate each match.
pub struct MemoryScanner<R: MemoryReader> {
    reader: R,
}

impl<R: MemoryReader> MemoryScanner<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Scan all RW regions for supported SQL hex literal patterns, then match
    /// candidates against known DB salts via HMAC validation.
    pub fn scan(
        &self,
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
    ) -> Result<Vec<ScanResult>, KeychainError> {
        let regions = self.reader.rw_regions()?;
        let (candidates, raw_key_candidates) = self.scan_regions(&regions)?;

        if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
            eprintln!(
                "scan diagnostics: {} regions, {} pattern candidates, {} raw-key strings, {} database salts",
                regions.len(),
                candidates.len(),
                raw_key_candidates.len(),
                db_salts.len()
            );
        }

        #[cfg(not(windows))]
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for found in &candidates {
            self.validate_candidate(found, db_salts, params, &mut results, &mut seen);
        }

        #[cfg(windows)]
        if results.is_empty() {
            self.scan_binary_keys_near_salts(
                &regions,
                &raw_key_candidates,
                db_salts,
                params,
                &mut results,
                &mut seen,
            )?;
        }

        self.cross_validate_known_keys(db_salts, params, &mut results, &mut seen);

        if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
            eprintln!("scan diagnostics: {} validated key pairs", results.len());
        }

        Ok(results)
    }

    #[cfg(windows)]
    fn scan_binary_keys_near_salts(
        &self,
        regions: &[crate::mach_vm::MemRegion],
        raw_key_candidates: &[[u8; 32]],
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
    ) -> Result<(), KeychainError> {
        const RADIUS: usize = 1024;
        const MAX_OCCURRENCES_PER_SALT: usize = 128;

        let mut targets = Vec::new();
        let mut unique_salts = HashSet::new();
        for (salt, path) in db_salts {
            if !unique_salts.insert(*salt) {
                continue;
            }
            if let Ok(first_page) = wx_decrypt::read_prefix_shared(path, params.page_size) {
                targets.push(BinaryTarget {
                    salt: *salt,
                    path,
                    first_page,
                });
            }
        }

        let mut by_prefix: HashMap<[u8; 4], Vec<usize>> = HashMap::new();
        for (index, target) in targets.iter().enumerate() {
            by_prefix
                .entry(target.salt[..4].try_into().expect("four-byte salt prefix"))
                .or_default()
                .push(index);
        }

        let mut occurrence_counts = vec![0usize; targets.len()];
        let mut tested = HashSet::new();
        let mut occurrence_addresses = HashSet::new();
        let mut salt_locations = Vec::new();

        for region in regions {
            let region_len = (region.end - region.start) as usize;
            let mut offset = 0usize;
            let mut carry = Vec::new();

            while offset < region_len {
                let read_len = CHUNK_SIZE.min(region_len - offset);
                let chunk = match self
                    .reader
                    .read_bytes(region.start + offset as u64, read_len)
                {
                    Ok(data) => data,
                    Err(_) => {
                        offset += read_len;
                        carry.clear();
                        continue;
                    }
                };
                let carry_len = carry.len();
                let scan_buf = if carry.is_empty() {
                    chunk.clone()
                } else {
                    carry.extend_from_slice(&chunk);
                    carry.clone()
                };
                let base_address = region.start + offset.saturating_sub(carry_len) as u64;

                if scan_buf.len() >= 16 {
                    for position in 0..=scan_buf.len() - 16 {
                        let prefix: [u8; 4] = scan_buf[position..position + 4]
                            .try_into()
                            .expect("four-byte candidate prefix");
                        let Some(indices) = by_prefix.get(&prefix) else {
                            continue;
                        };

                        for &target_index in indices {
                            let target = &targets[target_index];
                            if occurrence_counts[target_index] >= MAX_OCCURRENCES_PER_SALT
                                || scan_buf[position..position + 16] != target.salt
                            {
                                continue;
                            }
                            let address = base_address + position as u64;
                            if !occurrence_addresses.insert((target_index, address)) {
                                continue;
                            }
                            occurrence_counts[target_index] += 1;
                            salt_locations.push((target_index, address));

                            let start = position.saturating_sub(RADIUS);
                            let end = (position + 16 + RADIUS).min(scan_buf.len());
                            for candidate_start in candidate_starts(start, end, position) {
                                if candidate_start + 32 > scan_buf.len() {
                                    continue;
                                }
                                let mut key = [0u8; 32];
                                key.copy_from_slice(
                                    &scan_buf[candidate_start..candidate_start + 32],
                                );
                                validate_binary_candidate(
                                    key,
                                    target,
                                    params,
                                    results,
                                    seen,
                                    &mut tested,
                                );
                            }
                        }
                    }
                }

                let keep = (RADIUS + 32).min(chunk.len());
                carry = chunk[chunk.len() - keep..].to_vec();
                offset += read_len;
            }
        }

        let mut pointer_references = Vec::new();
        if results.is_empty() && !salt_locations.is_empty() {
            let mut addresses_by_prefix: HashMap<[u8; 4], Vec<(usize, u64)>> = HashMap::new();
            for &(target_index, address) in &salt_locations {
                addresses_by_prefix
                    .entry(
                        address.to_le_bytes()[..4]
                            .try_into()
                            .expect("pointer prefix"),
                    )
                    .or_default()
                    .push((target_index, address));
            }
            let mut seen_references = HashSet::new();

            for region in regions {
                let region_len = (region.end - region.start) as usize;
                let mut offset = 0usize;
                let mut carry = Vec::new();
                while offset < region_len {
                    let read_len = CHUNK_SIZE.min(region_len - offset);
                    let chunk = match self
                        .reader
                        .read_bytes(region.start + offset as u64, read_len)
                    {
                        Ok(data) => data,
                        Err(_) => {
                            offset += read_len;
                            carry.clear();
                            continue;
                        }
                    };
                    let carry_len = carry.len();
                    let scan_buf = if carry.is_empty() {
                        chunk.clone()
                    } else {
                        carry.extend_from_slice(&chunk);
                        carry.clone()
                    };
                    let base_address = region.start + offset.saturating_sub(carry_len) as u64;

                    if scan_buf.len() >= 8 {
                        let first_aligned = (8 - (base_address as usize & 7)) & 7;
                        for position in (first_aligned..=scan_buf.len() - 8).step_by(8) {
                            let prefix: [u8; 4] = scan_buf[position..position + 4]
                                .try_into()
                                .expect("pointer candidate prefix");
                            let Some(locations) = addresses_by_prefix.get(&prefix) else {
                                continue;
                            };
                            let value = u64::from_le_bytes(
                                scan_buf[position..position + 8]
                                    .try_into()
                                    .expect("pointer candidate"),
                            );
                            for &(target_index, salt_address) in locations {
                                if value == salt_address {
                                    let reference = base_address + position as u64;
                                    if seen_references.insert((target_index, reference)) {
                                        pointer_references.push((
                                            target_index,
                                            reference,
                                            salt_address,
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    let keep = 7.min(chunk.len());
                    carry = chunk[chunk.len() - keep..].to_vec();
                    offset += read_len;
                }
            }
        }

        let mut masked_context_candidates = 0usize;
        if results.is_empty() {
            for &(target_index, reference, salt_address) in &pointer_references {
                masked_context_candidates += self.scan_masked_sqlcipher_context(
                    reference,
                    salt_address,
                    &targets[target_index],
                    params,
                    results,
                    seen,
                    &mut tested,
                );
                if !results.is_empty() {
                    break;
                }
            }
        }

        let primary_target_index = occurrence_counts
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .max_by_key(|(_, count)| **count)
            .map(|(index, _)| index);
        let mut codec_context_candidates = 0usize;
        if results.is_empty() && primary_target_index.is_some() {
            codec_context_candidates = self.scan_weixin_4_1_codec_contexts(
                regions,
                &targets,
                params,
                results,
                seen,
                &mut tested,
            )?;
        }
        let mut broad_masked_candidates = 0usize;
        if results.is_empty() && primary_target_index.is_some() {
            broad_masked_candidates = self.scan_masked_cipher_contexts(
                regions,
                &targets,
                params,
                results,
                seen,
                &mut tested,
            )?;
        }

        for (target_index, reference, _) in &pointer_references {
            let target = &targets[*target_index];
            let context_start = reference.saturating_sub(128);
            let Ok(context) = self.reader.read_bytes(context_start, 256) else {
                continue;
            };
            for offset in (0..context.len().saturating_sub(7)).step_by(8) {
                let pointer = u64::from_le_bytes(
                    context[offset..offset + 8]
                        .try_into()
                        .expect("context pointer"),
                );
                let Ok(cipher_context) = self.reader.read_bytes(pointer, 160) else {
                    continue;
                };

                for key_offset in (0..cipher_context.len().saturating_sub(31)).step_by(8) {
                    let mut inline_key = [0u8; 32];
                    inline_key.copy_from_slice(&cipher_context[key_offset..key_offset + 32]);
                    validate_binary_candidate(
                        inline_key,
                        target,
                        params,
                        results,
                        seen,
                        &mut tested,
                    );

                    let key_pointer = u64::from_le_bytes(
                        cipher_context[key_offset..key_offset + 8]
                            .try_into()
                            .expect("key pointer"),
                    );
                    if let Ok(key_bytes) = self.reader.read_bytes(key_pointer, 32) {
                        if key_bytes.len() == 32 {
                            let mut pointed_key = [0u8; 32];
                            pointed_key.copy_from_slice(&key_bytes);
                            validate_binary_candidate(
                                pointed_key,
                                target,
                                params,
                                results,
                                seen,
                                &mut tested,
                            );
                        }
                    }
                }
            }
        }

        let exhaustive = cfg!(test) || std::env::var_os("WX_CLI_EXHAUSTIVE_SCAN").is_some();
        let scan_aes_schedules =
            exhaustive || std::env::var_os("WX_CLI_SCAN_AES_SCHEDULES").is_some();

        let mut raw_keys_derived = 0usize;
        if results.is_empty() && exhaustive {
            if let Some(target_index) = primary_target_index {
                raw_keys_derived = validate_windows_raw_keys(
                    raw_key_candidates,
                    &targets[target_index],
                    params,
                    results,
                    seen,
                )?;
            }
        }

        let mut schedule_candidates = 0usize;
        if results.is_empty() && scan_aes_schedules && primary_target_index.is_some() {
            schedule_candidates = self.scan_openssl_aes_schedules(
                regions,
                &targets,
                params,
                results,
                seen,
                &mut tested,
            )?;
        }

        let mut aligned_candidates = 0usize;
        if results.is_empty() && exhaustive {
            if let Some(target_index) = primary_target_index {
                let target = &targets[target_index];
                aligned_candidates +=
                    self.scan_aligned_binary_keys(regions, target, params, 0, results, seen)?;
                if results.is_empty() {
                    aligned_candidates +=
                        self.scan_aligned_binary_keys(regions, target, params, 8, results, seen)?;
                }
            }
        }

        if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
            eprintln!(
                "scan diagnostics: {} binary salt occurrences, {} pointer references, {} codec and {}/{} masked candidates, {} nearby candidates, {}/{} raw-key strings derived, {} AES schedules, {} aligned candidates",
                occurrence_counts.iter().sum::<usize>(),
                pointer_references.len(),
                codec_context_candidates,
                masked_context_candidates,
                broad_masked_candidates,
                tested.len(),
                raw_keys_derived,
                raw_key_candidates.len(),
                schedule_candidates,
                aligned_candidates
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn scan_weixin_4_1_codec_contexts(
        &self,
        regions: &[crate::mach_vm::MemRegion],
        targets: &[BinaryTarget<'_>],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
        tested: &mut HashSet<([u8; 32], [u8; 16])>,
    ) -> Result<usize, KeychainError> {
        const CODEC_SIZE: usize = 0x78;
        const CARRY_SIZE: usize = CODEC_SIZE - 1;
        const CIPHER_CONTEXT_OFFSETS: [usize; 2] = [0x68, 0x70];

        let mut context_count = 0usize;
        let mut matched_context_count = 0usize;
        let mut cipher_context_count = 0usize;
        let mut null_cipher_pointers = 0usize;
        let mut unreadable_cipher_contexts = 0usize;
        let mut mismatched_cipher_key_lengths = 0usize;
        let mut cipher_key_lengths = HashMap::new();
        let mut null_key_pointers = 0usize;
        let mut unreadable_key_buffers = 0usize;
        let mut readable_key_buffers = 0usize;
        let mut readable_derived_key_buffers = 0usize;
        let mut protected_pattern_candidates = 0usize;
        let mut pattern_salt_matches = 0usize;
        let mut codec_routed_patterns = 0usize;
        let mut codec_profiles = HashSet::new();
        let mut derived_raw_keys = HashSet::new();
        for region in regions {
            let region_len = (region.end - region.start) as usize;
            let mut offset = 0usize;
            let mut carry = Vec::new();

            while offset < region_len {
                let read_len = CHUNK_SIZE.min(region_len - offset);
                let chunk = match self
                    .reader
                    .read_bytes(region.start + offset as u64, read_len)
                {
                    Ok(data) => data,
                    Err(_) => {
                        offset += read_len;
                        carry.clear();
                        continue;
                    }
                };
                let carry_len = carry.len();
                let scan_buf = if carry.is_empty() {
                    chunk.clone()
                } else {
                    carry.extend_from_slice(&chunk);
                    carry.clone()
                };
                let base_address = region.start + offset.saturating_sub(carry_len) as u64;
                let first_aligned = (8 - (base_address as usize & 7)) & 7;

                if first_aligned + CODEC_SIZE <= scan_buf.len() {
                    for position in (first_aligned..=scan_buf.len() - CODEC_SIZE).step_by(8) {
                        let kdf_iter = read_u32(&scan_buf, position + 4);
                        let fast_kdf_iter = read_u32(&scan_buf, position + 8);
                        let salt_size = read_u32(&scan_buf, position + 0x0C);
                        let page_size = read_u32(&scan_buf, position + 0x1C);
                        if kdf_iter != Some(256_000)
                            || fast_kdf_iter != Some(2)
                            || salt_size != Some(16)
                            || page_size != Some(4096)
                        {
                            continue;
                        }
                        context_count += 1;
                        let matched_target = read_u64(&scan_buf, position + 0x48)
                            .and_then(|salt_address| self.reader.read_bytes(salt_address, 16).ok())
                            .and_then(|salt_bytes| {
                                targets
                                    .iter()
                                    .find(|target| salt_bytes.as_slice() == target.salt.as_slice())
                            });
                        if matched_target.is_some() {
                            matched_context_count += 1;
                            let profile = (0..=0x2C)
                                .step_by(4)
                                .filter_map(|offset| read_u32(&scan_buf, position + offset))
                                .collect::<Vec<_>>();
                            codec_profiles.insert(profile);
                        }

                        for cipher_offset in CIPHER_CONTEXT_OFFSETS {
                            let Some(cipher_address) =
                                read_u64(&scan_buf, position + cipher_offset)
                            else {
                                continue;
                            };
                            if cipher_address == 0 {
                                null_cipher_pointers += 1;
                                continue;
                            }
                            let Ok(cipher) = self.reader.read_bytes(cipher_address, 0x28) else {
                                unreadable_cipher_contexts += 1;
                                continue;
                            };

                            if read_u32(&scan_buf, position + 0x10) == Some(32) {
                                for key_pointer_offset in [0x08, 0x10] {
                                    let Some(derived_key_address) =
                                        read_u64(&cipher, key_pointer_offset)
                                    else {
                                        continue;
                                    };
                                    let Ok(derived_key_bytes) =
                                        self.reader.read_bytes(derived_key_address, 32)
                                    else {
                                        continue;
                                    };
                                    let Ok(derived_key) = <[u8; 32]>::try_from(derived_key_bytes)
                                    else {
                                        continue;
                                    };
                                    readable_derived_key_buffers += 1;
                                    if let Some(target) = matched_target {
                                        validate_binary_candidate(
                                            derived_key,
                                            target,
                                            params,
                                            results,
                                            seen,
                                            tested,
                                        );
                                    } else {
                                        validate_binary_candidate_for_targets(
                                            derived_key,
                                            targets,
                                            params,
                                            results,
                                            seen,
                                            tested,
                                        );
                                    }
                                }
                            }

                            let Some(key_len) = read_u32(&cipher, 4).map(|value| value as usize)
                            else {
                                mismatched_cipher_key_lengths += 1;
                                continue;
                            };
                            *cipher_key_lengths.entry(key_len).or_insert(0usize) += 1;
                            if !(32..=128).contains(&key_len) {
                                mismatched_cipher_key_lengths += 1;
                                continue;
                            }
                            cipher_context_count += 1;
                            let Some(key_address) = read_u64(&cipher, 0x18) else {
                                continue;
                            };
                            if key_address == 0 {
                                null_key_pointers += 1;
                                continue;
                            }
                            let Ok(bytes) = self.reader.read_bytes(key_address, key_len) else {
                                unreadable_key_buffers += 1;
                                continue;
                            };
                            if bytes.len() != key_len {
                                continue;
                            }
                            readable_key_buffers += 1;

                            for value in [bytes.clone(), unmask_weixin_key_buffer(&bytes)] {
                                for found in scan_chunk(&value) {
                                    protected_pattern_candidates += 1;
                                    if found.salt.is_some_and(|salt| {
                                        targets.iter().any(|target| target.salt == salt)
                                    }) {
                                        pattern_salt_matches += 1;
                                    }
                                    let result_count = results.len();
                                    validate_found_candidate_for_targets(
                                        &found, targets, params, results, seen, tested,
                                    );
                                    if results.len() == result_count {
                                        if let Some(target) = matched_target {
                                            codec_routed_patterns += 1;
                                            validate_found_candidate_for_target(
                                                &found, target, params, results, seen, tested,
                                            );
                                        }
                                    }
                                }
                            }

                            for raw_key in windows_cipher_key_candidates(&bytes) {
                                validate_binary_candidate_for_targets(
                                    raw_key, targets, params, results, seen, tested,
                                );
                                if let Some(target) = matched_target {
                                    if !derived_raw_keys.insert((raw_key, target.salt)) {
                                        continue;
                                    }
                                    let enc_key = wx_decrypt::kdf::derive_enc_key(
                                        &raw_key,
                                        &target.salt,
                                        params,
                                    );
                                    validate_binary_candidate(
                                        enc_key, target, params, results, seen, tested,
                                    );
                                }
                            }
                        }
                    }
                }

                let keep = CARRY_SIZE.min(chunk.len());
                carry = chunk[chunk.len() - keep..].to_vec();
                offset += read_len;
            }
        }
        if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
            let mut key_lengths = cipher_key_lengths.into_iter().collect::<Vec<_>>();
            key_lengths.sort_unstable();
            let mut profiles = codec_profiles.into_iter().collect::<Vec<_>>();
            profiles.sort_unstable();
            eprintln!(
                "scan diagnostics: {matched_context_count}/{context_count} codec salts matched, {readable_derived_key_buffers} derived key buffers and {cipher_context_count} passphrase contexts ({null_cipher_pointers} null pointers, {unreadable_cipher_contexts} unreadable, {mismatched_cipher_key_lengths} unsupported key lengths, lengths {key_lengths:?}), {null_key_pointers} null and {unreadable_key_buffers} unreadable key pointers, {readable_key_buffers} passphrase buffers readable, {protected_pattern_candidates} protected patterns parsed ({pattern_salt_matches} pattern salts and {codec_routed_patterns} codec salts matched), profiles {profiles:?}, {} raw keys derived",
                derived_raw_keys.len()
            );
        }
        Ok(context_count)
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn scan_masked_cipher_contexts(
        &self,
        regions: &[crate::mach_vm::MemRegion],
        targets: &[BinaryTarget<'_>],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
        tested: &mut HashSet<([u8; 32], [u8; 16])>,
    ) -> Result<usize, KeychainError> {
        const CONTEXT_SIZE: usize = 0x28;
        const CARRY_SIZE: usize = CONTEXT_SIZE - 1;
        const KEY_POINTER_OFFSETS: [usize; 2] = [0x18, 0x20];

        let mut candidate_count = 0usize;
        for region in regions {
            let region_len = (region.end - region.start) as usize;
            let mut offset = 0usize;
            let mut carry = Vec::new();

            while offset < region_len && results.is_empty() {
                let read_len = CHUNK_SIZE.min(region_len - offset);
                let chunk = match self
                    .reader
                    .read_bytes(region.start + offset as u64, read_len)
                {
                    Ok(data) => data,
                    Err(_) => {
                        offset += read_len;
                        carry.clear();
                        continue;
                    }
                };
                let carry_len = carry.len();
                let scan_buf = if carry.is_empty() {
                    chunk.clone()
                } else {
                    carry.extend_from_slice(&chunk);
                    carry.clone()
                };
                let base_address = region.start + offset.saturating_sub(carry_len) as u64;
                let first_aligned = (8 - (base_address as usize & 7)) & 7;

                if first_aligned + CONTEXT_SIZE <= scan_buf.len() {
                    for position in (first_aligned..=scan_buf.len() - CONTEXT_SIZE).step_by(8) {
                        let key_len = u32::from_le_bytes(
                            scan_buf[position + 4..position + 8]
                                .try_into()
                                .expect("cipher key length"),
                        );
                        if key_len != 32 {
                            continue;
                        }

                        for key_pointer_offset in KEY_POINTER_OFFSETS {
                            let Some(key_address) =
                                read_u64(&scan_buf, position + key_pointer_offset)
                            else {
                                continue;
                            };
                            let Ok(bytes) = self.reader.read_bytes(key_address, 32) else {
                                continue;
                            };
                            if bytes.len() != 32 {
                                continue;
                            }

                            let mut stored = [0u8; 32];
                            stored.copy_from_slice(&bytes);
                            let unmasked = std::array::from_fn(|index| {
                                stored[index] ^ WEIXIN_4_1_KEY_MASK[index]
                            });
                            for key in [stored, unmasked] {
                                candidate_count += 1;
                                validate_binary_candidate_for_targets(
                                    key, targets, params, results, seen, tested,
                                );
                                if !results.is_empty() {
                                    return Ok(candidate_count);
                                }
                            }
                        }
                    }
                }

                let keep = CARRY_SIZE.min(chunk.len());
                carry = chunk[chunk.len() - keep..].to_vec();
                offset += read_len;
            }

            if !results.is_empty() {
                break;
            }
        }
        Ok(candidate_count)
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn scan_masked_sqlcipher_context(
        &self,
        salt_reference: u64,
        salt_address: u64,
        target: &BinaryTarget<'_>,
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
        tested: &mut HashSet<([u8; 32], [u8; 16])>,
    ) -> usize {
        const KDF_SALT_OFFSET: u64 = 0x48;
        const CIPHER_CONTEXT_OFFSETS: [usize; 2] = [0x68, 0x70];
        const KEY_POINTER_OFFSETS: [usize; 2] = [0x18, 0x20];
        let Some(codec_address) = salt_reference.checked_sub(KDF_SALT_OFFSET) else {
            return 0;
        };
        let Ok(codec) = self.reader.read_bytes(codec_address, 0x78) else {
            return 0;
        };
        if codec.len() < 0x78 || read_u64(&codec, KDF_SALT_OFFSET as usize) != Some(salt_address) {
            return 0;
        }

        let mut candidate_count = 0usize;
        for context_offset in CIPHER_CONTEXT_OFFSETS {
            let Some(cipher_address) = read_u64(&codec, context_offset) else {
                continue;
            };
            let Ok(cipher) = self.reader.read_bytes(cipher_address, 0x28) else {
                continue;
            };
            if cipher.len() < 0x28 {
                continue;
            }

            let key_len = u32::from_le_bytes(cipher[4..8].try_into().expect("key length")) as usize;
            if !(32..=128).contains(&key_len) {
                continue;
            }

            for key_pointer_offset in KEY_POINTER_OFFSETS {
                let Some(key_address) = read_u64(&cipher, key_pointer_offset) else {
                    continue;
                };
                let Ok(bytes) = self.reader.read_bytes(key_address, 32) else {
                    continue;
                };
                if bytes.len() != 32 {
                    continue;
                }

                let mut stored = [0u8; 32];
                stored.copy_from_slice(&bytes);
                for key in [
                    stored,
                    std::array::from_fn(|index| stored[index] ^ WEIXIN_4_1_KEY_MASK[index]),
                ] {
                    candidate_count += 1;
                    validate_binary_candidate(key, target, params, results, seen, tested);
                    if !results.is_empty() {
                        return candidate_count;
                    }
                }
            }
        }
        candidate_count
    }

    #[cfg(windows)]
    fn scan_openssl_aes_schedules(
        &self,
        regions: &[crate::mach_vm::MemRegion],
        targets: &[BinaryTarget<'_>],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
        tested: &mut HashSet<([u8; 32], [u8; 16])>,
    ) -> Result<usize, KeychainError> {
        const AES_256_SCHEDULE_SIZE: usize = 240;
        const CARRY_SIZE: usize = AES_256_SCHEDULE_SIZE + 3;
        const AES_256_ROUNDS: [u8; 4] = 14u32.to_le_bytes();

        let mut candidate_count = 0usize;
        for region in regions {
            let region_len = (region.end - region.start) as usize;
            let mut offset = 0usize;
            let mut carry = Vec::new();

            while offset < region_len && results.is_empty() {
                let read_len = CHUNK_SIZE.min(region_len - offset);
                let chunk = match self
                    .reader
                    .read_bytes(region.start + offset as u64, read_len)
                {
                    Ok(data) => data,
                    Err(_) => {
                        offset += read_len;
                        carry.clear();
                        continue;
                    }
                };
                let carry_len = carry.len();
                let scan_buf = if carry.is_empty() {
                    chunk.clone()
                } else {
                    carry.extend_from_slice(&chunk);
                    carry.clone()
                };
                let base_address = region.start + offset.saturating_sub(carry_len) as u64;
                let minimum_position = AES_256_SCHEDULE_SIZE.max(carry_len.saturating_sub(3));
                let address_mod = (base_address + minimum_position as u64) as usize & 3;
                let first_aligned = minimum_position + ((4 - address_mod) & 3);

                if first_aligned + 4 <= scan_buf.len() {
                    for rounds_position in (first_aligned..=scan_buf.len() - 4).step_by(4) {
                        if scan_buf[rounds_position..rounds_position + 4] != AES_256_ROUNDS {
                            continue;
                        }
                        candidate_count += 1;
                        let schedule =
                            &scan_buf[rounds_position - AES_256_SCHEDULE_SIZE..rounds_position];
                        for key in openssl_schedule_key_candidates(schedule) {
                            validate_binary_candidate_for_targets(
                                key, targets, params, results, seen, tested,
                            );
                            if !results.is_empty() {
                                break;
                            }
                        }
                        if !results.is_empty() {
                            break;
                        }
                    }
                }

                let keep = CARRY_SIZE.min(chunk.len());
                carry = chunk[chunk.len() - keep..].to_vec();
                offset += read_len;
            }

            if !results.is_empty() {
                break;
            }
        }

        Ok(candidate_count)
    }

    #[cfg(windows)]
    fn scan_aligned_binary_keys(
        &self,
        regions: &[crate::mach_vm::MemRegion],
        target: &BinaryTarget<'_>,
        params: &wx_decrypt::CryptoParams,
        alignment_offset: usize,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
    ) -> Result<usize, KeychainError> {
        debug_assert!(alignment_offset < 16);
        let mut candidate_count = 0usize;

        for region in regions {
            let region_len = (region.end - region.start) as usize;
            let mut offset = 0usize;
            let mut carry = Vec::new();

            while offset < region_len && results.is_empty() {
                let read_len = CHUNK_SIZE.min(region_len - offset);
                let chunk = match self
                    .reader
                    .read_bytes(region.start + offset as u64, read_len)
                {
                    Ok(data) => data,
                    Err(_) => {
                        offset += read_len;
                        carry.clear();
                        continue;
                    }
                };
                let carry_len = carry.len();
                let scan_buf = if carry.is_empty() {
                    chunk.clone()
                } else {
                    carry.extend_from_slice(&chunk);
                    carry.clone()
                };
                let base_address = region.start + offset.saturating_sub(carry_len) as u64;

                if scan_buf.len() >= 32 {
                    let address_mod = base_address as usize & 15;
                    let first_aligned = (alignment_offset + 16 - address_mod) & 15;
                    if first_aligned + 32 <= scan_buf.len() {
                        for position in (first_aligned..=scan_buf.len() - 32).step_by(16) {
                            candidate_count += 1;
                            let key: &[u8; 32] = scan_buf[position..position + 32]
                                .try_into()
                                .expect("32-byte aligned key candidate");
                            if let Some(reserve) = wx_decrypt::validate_enc_key_header_reserves(
                                &target.first_page,
                                key,
                                &[params.reserve, 48, 64],
                            ) {
                                if seen.insert((*key, target.salt)) {
                                    if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
                                        eprintln!(
                                            "scan diagnostics: aligned AES header matched reserve {reserve}"
                                        );
                                    }
                                    results.push(ScanResult {
                                        enc_key: *key,
                                        salt: target.salt,
                                        db_path: target.path.to_path_buf(),
                                    });
                                }
                                break;
                            }
                        }
                    }
                }

                let keep = 31.min(chunk.len());
                carry = chunk[chunk.len() - keep..].to_vec();
                offset += read_len;
            }

            if !results.is_empty() {
                break;
            }
        }

        Ok(candidate_count)
    }

    fn validate_candidate(
        &self,
        found: &FoundKey,
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
    ) {
        match found.salt {
            Some(salt_hint) => {
                for (salt, db_path) in db_salts {
                    if *salt != salt_hint {
                        continue;
                    }
                    if validate_key_for_db(&found.enc_key, salt, db_path, params)
                        && seen.insert((found.enc_key, *salt))
                    {
                        results.push(ScanResult {
                            enc_key: found.enc_key,
                            salt: *salt,
                            db_path: db_path.to_path_buf(),
                        });
                    }
                    break;
                }
            }
            None => {
                for (salt, db_path) in db_salts {
                    if validate_key_for_db(&found.enc_key, salt, db_path, params)
                        && seen.insert((found.enc_key, *salt))
                    {
                        results.push(ScanResult {
                            enc_key: found.enc_key,
                            salt: *salt,
                            db_path: db_path.to_path_buf(),
                        });
                    }
                }
            }
        }
    }

    fn cross_validate_known_keys(
        &self,
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
    ) {
        if results.is_empty() {
            return;
        }

        let matched_salts: HashSet<[u8; 16]> = results.iter().map(|r| r.salt).collect();
        let known_keys: HashSet<[u8; 32]> = results.iter().map(|r| r.enc_key).collect();

        for (salt, db_path) in db_salts {
            if matched_salts.contains(salt) {
                continue;
            }
            for enc_key in &known_keys {
                if validate_key_for_db(enc_key, salt, db_path, params)
                    && seen.insert((*enc_key, *salt))
                {
                    results.push(ScanResult {
                        enc_key: *enc_key,
                        salt: *salt,
                        db_path: db_path.to_path_buf(),
                    });
                    break;
                }
            }
        }
    }

    /// Scan all regions, returning deduplicated candidates.
    fn scan_regions(
        &self,
        regions: &[crate::mach_vm::MemRegion],
    ) -> Result<(Vec<FoundKey>, Vec<[u8; 32]>), KeychainError> {
        let mut seen = HashSet::new();
        let mut all_keys = Vec::new();
        let mut seen_raw_keys = HashSet::new();
        let mut raw_keys = Vec::new();

        for region in regions {
            let region_len = (region.end - region.start) as usize;
            if region_len == 0 {
                continue;
            }

            let mut offset: u64 = 0;
            let mut carry: Vec<u8> = Vec::new();

            while (offset as usize) < region_len {
                let read_len = CHUNK_SIZE.min(region_len - offset as usize);
                let chunk = match self.reader.read_bytes(region.start + offset, read_len) {
                    Ok(data) => data,
                    Err(_) => {
                        offset += read_len as u64;
                        carry.clear();
                        continue;
                    }
                };

                let scan_buf = if carry.is_empty() {
                    chunk.clone()
                } else {
                    let mut buf = carry.clone();
                    buf.extend_from_slice(&chunk);
                    buf
                };

                for found in scan_chunk(&scan_buf) {
                    if seen.insert(found.clone()) {
                        all_keys.push(found);
                    }
                }
                for raw_key in scan_bare_hex_keys(&scan_buf) {
                    if seen_raw_keys.insert(raw_key) {
                        raw_keys.push(raw_key);
                    }
                }

                carry = if chunk.len() > OVERLAP {
                    chunk[chunk.len() - OVERLAP..].to_vec()
                } else {
                    chunk.clone()
                };

                offset += read_len as u64;
            }
        }

        Ok((all_keys, raw_keys))
    }
}

#[cfg(windows)]
fn validate_windows_raw_keys(
    raw_keys: &[[u8; 32]],
    target: &BinaryTarget<'_>,
    params: &wx_decrypt::CryptoParams,
    results: &mut Vec<ScanResult>,
    seen: &mut HashSet<([u8; 32], [u8; 16])>,
) -> Result<usize, KeychainError> {
    const MAX_PBKDF2_CANDIDATES: usize = 512;

    for key in raw_keys {
        if let Some(reserve) = wx_decrypt::validate_enc_key_header_reserves(
            &target.first_page,
            key,
            &[48, params.reserve, 64],
        ) {
            if seen.insert((*key, target.salt)) {
                if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
                    eprintln!("scan diagnostics: direct raw-key string matched reserve {reserve}");
                }
                results.push(ScanResult {
                    enc_key: *key,
                    salt: target.salt,
                    db_path: target.path.to_path_buf(),
                });
            }
            return Ok(0);
        }
    }

    let pbkdf2 = WindowsPbkdf2Sha1::new()?;
    let mut derived = 0usize;

    for raw_key in raw_keys.iter().take(MAX_PBKDF2_CANDIDATES) {
        derived += 1;
        let enc_key = pbkdf2.derive(raw_key, &target.salt, 64_000)?;
        if let Some(reserve) = wx_decrypt::validate_enc_key_header_reserves(
            &target.first_page,
            &enc_key,
            &[48, params.reserve, 64],
        ) {
            if seen.insert((enc_key, target.salt)) {
                if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "scan diagnostics: PBKDF2-SHA1 raw-key string matched reserve {reserve}"
                    );
                }
                results.push(ScanResult {
                    enc_key,
                    salt: target.salt,
                    db_path: target.path.to_path_buf(),
                });
            }
            break;
        }
    }
    Ok(derived)
}

#[cfg(windows)]
struct WindowsPbkdf2Sha1 {
    handle: windows_sys::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE,
}

#[cfg(windows)]
impl WindowsPbkdf2Sha1 {
    fn new() -> Result<Self, KeychainError> {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE_HMAC_FLAG, BCRYPT_SHA1_ALGORITHM,
        };

        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut handle,
                BCRYPT_SHA1_ALGORITHM,
                std::ptr::null(),
                BCRYPT_ALG_HANDLE_HMAC_FLAG,
            )
        };
        if status < 0 {
            return Err(KeychainError::Other(format!(
                "BCryptOpenAlgorithmProvider(SHA1) failed: NTSTATUS {status:#x}"
            )));
        }
        Ok(Self { handle })
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u64,
    ) -> Result<[u8; 32], KeychainError> {
        use windows_sys::Win32::Security::Cryptography::BCryptDeriveKeyPBKDF2;

        let mut output = [0u8; 32];
        let status = unsafe {
            BCryptDeriveKeyPBKDF2(
                self.handle,
                password.as_ptr(),
                password.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                iterations,
                output.as_mut_ptr(),
                output.len() as u32,
                0,
            )
        };
        if status < 0 {
            return Err(KeychainError::Other(format!(
                "BCryptDeriveKeyPBKDF2 failed: NTSTATUS {status:#x}"
            )));
        }
        Ok(output)
    }
}

#[cfg(windows)]
impl Drop for WindowsPbkdf2Sha1 {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Security::Cryptography::BCryptCloseAlgorithmProvider(
                self.handle,
                0,
            );
        }
    }
}

#[cfg(windows)]
fn validate_binary_candidate(
    key: [u8; 32],
    target: &BinaryTarget<'_>,
    params: &wx_decrypt::CryptoParams,
    results: &mut Vec<ScanResult>,
    seen: &mut HashSet<([u8; 32], [u8; 16])>,
    tested: &mut HashSet<([u8; 32], [u8; 16])>,
) {
    let salt = target.salt;
    if !tested.insert((key, salt)) {
        return;
    }
    let matched_reserve = wx_decrypt::validate_enc_key_header_reserves(
        &target.first_page,
        &key,
        &[params.reserve, 48, 64],
    );
    let hmac_matches = wx_decrypt::validate_enc_key(&target.first_page, &key, &target.salt, params);
    if (matched_reserve.is_some() || hmac_matches) && seen.insert((key, salt)) {
        if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
            if let Some(reserve) = matched_reserve {
                eprintln!("scan diagnostics: AES header matched reserve {reserve}");
            } else {
                eprintln!("scan diagnostics: database page HMAC matched");
            }
        }
        results.push(ScanResult {
            enc_key: key,
            salt,
            db_path: target.path.to_path_buf(),
        });
    }
}

#[cfg(windows)]
fn validate_binary_candidate_for_targets(
    key: [u8; 32],
    targets: &[BinaryTarget<'_>],
    params: &wx_decrypt::CryptoParams,
    results: &mut Vec<ScanResult>,
    seen: &mut HashSet<([u8; 32], [u8; 16])>,
    tested: &mut HashSet<([u8; 32], [u8; 16])>,
) -> Option<usize> {
    for (index, target) in targets.iter().enumerate() {
        let result_count = results.len();
        validate_binary_candidate(key, target, params, results, seen, tested);
        if results.len() > result_count {
            return Some(index);
        }
    }
    None
}

#[cfg(windows)]
fn validate_found_candidate_for_targets(
    found: &FoundKey,
    targets: &[BinaryTarget<'_>],
    params: &wx_decrypt::CryptoParams,
    results: &mut Vec<ScanResult>,
    seen: &mut HashSet<([u8; 32], [u8; 16])>,
    tested: &mut HashSet<([u8; 32], [u8; 16])>,
) {
    if let Some(salt) = found.salt {
        if let Some(target) = targets.iter().find(|target| target.salt == salt) {
            validate_found_candidate_for_target(found, target, params, results, seen, tested);
        }
    } else {
        for target in targets {
            let result_count = results.len();
            validate_found_candidate_for_target(found, target, params, results, seen, tested);
            if results.len() > result_count {
                break;
            }
        }
    }
}

#[cfg(windows)]
fn validate_found_candidate_for_target(
    found: &FoundKey,
    target: &BinaryTarget<'_>,
    params: &wx_decrypt::CryptoParams,
    results: &mut Vec<ScanResult>,
    seen: &mut HashSet<([u8; 32], [u8; 16])>,
    tested: &mut HashSet<([u8; 32], [u8; 16])>,
) {
    let result_count = results.len();
    validate_binary_candidate(found.enc_key, target, params, results, seen, tested);
    if results.len() == result_count {
        let derived = wx_decrypt::kdf::derive_enc_key(&found.enc_key, &target.salt, params);
        validate_binary_candidate(derived, target, params, results, seen, tested);
    }
}

#[cfg(windows)]
fn unmask_weixin_key_buffer(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ WEIXIN_4_1_KEY_MASK[index & 31])
        .collect()
}

#[cfg(windows)]
fn windows_cipher_key_candidates(bytes: &[u8]) -> Vec<[u8; 32]> {
    let mut candidates = Vec::new();
    if bytes.len() >= 32 {
        for offset in [0, bytes.len() - 32] {
            let mut stored = [0u8; 32];
            stored.copy_from_slice(&bytes[offset..offset + 32]);
            candidates.push(stored);
            candidates.push(std::array::from_fn(|index| {
                stored[index] ^ WEIXIN_4_1_KEY_MASK[(offset + index) & 31]
            }));
        }
    }

    if bytes.len() == 64 {
        for value in [bytes.to_vec(), unmask_weixin_key_buffer(bytes)] {
            if let Ok(decoded) = hex::decode(value) {
                if let Ok(key) = <[u8; 32]>::try_from(decoded) {
                    candidates.push(key);
                }
            }
        }
    }

    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

#[cfg(windows)]
struct BinaryTarget<'a> {
    salt: [u8; 16],
    path: &'a Path,
    first_page: Vec<u8>,
}

#[cfg(windows)]
fn openssl_schedule_key_candidates(schedule: &[u8]) -> Vec<[u8; 32]> {
    if schedule.len() != 240 {
        return Vec::new();
    }

    let mut candidates = Vec::with_capacity(4);
    for swap_words in [false, true] {
        let first_half = decode_round_key(&schedule[224..240], swap_words);
        let encoded_second_half = decode_round_key(&schedule[208..224], swap_words);

        let mut direct = [0u8; 32];
        direct[..16].copy_from_slice(&first_half);
        direct[16..].copy_from_slice(&encoded_second_half);
        candidates.push(direct);

        let mut mixed_second_half = encoded_second_half;
        mix_columns(&mut mixed_second_half);
        let mut inverse_schedule = [0u8; 32];
        inverse_schedule[..16].copy_from_slice(&first_half);
        inverse_schedule[16..].copy_from_slice(&mixed_second_half);
        candidates.push(inverse_schedule);
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

#[cfg(windows)]
fn decode_round_key(bytes: &[u8], swap_words: bool) -> [u8; 16] {
    let mut result: [u8; 16] = bytes.try_into().expect("AES round key size");
    if swap_words {
        for word in result.chunks_exact_mut(4) {
            word.reverse();
        }
    }
    result
}

#[cfg(windows)]
fn mix_columns(block: &mut [u8; 16]) {
    for column in block.chunks_exact_mut(4) {
        let first = column[0];
        let all = column[0] ^ column[1] ^ column[2] ^ column[3];
        column[0] ^= all ^ xtime(column[0] ^ column[1]);
        column[1] ^= all ^ xtime(column[1] ^ column[2]);
        column[2] ^= all ^ xtime(column[2] ^ column[3]);
        column[3] ^= all ^ xtime(column[3] ^ first);
    }
}

#[cfg(windows)]
fn xtime(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 == 0 { 0 } else { 0x1b }
}

#[cfg(windows)]
fn candidate_starts(start: usize, end: usize, salt_position: usize) -> Vec<usize> {
    let mut starts = Vec::new();
    let near_start = salt_position.saturating_sub(128).max(start);
    let near_end = (salt_position + 16 + 128).min(end);
    starts.extend(near_start..near_end.saturating_sub(31));

    let mut position = start;
    while position + 32 <= end {
        starts.push(position);
        position += 8;
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

#[cfg(windows)]
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(windows)]
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn validate_key_for_db(
    enc_key: &[u8; 32],
    salt: &[u8; 16],
    db_path: &Path,
    params: &wx_decrypt::CryptoParams,
) -> bool {
    let first_page = match wx_decrypt::read_prefix_shared(db_path, params.page_size) {
        Ok(data) => data,
        _ => return false,
    };

    wx_decrypt::validate_enc_key(&first_page, enc_key, salt, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mach_vm::reader::MemRegion;
    use wx_decrypt::MACOS_4_1_7_31;

    struct MockReader {
        regions: Vec<MemRegion>,
        data: Vec<u8>,
    }

    impl MemoryReader for MockReader {
        fn rw_regions(&self) -> Result<Vec<MemRegion>, KeychainError> {
            Ok(self.regions.clone())
        }

        fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, KeychainError> {
            let start = addr as usize;
            let end = (start + len).min(self.data.len());
            if start >= self.data.len() {
                return Err(KeychainError::Other("out of bounds".into()));
            }
            Ok(self.data[start..end].to_vec())
        }
    }

    fn make_pattern(enc_key: &[u8; 32], salt: &[u8; 16]) -> Vec<u8> {
        format!("x'{}{}'", hex::encode(enc_key), hex::encode(salt)).into_bytes()
    }

    fn make_key_only_pattern(enc_key: &[u8; 32]) -> Vec<u8> {
        format!("x'{}'", hex::encode(enc_key)).into_bytes()
    }

    fn make_long_pattern(enc_key: &[u8; 32], middle_hex: &str, salt: &[u8; 16]) -> Vec<u8> {
        format!(
            "x'{}{}{}'",
            hex::encode(enc_key),
            middle_hex,
            hex::encode(salt)
        )
        .into_bytes()
    }

    fn build_first_page(enc_key: &[u8; 32], salt: &[u8; 16]) -> Vec<u8> {
        use aes::cipher::{block_padding::NoPadding, BlockModeEncrypt, KeyIvInit};
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let params = &MACOS_4_1_7_31;
        let iv = [0x42u8; 16];
        let data_len = params.page_size - params.reserve - params.salt_size;
        let plaintext = vec![0u8; data_len];

        let mut ciphertext = plaintext;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        Aes256CbcEnc::new(enc_key.into(), (&iv).into())
            .encrypt_padded::<NoPadding>(&mut ciphertext, data_len)
            .unwrap();

        let mut page = vec![0u8; params.page_size];
        page[..params.salt_size].copy_from_slice(salt);
        page[params.salt_size..params.salt_size + data_len].copy_from_slice(&ciphertext);

        let iv_start = params.page_size - params.reserve;
        page[iv_start..iv_start + params.iv_size].copy_from_slice(&iv);

        let hmac_data_end = params.page_size - params.reserve + params.iv_size;
        let mac_key = wx_decrypt::kdf::derive_mac_key(enc_key, salt, params);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[params.salt_size..hmac_data_end]);
        mac.update(&1u32.to_le_bytes());
        let hmac_result = mac.finalize().into_bytes();
        page[hmac_data_end..hmac_data_end + params.hmac_size]
            .copy_from_slice(&hmac_result[..params.hmac_size]);

        page
    }

    #[test]
    fn mock_reader_finds_valid_pattern() {
        let enc_key = [0xABu8; 32];
        let salt = [0x01u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let mut data = vec![0u8; 1000];
        let pattern = make_pattern(&enc_key, &salt);
        data[100..100 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].enc_key, enc_key);
        assert_eq!(results[0].salt, salt);
    }

    #[test]
    fn key_only_pattern_validates_against_known_dbs() {
        let enc_key = [0xABu8; 32];
        let salt = [0x01u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let mut data = vec![0u8; 1000];
        let pattern = make_key_only_pattern(&enc_key);
        data[100..100 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].salt, salt);
    }

    #[test]
    fn long_hex_pattern_uses_first_key_and_last_salt() {
        let enc_key = [0xCDu8; 32];
        let salt = [0x02u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let mut data = vec![0u8; 2048];
        let pattern = make_long_pattern(&enc_key, &"a1".repeat(20), &salt);
        data[300..300 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].enc_key, enc_key);
        assert_eq!(results[0].salt, salt);
    }

    #[test]
    fn cross_validation_reuses_known_key_for_missing_salt() {
        let enc_key = [0xAAu8; 32];
        let salt1 = [0x01u8; 16];
        let salt2 = [0x02u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db1 = dir.path().join("db1.db");
        let db2 = dir.path().join("db2.db");
        std::fs::write(&db1, build_first_page(&enc_key, &salt1)).unwrap();
        std::fs::write(&db2, build_first_page(&enc_key, &salt2)).unwrap();

        let mut data = vec![0u8; 1000];
        let pattern = make_pattern(&enc_key, &salt1);
        data[100..100 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner
            .scan(
                &[(salt1, db1.as_path()), (salt2, db2.as_path())],
                &MACOS_4_1_7_31,
            )
            .unwrap();

        assert_eq!(results.len(), 2);
        let salts: Vec<_> = results.iter().map(|r| r.salt).collect();
        assert!(salts.contains(&salt1));
        assert!(salts.contains(&salt2));
    }

    #[test]
    fn pattern_spanning_chunks_found_via_overlap() {
        let enc_key = [0xEFu8; 32];
        let salt = [0x03u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let pattern = make_long_pattern(&enc_key, &"a1".repeat(20), &salt);
        let split_point = CHUNK_SIZE - 100;
        let total_len = split_point + pattern.len();
        let mut data = vec![0u8; total_len];
        data[split_point..split_point + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].salt, salt);
    }

    #[cfg(windows)]
    #[test]
    fn aligned_fallback_finds_key_far_from_salt() {
        let enc_key = [0x7Bu8; 32];
        let salt = [0x31u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let mut first_page = build_first_page(&enc_key, &salt);
        first_page[16..32].fill(0);
        let iv_start = MACOS_4_1_7_31.page_size - MACOS_4_1_7_31.reserve;
        first_page[iv_start..iv_start + 16].fill(0);

        use aes::cipher::{block_padding::NoPadding, BlockModeEncrypt, KeyIvInit};
        let mut header = b"SQLite format 3\0".to_vec();
        cbc::Encryptor::<aes::Aes256>::new((&enc_key).into(), (&[0u8; 16]).into())
            .encrypt_padded::<NoPadding>(&mut header, 16)
            .unwrap();
        first_page[16..32].copy_from_slice(&header);
        std::fs::write(&db_path, first_page).unwrap();

        let mut data = vec![0u8; 8192];
        data[100..116].copy_from_slice(&salt);
        data[4104..4136].copy_from_slice(&enc_key); // 8-byte aligned, not 16-byte aligned.

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].enc_key, enc_key);
    }

    #[cfg(windows)]
    #[test]
    fn mix_columns_matches_fips_197_example() {
        let mut block = [
            0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6,
            0xc6, 0xc6,
        ];
        mix_columns(&mut block);
        assert_eq!(
            block,
            [
                0x8e, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6,
                0xc6, 0xc6,
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn openssl_schedule_candidates_restore_word_order() {
        let key: [u8; 32] = std::array::from_fn(|index| index as u8);
        let mut schedule = [0u8; 240];
        for (source, destination) in key[..16]
            .chunks_exact(4)
            .zip(schedule[224..240].chunks_exact_mut(4))
        {
            destination.copy_from_slice(source);
            destination.reverse();
        }
        for (source, destination) in key[16..]
            .chunks_exact(4)
            .zip(schedule[208..224].chunks_exact_mut(4))
        {
            destination.copy_from_slice(source);
            destination.reverse();
        }

        assert!(openssl_schedule_key_candidates(&schedule).contains(&key));
    }
}
