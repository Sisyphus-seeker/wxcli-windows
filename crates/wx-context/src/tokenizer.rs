use rust_stemmers::{Algorithm, Stemmer};

/// Configuration flags for the MMFtsTokenizer.
///
/// Mirrors WCDB's `OneOrBinaryTokenizer` config parameters.
#[derive(Debug, Clone, Default)]
pub struct TokenizerConfig {
    /// Emit each special/symbol character as a token.
    pub enable_special_char: bool,
    /// Emit ASCII digit sequences as tokens.
    pub enable_num_token: bool,
    /// Skip Porter stemming (emit lowercased form only).
    pub skip_stemming: bool,
}

/// A single token emitted by the tokenizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    /// Byte offset of the first byte in the input.
    pub start: usize,
    /// Byte offset one past the last byte in the input.
    pub end: usize,
    /// True for colocated (synonym/variant) tokens — they share position with
    /// the preceding primary token (FTS5_TOKEN_COLOCATED).
    pub colocated: bool,
}

impl Token {
    fn primary(text: String, start: usize, end: usize) -> Self {
        Token {
            text,
            start,
            end,
            colocated: false,
        }
    }

    fn colocated(text: String, start: usize, end: usize) -> Self {
        Token {
            text,
            start,
            end,
            colocated: true,
        }
    }
}

/// Tokenize `input` according to WCDB's `OneOrBinaryTokenizer` (m_needBinary=false).
///
/// - ASCII letters → one token (lowercased + Porter-stemmed; original lowercased
///   form emitted as colocated token if it differs from stem)
/// - ASCII digits → one token if `enable_num_token`, else skipped
/// - CJK / BMP multi-byte / Auxiliary Plane → each codepoint is one token
/// - Symbols → emitted as individual token if `enable_special_char`, else skipped
pub fn tokenize(input: &[u8], config: &TokenizerConfig) -> Vec<Token> {
    let Ok(text) = std::str::from_utf8(input) else {
        return Vec::new();
    };
    if text.is_empty() {
        return Vec::new();
    }

    let stemmer = if config.skip_stemming {
        None
    } else {
        Some(Stemmer::create(Algorithm::English))
    };

    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() {
        let byte = bytes[pos];

        if byte < 0xC0 {
            // Single-byte UTF-8 (ASCII)
            let ch = byte as char;

            if ch.is_ascii_alphabetic() {
                // Consume consecutive ASCII letters
                let start = pos;
                while pos < bytes.len() && (bytes[pos] as char).is_ascii_alphabetic() {
                    pos += 1;
                }
                let word = &text[start..pos];
                let lowercased = word.to_lowercase();

                if let Some(ref s) = stemmer {
                    let stemmed = s.stem(&lowercased).into_owned();
                    if stemmed != lowercased {
                        // Emit stemmed form as primary
                        tokens.push(Token::primary(stemmed, start, pos));
                        // Emit original lowercased form as colocated (for exact match)
                        tokens.push(Token::colocated(lowercased, start, pos));
                    } else {
                        tokens.push(Token::primary(lowercased, start, pos));
                    }
                } else {
                    tokens.push(Token::primary(lowercased, start, pos));
                }
            } else if ch.is_ascii_digit() {
                // Consume consecutive ASCII digits
                let start = pos;
                while pos < bytes.len() && (bytes[pos] as char).is_ascii_digit() {
                    pos += 1;
                }
                if config.enable_num_token {
                    let num_str = &text[start..pos];
                    tokens.push(Token::primary(num_str.to_string(), start, pos));
                }
            } else {
                // Symbol or whitespace (0x00-0x2F range minus letters/digits, etc.)
                if config.enable_special_char && !ch.is_ascii_whitespace() && !ch.is_ascii_control()
                {
                    let sym = ch.to_string();
                    tokens.push(Token::primary(sym, pos, pos + 1));
                }
                pos += 1;
            }
        } else if byte < 0xF0 {
            // 2-3 byte UTF-8 → BMP multi-byte character
            let char_len = utf8_char_len(byte);
            let start = pos;
            pos += char_len;
            let ch_str = &text[start..pos];

            // Check if this is a symbol that should be emitted or skipped
            let is_sym = is_symbol_char(ch_str);
            if is_sym {
                if config.enable_special_char {
                    tokens.push(Token::primary(ch_str.to_string(), start, pos));
                }
            } else {
                // BMP-Other (including CJK): emit as individual unigram token
                tokens.push(Token::primary(ch_str.to_string(), start, pos));
            }
        } else {
            // 4+ byte UTF-8 → Auxiliary Plane character
            let char_len = utf8_char_len(byte);
            let start = pos;
            pos += char_len;
            let ch_str = &text[start..pos];
            // Each codepoint emitted individually
            tokens.push(Token::primary(ch_str.to_string(), start, pos));
        }
    }

    tokens
}

/// Return the byte-length of a UTF-8 character given its leading byte.
fn utf8_char_len(leading: u8) -> usize {
    if leading < 0x80 {
        1
    } else if leading < 0xE0 {
        2
    } else if leading < 0xF0 {
        3
    } else if leading < 0xF8 {
        4
    } else if leading < 0xFC {
        5
    } else {
        6
    }
}

/// Heuristic: is this 2-3 byte BMP character a "symbol"?
///
/// In practice WCDB's symbol detector is rarely configured for message_fts.db,
/// so we conservatively only mark obvious punctuation Unicode blocks as symbols.
/// This preserves CJK characters, Hangul, etc. as normal tokens.
fn is_symbol_char(s: &str) -> bool {
    s.chars().all(|c| {
        // General punctuation and symbol blocks
        matches!(c,
            '\u{2000}'..='\u{206F}'   // General Punctuation
            | '\u{2E00}'..='\u{2E7F}' // Supplemental Punctuation
            | '\u{3000}'..='\u{303F}' // CJK Symbols and Punctuation
        )
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_default() -> TokenizerConfig {
        TokenizerConfig::default()
    }

    fn primary_texts(tokens: &[Token]) -> Vec<String> {
        tokens
            .iter()
            .filter(|t| !t.colocated)
            .map(|t| t.text.clone())
            .collect()
    }

    fn all_texts(tokens: &[Token]) -> Vec<String> {
        tokens.iter().map(|t| t.text.clone()).collect()
    }

    // Test 1: Empty input → empty tokens
    #[test]
    fn empty_input() {
        let tokens = tokenize(b"", &cfg_default());
        assert!(tokens.is_empty());
    }

    // Test 2: Pure ASCII letters: "hello" → stemmed form (no diff for "hello")
    #[test]
    fn pure_ascii_letters() {
        let tokens = tokenize(b"hello", &cfg_default());
        let primary: Vec<_> = tokens.iter().filter(|t| !t.colocated).collect();
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].start, 0);
        assert_eq!(primary[0].end, 5);
        // "hello" → Porter stem → "hello" (no stem difference)
        assert_eq!(primary[0].text, "hello");
    }

    // Test 3: Pure CJK: "你好世界" → 4 individual unigram tokens with correct byte offsets
    #[test]
    fn pure_cjk() {
        let tokens = tokenize("你好世界".as_bytes(), &cfg_default());
        let primary = primary_texts(&tokens);
        assert_eq!(primary, vec!["你", "好", "世", "界"]);
        // Each CJK char is 3 bytes in UTF-8
        assert_eq!(tokens[0].start, 0);
        assert_eq!(tokens[0].end, 3);
        assert_eq!(tokens[1].start, 3);
        assert_eq!(tokens[1].end, 6);
        assert_eq!(tokens[2].start, 6);
        assert_eq!(tokens[2].end, 9);
        assert_eq!(tokens[3].start, 9);
        assert_eq!(tokens[3].end, 12);
    }

    // Test 4: Mixed CJK + ASCII: "你好world" → ["你", "好", "world"]
    #[test]
    fn mixed_cjk_ascii() {
        let tokens = tokenize("你好world".as_bytes(), &cfg_default());
        let primary = primary_texts(&tokens);
        assert_eq!(primary, vec!["你", "好", "world"]);
    }

    // Test 5: Digits with enable_num_token
    #[test]
    fn digits_disabled() {
        let tokens = tokenize(b"abc123", &cfg_default());
        let primary = primary_texts(&tokens);
        // digits skipped by default
        assert!(primary.iter().all(|t| t != "123"));
    }

    #[test]
    fn digits_enabled() {
        let config = TokenizerConfig {
            enable_num_token: true,
            ..Default::default()
        };
        let tokens = tokenize(b"abc123", &config);
        let primary = primary_texts(&tokens);
        assert!(primary.contains(&"123".to_string()));
    }

    // Test 6: Symbols skip/emit
    #[test]
    fn symbols_default_skipped() {
        let tokens = tokenize(b"hello!world", &cfg_default());
        let primary = primary_texts(&tokens);
        // "!" should not appear in tokens
        assert!(!primary.contains(&"!".to_string()));
    }

    #[test]
    fn symbols_enabled() {
        let config = TokenizerConfig {
            enable_special_char: true,
            ..Default::default()
        };
        let tokens = tokenize(b"hello!world", &config);
        let texts = all_texts(&tokens);
        assert!(texts.contains(&"!".to_string()));
    }

    // Test 7: Porter stemming: "running" → "run"
    #[test]
    fn porter_stemming_running() {
        let tokens = tokenize(b"running", &cfg_default());
        // Primary token should be the stemmed form
        let primary: Vec<_> = tokens.iter().filter(|t| !t.colocated).collect();
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].text, "run");
        // Colocated token should be the original lowercased form
        let colocated: Vec<_> = tokens.iter().filter(|t| t.colocated).collect();
        assert_eq!(colocated.len(), 1);
        assert_eq!(colocated[0].text, "running");
    }

    // Test 8: Consecutive types: "abc123你好" (digits disabled by default)
    #[test]
    fn consecutive_types() {
        let tokens = tokenize("abc123你好".as_bytes(), &cfg_default());
        let primary = primary_texts(&tokens);
        // abc → stemmed (no stem diff for "abc"), then CJK chars
        assert!(primary.contains(&"你".to_string()));
        assert!(primary.contains(&"好".to_string()));
        // digits skipped
        assert!(!primary.contains(&"123".to_string()));
    }

    #[test]
    fn consecutive_types_num_enabled() {
        let config = TokenizerConfig {
            enable_num_token: true,
            ..Default::default()
        };
        let tokens = tokenize("abc123你好".as_bytes(), &config);
        let primary = primary_texts(&tokens);
        assert!(primary.contains(&"123".to_string()));
        assert!(primary.contains(&"abc".to_string()));
        assert!(primary.contains(&"你".to_string()));
        assert!(primary.contains(&"好".to_string()));
    }

    // Test 9: 4-byte emoji "😀" → single token
    #[test]
    fn emoji_single_token() {
        let emoji = "😀";
        let tokens = tokenize(emoji.as_bytes(), &cfg_default());
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].text, "😀");
        assert_eq!(tokens[0].start, 0);
        assert_eq!(tokens[0].end, 4); // 😀 is 4 bytes in UTF-8
    }

    // Test 10: Fullwidth "！" (U+FF01) — in Fullwidth Forms, treated as BMP-Other
    // With enable_special_char=false, if it's classified as symbol it should be skipped.
    // Since U+FF01 is NOT in our symbol ranges, it's emitted as a normal token.
    #[test]
    fn fullwidth_forms() {
        let s = "！"; // U+FF01 fullwidth exclamation mark (3 bytes)
        let tokens = tokenize(s.as_bytes(), &cfg_default());
        // U+FF01 is NOT in our symbol ranges → emitted as BMP-Other token
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].text, "！");
    }

    // Additional: skip_stemming mode
    #[test]
    fn skip_stemming_mode() {
        let config = TokenizerConfig {
            skip_stemming: true,
            ..Default::default()
        };
        let tokens = tokenize(b"running", &config);
        let primary = primary_texts(&tokens);
        assert_eq!(primary, vec!["running"]);
        // No colocated tokens
        assert!(!tokens.iter().any(|t| t.colocated));
    }

    // Additional: byte offsets for mixed content
    #[test]
    fn byte_offsets_mixed() {
        // "hi你" — "hi" is 2 bytes, "你" starts at byte 2
        let tokens = tokenize("hi你".as_bytes(), &cfg_default());
        let primary: Vec<_> = tokens.iter().filter(|t| !t.colocated).collect();
        assert_eq!(primary[0].text, "hi");
        assert_eq!(primary[0].start, 0);
        assert_eq!(primary[0].end, 2);
        assert_eq!(primary[1].text, "你");
        assert_eq!(primary[1].start, 2);
        assert_eq!(primary[1].end, 5); // 你 is 3 bytes
    }
}
