//! RFC 4518 string preparation, which RFC 5280 §7.1 asks for when comparing
//! names, less the steps that need Unicode tables.
//!
//! Applied: the §2.2 mappings, the §2.4 prohibitions that are plain ranges,
//! and the §2.6.1 insignificant space handling. Approximated: case folding
//! is `char::to_lowercase`, one character at a time, not RFC 3454 table B.2.
//! Not applied: §2.3 NFKC normalization and the §2.4 prohibition of
//! unassigned code points. So text that only those steps would reconcile,
//! such as a precomposed and a decomposed accent, or `ß` and `ss`, does not
//! match.

use alloc::string::String;

/// Whether two texts match after preparation. Text that preparation
/// rejects matches only identical text, which keeps the relation an
/// equivalence.
pub(crate) fn text_equivalent(a: &str, b: &str) -> bool {
    match (prepare(a), prepare(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

/// The prepared text, or `None` when a prohibited code point occurs.
///
/// §2.6.1 turns a stored value into one SPACE, the words separated by two
/// SPACEs, and one SPACE; the words joined by a single space compare the
/// same, and that is the form kept here.
fn prepare(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut space_pending = false;
    for c in text.chars() {
        if is_prohibited(c) {
            return None;
        }
        if maps_to_nothing(c) {
            continue;
        }
        if maps_to_space(c) {
            space_pending = !out.is_empty();
            continue;
        }
        if space_pending {
            out.push(' ');
            space_pending = false;
        }
        out.extend(c.to_lowercase());
    }
    Some(out)
}

/// §2.2: soft hyphens, the combining grapheme joiner, variation selectors,
/// the object replacement character, zero width space, and every other
/// control or format character. The RFC prints the variation selectors as
/// `FF00-FE0F`, a typo for `FE00-FE0F`.
fn maps_to_nothing(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{1806}'
            | '\u{034F}'
            | '\u{180B}'..='\u{180D}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FFFC}'
            | '\u{200B}'
            | '\u{0000}'..='\u{0008}'
            | '\u{000E}'..='\u{001F}'
            | '\u{007F}'..='\u{0084}'
            | '\u{0086}'..='\u{009F}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{180E}'
            | '\u{200C}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2063}'
            | '\u{206A}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// §2.2: the tab and line controls, and every space, line or paragraph
/// separator.
fn maps_to_space(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0085}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// §2.4: private use (RFC 3454 table C.3), noncharacters (C.4) and U+FFFD.
/// Surrogates (C.5) cannot occur in a `str`, and every code point of C.8 is
/// mapped to nothing above or, for U+0340 and U+0341, would be normalized
/// away by NFKC.
fn is_prohibited(c: char) -> bool {
    matches!(
        c,
        '\u{E000}'..='\u{F8FF}'
            | '\u{F0000}'..='\u{FFFFD}'
            | '\u{100000}'..='\u{10FFFD}'
            | '\u{FDD0}'..='\u{FDEF}'
            | '\u{FFFD}'
    ) || c as u32 & 0xFFFE == 0xFFFE
}

#[cfg(test)]
mod tests {
    use super::text_equivalent;

    #[test]
    fn case_and_insignificant_spaces_do_not_matter_but_word_breaks_do() {
        assert!(text_equivalent("Root CA", "root ca"));
        assert!(text_equivalent("  Root   CA  ", "Root CA"));
        assert!(text_equivalent(
            "\u{039F}\u{0394}\u{039F}\u{03A3}",
            "\u{03BF}\u{03B4}\u{03BF}\u{03C3}"
        ));
        assert!(text_equivalent(" ", "   "));
        assert!(!text_equivalent("RootCA", "Root CA"));
    }

    #[test]
    fn controls_and_separators_become_spaces() {
        assert!(text_equivalent("Root\tCA\r\n", "Root CA"));
        assert!(text_equivalent("Root\u{0085}CA", "Root CA"));
        assert!(text_equivalent("Root\u{00A0}CA", "Root CA"));
        assert!(text_equivalent("Root\u{3000}CA", "Root CA"));
        assert!(text_equivalent("Root\u{2028}CA", "Root CA"));
    }

    #[test]
    fn invisible_characters_are_dropped() {
        assert!(text_equivalent("Ro\u{00AD}ot CA", "Root CA"));
        assert!(text_equivalent("Root\u{200B}CA", "RootCA"));
        assert!(text_equivalent("\u{FEFF}Root CA", "Root CA"));
        assert!(text_equivalent("Root\u{200D} CA\u{FE0F}", "Root CA"));
        assert!(text_equivalent(
            "Root\u{0000}\u{001F}\u{E0041} CA",
            "Root CA"
        ));
        // Dropped before spaces are handled, so they cannot join two words.
        assert!(text_equivalent("Root \u{200B} CA", "Root CA"));
    }

    #[test]
    fn prohibited_text_matches_only_identical_text() {
        for bad in [
            "CA\u{E000}",
            "CA\u{FFFD}",
            "CA\u{FDD0}",
            "CA\u{FFFF}",
            "CA\u{10FFFE}",
        ] {
            assert!(text_equivalent(bad, bad), "{bad:?}");
            assert!(!text_equivalent(bad, "CA"), "{bad:?}");
            assert!(!text_equivalent(bad, &bad.to_lowercase()), "{bad:?}");
        }
    }

    #[test]
    fn steps_that_need_unicode_tables_are_not_applied() {
        // NFKC would compose the accent and fold the fullwidth letters.
        assert!(!text_equivalent("Caf\u{00E9}", "Cafe\u{0301}"));
        assert!(!text_equivalent("\u{FF23}\u{FF21}", "CA"));
        // RFC 3454 B.2 would fold both to "ss".
        assert!(!text_equivalent("Stra\u{00DF}e", "STRASSE"));
    }
}
