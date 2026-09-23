//! X.520 `DirectoryString`, as profiled by RFC 5280 §4.1.2.4.
//!
//! ```text
//! DirectoryString ::= CHOICE {
//!     teletexString     TeletexString   (SIZE (1..MAX)),
//!     printableString   PrintableString (SIZE (1..MAX)),
//!     universalString   UniversalString (SIZE (1..MAX)),
//!     utf8String        UTF8String      (SIZE (1..MAX)),
//!     bmpString         BMPString       (SIZE (1..MAX))
//! }
//! ```
//!
//! New certificates MUST use PrintableString or UTF8String; the other three
//! alternatives exist to read older ones. The `SIZE (1..MAX)` constraint is
//! kept when building a value but not when decoding one, since some
//! certificates carry empty values. TeletexString is kept as raw
//! octets because its character set (T.61 with escape sequences) is not
//! reliably decodable, and in practice such fields often hold Latin-1 anyway.

use core::fmt;

use tc_asn1::{
    Asn1Any, Asn1BmpString, Asn1Error, Asn1PrintableString, Asn1Ref, Asn1UniversalString,
    Asn1Utf8String, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, tag,
};

use crate::string_prep::text_equivalent;

/// The string CHOICE used for most `Name` attribute values. Never empty
/// when built with [`new`](Self::new); may be empty when decoded.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DirectoryString {
    PrintableString(Asn1PrintableString),
    Utf8String(Asn1Utf8String),
    /// Raw contents under tag 20; the character set is not interpreted.
    TeletexString(Asn1Any),
    BmpString(Asn1BmpString),
    UniversalString(Asn1UniversalString),
}

impl DirectoryString {
    /// PrintableString when every character is in its set, UTF8String
    /// otherwise, as RFC 5280 §4.1.2.4 prefers. An empty string violates the
    /// `SIZE (1..MAX)` constraint and is `MalformedValue`.
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if text.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(match Asn1PrintableString::new(text) {
            Ok(printable) => Self::PrintableString(printable),
            Err(_) => Self::Utf8String(Asn1Utf8String::new(text)),
        })
    }

    /// The text, or `None` for a TeletexString.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::PrintableString(s) => Some(s.as_str()),
            Self::Utf8String(s) => Some(s.as_str()),
            Self::TeletexString(_) => None,
            Self::BmpString(s) => Some(s.as_str()),
            Self::UniversalString(s) => Some(s.as_str()),
        }
    }

    /// Compares text regardless of string type after the RFC 4518 string
    /// preparation that RFC 5280 §7.1 asks for: case is ignored, invisible
    /// characters are dropped, and runs of whitespace count as one space,
    /// none at either end. NFKC normalization and full Unicode case folding
    /// are not applied, so a precomposed and a decomposed accent differ.
    /// Text with a code point the preparation prohibits (private use,
    /// noncharacters, U+FFFD) matches only identical text. TeletexStrings
    /// are compared as octets and never match another alternative.
    /// Variable time; for public values.
    pub fn equivalent(&self, other: &Self) -> bool {
        match (self.as_str(), other.as_str()) {
            (Some(a), Some(b)) => text_equivalent(a, b),
            _ => self == other,
        }
    }
}

/// The text, or the TeletexString octets as `\xNN` escapes.
impl fmt::Display for DirectoryString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(text) => f.write_str(text),
            None => {
                let Self::TeletexString(any) = self else {
                    unreachable!("as_str is None only for TeletexString");
                };
                for byte in any.as_ref().value() {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        write!(f, "{}", *byte as char)?;
                    } else {
                        write!(f, "\\x{byte:02x}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl DecodeInner for DirectoryString {
    /// The identifier selects the alternative. An empty value is accepted,
    /// though X.520 forbids it: some certificates carry one, and refusing it
    /// would make the whole certificate unreadable. [`new`](Self::new) still
    /// refuses one. Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let tag = element.tag();
        let (used, value) = if tag == Asn1PrintableString::TAG {
            let (n, s) = Asn1PrintableString::decode_inner(buff, context)?;
            (n, Self::PrintableString(s))
        } else if tag == Asn1Utf8String::TAG {
            let (n, s) = Asn1Utf8String::decode_inner(buff, context)?;
            (n, Self::Utf8String(s))
        } else if tag == tag::TELETEX_STRING {
            (
                element.total_len(),
                Self::TeletexString(Asn1Any::from(&element)),
            )
        } else if tag == Asn1BmpString::TAG {
            let (n, s) = Asn1BmpString::decode_inner(buff, context)?;
            (n, Self::BmpString(s))
        } else if tag == Asn1UniversalString::TAG {
            let (n, s) = Asn1UniversalString::decode_inner(buff, context)?;
            (n, Self::UniversalString(s))
        } else {
            return Err(Asn1Error::UnexpectedTag);
        };
        Ok((used, value))
    }
}

impl Decode for DirectoryString {}

impl EncodeContent for DirectoryString {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::PrintableString(s) => s.content_len(rules),
            Self::Utf8String(s) => s.content_len(rules),
            Self::TeletexString(s) => s.content_len(rules),
            Self::BmpString(s) => s.content_len(rules),
            Self::UniversalString(s) => s.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::PrintableString(s) => s.encode_content(rules, out),
            Self::Utf8String(s) => s.encode_content(rules, out),
            Self::TeletexString(s) => s.encode_content(rules, out),
            Self::BmpString(s) => s.encode_content(rules, out),
            Self::UniversalString(s) => s.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for DirectoryString {}

/// Each alternative writes its own identifier.
impl Encode for DirectoryString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::PrintableString(s) => s.encoded_len(rules),
            Self::Utf8String(s) => s.encoded_len(rules),
            Self::TeletexString(s) => s.encoded_len(rules),
            Self::BmpString(s) => s.encoded_len(rules),
            Self::UniversalString(s) => s.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::PrintableString(s) => s.encode(rules, out),
            Self::Utf8String(s) => s.encode(rules, out),
            Self::TeletexString(s) => s.encode(rules, out),
            Self::BmpString(s) => s.encode(rules, out),
            Self::UniversalString(s) => s.encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::DirectoryString;

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn new_prefers_printable_string_and_falls_back_to_utf8string() {
        let s = DirectoryString::new("Example Inc").unwrap();
        assert!(matches!(s, DirectoryString::PrintableString(_)));
        assert_eq!(s.encode_to_vec(&der()).unwrap(), b"\x13\x0bExample Inc");
        let s = DirectoryString::new("\u{53F0}\u{5317}").unwrap();
        assert!(matches!(s, DirectoryString::Utf8String(_)));
        assert_eq!(
            s.encode_to_vec(&der()).unwrap(),
            b"\x0c\x06\xe5\x8f\xb0\xe5\x8c\x97"
        );
        assert!(matches!(
            DirectoryString::new(""),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn every_alternative_decodes_by_tag_and_round_trips() {
        let cases: [(&[u8], Option<&str>); 5] = [
            (b"\x13\x02TW", Some("TW")),
            (b"\x0c\x02TW", Some("TW")),
            (b"\x14\x02TW", None),
            (b"\x1e\x04\x00T\x00W", Some("TW")),
            (b"\x1c\x08\x00\x00\x00T\x00\x00\x00W", Some("TW")),
        ];
        for (bytes, text) in cases {
            let (used, s) = DirectoryString::decode(bytes, &options()).unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(s.as_str(), text);
            assert_eq!(s.encode_to_vec(&der()).unwrap(), bytes);
        }
    }

    #[test]
    fn equivalence_ignores_the_string_type_case_and_extra_whitespace() {
        let printable = |s| DirectoryString::decode(s, &options()).unwrap().1;
        let a = printable(b"\x13\x07Root CA");
        let b = printable(b"\x0c\x0a  root  CA ");
        let c = printable(b"\x1e\x0e\x00R\x00o\x00o\x00t\x00 \x00C\x00A");
        assert_ne!(a, b);
        assert!(a.equivalent(&b));
        assert!(a.equivalent(&c));
        assert!(!a.equivalent(&printable(b"\x13\x06RootCA")));
        // Teletex compares as octets only
        let teletex = printable(b"\x14\x07Root CA");
        assert!(teletex.equivalent(&printable(b"\x14\x07Root CA")));
        assert!(!teletex.equivalent(&a));
        assert!(!teletex.equivalent(&printable(b"\x14\x07root ca")));
    }

    #[test]
    fn a_teletex_string_displays_its_octets() {
        let (_, s) = DirectoryString::decode(b"\x14\x03T\xe9W", &options()).unwrap();
        assert_eq!(s.to_string(), "T\\xe9W");
        assert_eq!(DirectoryString::new("TW").unwrap().to_string(), "TW");
    }

    #[test]
    fn other_string_types_are_rejected() {
        assert!(matches!(
            DirectoryString::decode(b"\x16\x02TW", &options()), // IA5String is not in the CHOICE
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn empty_values_are_decoded_but_never_built() {
        for bytes in [
            &b"\x13\x00"[..],
            b"\x0c\x00",
            b"\x14\x00",
            b"\x1e\x00",
            b"\x1c\x00",
        ] {
            let (_, s) = DirectoryString::decode(bytes, &options()).unwrap();
            assert!(s.as_str().is_none_or(str::is_empty), "{bytes:02x?}");
            assert_eq!(s.encode_to_vec(&der()).unwrap(), bytes);
        }
        assert!(matches!(
            DirectoryString::new(""),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
