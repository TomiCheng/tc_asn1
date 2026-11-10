//! Text displayed in certificate policy notices.
//!
//! DisplayText is a CHOICE of IA5String, VisibleString, BMPString and UTF8String.
//! The ASN.1 size constraint is 1..200 characters. Empty text is rejected by
//! construction through `new`, decoding and encoding; the 200-character upper
//! bound is left to the certificate profile validator.
//!
//! ```text
//! DisplayText ::= CHOICE {
//!     ia5String     IA5String     (SIZE (1..200)),
//!     visibleString VisibleString (SIZE (1..200)),
//!     bmpString     BMPString     (SIZE (1..200)),
//!     utf8String    UTF8String    (SIZE (1..200)) }
//! ```

use core::fmt;

use tc_asn1::{
    Asn1BmpString, Asn1Error, Asn1Ia5String, Asn1Ref, Asn1Utf8String, Asn1VisibleString, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions,
};

/// Human-readable text in a certificate policy notice.
///
/// `new` selects UTF8String. The `From` conversions preserve the supplied
/// string alternative; an empty converted value is rejected when encoded.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::DisplayText;
///
/// let text = DisplayText::new("Policy notice")?;
/// assert_eq!(text.as_str(), "Policy notice");
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(DisplayText::decode_der(&der, &DecodingOptions::default())?.1, text);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum DisplayText {
    /// ASCII text encoded as IA5String.
    Ia5String(Asn1Ia5String),
    /// Printable ASCII text encoded as VisibleString.
    VisibleString(Asn1VisibleString),
    /// Basic Multilingual Plane text encoded as BMPString.
    BmpString(Asn1BmpString),
    /// Unicode text encoded as UTF8String; the default for new values.
    Utf8String(Asn1Utf8String),
}

impl DisplayText {
    /// Creates UTF8String text. Empty text returns `MalformedValue`.
    /// Text longer than 200 characters is accepted.
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if text.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self::Utf8String(Asn1Utf8String::new(text)))
    }

    /// Returns the text regardless of its ASN.1 string alternative.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ia5String(s) => s.as_str(),
            Self::VisibleString(s) => s.as_str(),
            Self::BmpString(s) => s.as_str(),
            Self::Utf8String(s) => s.as_str(),
        }
    }
}

impl From<Asn1Ia5String> for DisplayText {
    fn from(value: Asn1Ia5String) -> Self {
        Self::Ia5String(value)
    }
}

impl From<Asn1VisibleString> for DisplayText {
    fn from(value: Asn1VisibleString) -> Self {
        Self::VisibleString(value)
    }
}

impl From<Asn1BmpString> for DisplayText {
    fn from(value: Asn1BmpString) -> Self {
        Self::BmpString(value)
    }
}

impl From<Asn1Utf8String> for DisplayText {
    fn from(value: Asn1Utf8String) -> Self {
        Self::Utf8String(value)
    }
}

impl fmt::Display for DisplayText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DecodeInner for DisplayText {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let text = match element.tag() {
            t if t == Asn1Ia5String::TAG => {
                Self::Ia5String(Asn1Ia5String::decode_content(element.value(), context)?)
            }
            t if t == Asn1VisibleString::TAG => {
                Self::VisibleString(Asn1VisibleString::decode_content(element.value(), context)?)
            }
            t if t == Asn1BmpString::TAG => {
                Self::BmpString(Asn1BmpString::decode_content(element.value(), context)?)
            }
            t if t == Asn1Utf8String::TAG => {
                Self::Utf8String(Asn1Utf8String::decode_content(element.value(), context)?)
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        if text.as_str().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((element.total_len(), text))
    }
}

impl Decode for DisplayText {}

impl EncodeContent for DisplayText {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Ia5String(s) => s.content_len(rules),
            Self::VisibleString(s) => s.content_len(rules),
            Self::BmpString(s) => s.content_len(rules),
            Self::Utf8String(s) => s.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        if self.as_str().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        match self {
            Self::Ia5String(s) => s.encode_content(rules, out),
            Self::VisibleString(s) => s.encode_content(rules, out),
            Self::BmpString(s) => s.encode_content(rules, out),
            Self::Utf8String(s) => s.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for DisplayText {}

impl Encode for DisplayText {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Ia5String(s) => s.encoded_len(rules),
            Self::VisibleString(s) => s.encoded_len(rules),
            Self::BmpString(s) => s.encoded_len(rules),
            Self::Utf8String(s) => s.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        if self.as_str().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        match self {
            Self::Ia5String(s) => s.encode(rules, out),
            Self::VisibleString(s) => s.encode(rules, out),
            Self::BmpString(s) => s.encode(rules, out),
            Self::Utf8String(s) => s.encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{
        Asn1BmpString, Asn1Error, Asn1Ia5String, Asn1Utf8String, Asn1VisibleString, Decode,
        DecodingOptions, Encode, EncodingOptions,
    };

    use super::DisplayText;

    #[test]
    fn all_four_alternatives_preserve_their_tags_and_text() {
        for (text, wire) in [
            (
                DisplayText::from(Asn1Ia5String::new("A").unwrap()),
                &b"\x16\x01A"[..],
            ),
            (
                DisplayText::from(Asn1VisibleString::new("A").unwrap()),
                &b"\x1a\x01A"[..],
            ),
            (
                DisplayText::from(Asn1BmpString::new("A").unwrap()),
                &b"\x1e\x02\x00A"[..],
            ),
            (
                DisplayText::from(Asn1Utf8String::new("A")),
                &b"\x0c\x01A"[..],
            ),
        ] {
            assert_eq!(text.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(text.as_str(), "A");
            assert_eq!(text.to_string(), "A");
            assert_eq!(
                DisplayText::decode_der(wire, &DecodingOptions::default()).unwrap(),
                (wire.len(), text)
            );
        }
    }

    #[test]
    fn new_uses_utf8_and_long_text_is_preserved() {
        for value in ["Hello".to_string(), "界".repeat(201)] {
            let text = DisplayText::new(&value).unwrap();
            assert!(matches!(text, DisplayText::Utf8String(_)));
            let wire = text.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                DisplayText::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1
                    .as_str(),
                value
            );
        }
    }

    #[test]
    fn empty_text_is_rejected_by_new_decode_and_encode() {
        assert!(matches!(
            DisplayText::new(""),
            Err(Asn1Error::MalformedValue)
        ));
        for tag in [0x16, 0x1a, 0x1e, 0x0c] {
            assert!(matches!(
                DisplayText::decode(&[tag, 0], &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            ));
        }
        for text in [
            DisplayText::from(Asn1Ia5String::new("").unwrap()),
            DisplayText::from(Asn1VisibleString::new("").unwrap()),
            DisplayText::from(Asn1BmpString::new("").unwrap()),
            DisplayText::from(Asn1Utf8String::new("")),
        ] {
            assert!(matches!(
                text.encode_to_vec(&EncodingOptions::DER),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn unsupported_tags_and_invalid_character_encodings_are_rejected() {
        for tag in [0x13, 0x14, 0x1c] {
            assert!(matches!(
                DisplayText::decode(&[tag, 0], &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            ));
        }
        for wire in [
            &b"\x16\x01\xff"[..],
            b"\x1a\x01\x00",
            b"\x1e\x01A",
            b"\x0c\x01\xff",
        ] {
            assert!(DisplayText::decode(wire, &DecodingOptions::default()).is_err());
        }
    }
}
