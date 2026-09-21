//! X.680 §41 `VisibleString`, universal tag 26.
//!
//! The printable characters of ISO 646, `0x20` to `0x7E` (X.680 §41.4):
//! IA5String without the control characters.
//!
//! One octet per character, so the contents are ASCII and the type is a
//! subset of [`Asn1Ia5String`](crate::Asn1Ia5String) in what it accepts.
//! Every rule set writes it the same way; the constructed form BER allows
//! and CER requires over 1000 octets is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `0x3A`.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// ISO 646 printable characters `0x20`-`0x7E`; no control characters.
fn is_visible(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte)
}

/// Printable ASCII, space included.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1VisibleString, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let text = Asn1VisibleString::new("Hello, World!")?;
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der[..2], [0x1A, 13]);
/// assert_eq!(&der[2..], "Hello, World!".as_bytes());
/// let (_, back) = Asn1VisibleString::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.as_str(), "Hello, World!");
///
/// // A control character is not visible.
/// assert!(matches!(Asn1VisibleString::new("line\n"), Err(Asn1Error::MalformedValue)));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1VisibleString {
    text: String,
}

impl Asn1VisibleString {
    /// The identifier octets, [`tag::VISIBLE_STRING`](crate::tag::VISIBLE_STRING).
    pub const TAG: &'static [u8] = super::tag::VISIBLE_STRING;

    /// Rejects any character outside `0x20`-`0x7E`.
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text.bytes().all(is_visible) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            text: String::from(text),
        })
    }

    /// The text, `0x20`-`0x7E` only.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl core::fmt::Display for Asn1VisibleString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1VisibleString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1Constructed with tag 0x3A.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1VisibleString {}
impl Tagged for Asn1VisibleString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1VisibleString {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if !value.iter().all(|b| is_visible(*b)) {
            return Err(Asn1Error::MalformedValue);
        }
        // The character set is a subset of ASCII, hence valid UTF-8.
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self {
            text: String::from(text),
        })
    }
}

impl EncodeContent for Asn1VisibleString {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.text.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.text.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(self.text.as_bytes());
        Ok(self.text.len())
    }
}

impl EncodeTagged for Asn1VisibleString {
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(self.text.len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1VisibleString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};

    use super::Asn1VisibleString;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn only_the_character_set_is_accepted_when_built_or_decoded() {
        for text in ["Hello, World!", "~", " ", ""] {
            assert!(Asn1VisibleString::new(text).is_ok(), "{text:?}");
        }
        for text in ["tab\t", "nl\n", "\u{7f}", "café"] {
            assert!(
                matches!(Asn1VisibleString::new(text), Err(Asn1Error::MalformedValue)),
                "{text:?}"
            );
            let mut wire = alloc::vec![0x1A, text.len() as u8];
            wire.extend_from_slice(text.as_bytes());
            assert!(
                matches!(
                    Asn1VisibleString::decode(&wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_wire_form_is_one_octet_per_character() {
        let der = EncodingOptions::DER;
        let value = Asn1VisibleString::new("Hello, World!").unwrap();
        let wire = value.encode_to_vec(&der).unwrap();
        assert_eq!(wire[..2], [0x1A, 13]);
        assert_eq!(&wire[2..], "Hello, World!".as_bytes());
        let (used, back) = Asn1VisibleString::decode(&wire, &options()).unwrap();
        assert_eq!((used, &back), (wire.len(), &value));
        assert_eq!(back.to_string(), "Hello, World!");
        assert_eq!(
            Asn1VisibleString::decode_der(&wire, &options()).unwrap().1,
            value
        );
        assert_eq!(Asn1VisibleString::default().as_str(), "");
    }

    #[test]
    fn the_constructed_form_and_other_tags_are_unexpected_and_cer_limits_the_length() {
        assert!(matches!(
            Asn1VisibleString::decode(&[0x3A, 0x02, 0x1A, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Asn1VisibleString::decode(&[0x04, 0x01, 0x31], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        let long =
            Asn1VisibleString::new(&String::from_utf8(alloc::vec![b'1'; 1001]).unwrap()).unwrap();
        assert!(matches!(
            long.encode_to_vec(&EncodingOptions::CER),
            Err(Asn1Error::PrimitiveTooLong)
        ));
        assert!(long.encode_to_vec(&EncodingOptions::DER).is_ok());
    }
}
