//! X.680 §41 `UTF8String`, universal tag 12.
//!
//! The UTF-8 octets of any Unicode text, the general-purpose string type
//! of every modern profile: RFC 5280 requires it for a DirectoryString
//! whose text is not printable. A Rust `str` is already valid UTF-8, so
//! building never fails; decoding rejects invalid UTF-8. The constructed
//! form BER allows and CER requires over 1000 octets is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `0x2C`.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Any Unicode text, written as UTF-8.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Utf8String, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let text = Asn1Utf8String::new("caf\u{e9}");
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x0C, 0x05, b'c', b'a', b'f', 0xC3, 0xA9]);
/// let (_, back) = Asn1Utf8String::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.as_str(), "caf\u{e9}");
///
/// // Octets that are not UTF-8 are rejected.
/// assert!(matches!(
///     Asn1Utf8String::decode(&[0x0C, 0x01, 0xFF], &DecodingOptions::default()),
///     Err(Asn1Error::MalformedValue)
/// ));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1Utf8String {
    text: String,
}

impl Asn1Utf8String {
    /// The identifier octets, [`tag::UTF8_STRING`](crate::tag::UTF8_STRING).
    pub const TAG: &'static [u8] = super::tag::UTF8_STRING;

    /// Copies the text.
    pub fn new(text: &str) -> Self {
        Self {
            text: String::from(text),
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl From<String> for Asn1Utf8String {
    fn from(text: String) -> Self {
        Self { text }
    }
}

impl core::fmt::Display for Asn1Utf8String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1Utf8String {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1Constructed with tag 0x2C.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Utf8String {}
impl Tagged for Asn1Utf8String {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Utf8String {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self::new(text))
    }
}

impl EncodeContent for Asn1Utf8String {
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

impl EncodeTagged for Asn1Utf8String {
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

impl Encode for Asn1Utf8String {
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

    use super::Asn1Utf8String;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_wire_form_is_the_utf8_octets() {
        let der = EncodingOptions::DER;
        for (text, wire) in [
            ("", &[0x0C, 0x00][..]),
            ("abc", &[0x0C, 0x03, b'a', b'b', b'c']),
            ("\u{53f0}", &[0x0C, 0x03, 0xE5, 0x8F, 0xB0]),
            ("\u{1F600}", &[0x0C, 0x04, 0xF0, 0x9F, 0x98, 0x80]),
        ] {
            let value = Asn1Utf8String::new(text);
            assert_eq!(value.encode_to_vec(&der).unwrap(), wire, "{text:?}");
            let (used, back) = Asn1Utf8String::decode(wire, &options()).unwrap();
            assert_eq!((used, back.as_str()), (wire.len(), text));
            assert_eq!(back.to_string(), text);
        }
        assert_eq!(
            Asn1Utf8String::from(String::from("x")),
            Asn1Utf8String::new("x")
        );
    }

    #[test]
    fn invalid_utf8_the_constructed_form_and_other_tags_are_rejected() {
        for wire in [
            &[0x0C, 0x01, 0xFF][..],
            &[0x0C, 0x02, 0xC3, 0x28],
            &[0x0C, 0x01, 0x80],
        ] {
            assert!(matches!(
                Asn1Utf8String::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            Asn1Utf8String::decode(&[0x2C, 0x02, 0x0C, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Asn1Utf8String::decode(&[0x13, 0x01, b'a'], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn cer_counts_octets_not_characters() {
        let cer = EncodingOptions::CER;
        let just_fits = Asn1Utf8String::new(&"\u{53f0}".repeat(333)); // 999 octets
        assert!(just_fits.encode_to_vec(&cer).is_ok());
        let too_long = Asn1Utf8String::new(&"\u{53f0}".repeat(334)); // 1002 octets
        assert!(matches!(
            too_long.encode_to_vec(&cer),
            Err(Asn1Error::PrimitiveTooLong)
        ));
    }
}
