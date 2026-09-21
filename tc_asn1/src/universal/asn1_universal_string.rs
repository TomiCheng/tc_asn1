//! X.680 §41 `UniversalString`, universal tag 28: UCS-4, four big-endian
//! octets per character.
//!
//! Every Unicode scalar value fits, characters outside the BMP as a single
//! code point; a Rust string already excludes surrogates and values above
//! `U+10FFFF`, so building never fails and decoding checks each code
//! point. Rare in practice, UTF8String having taken its place. The
//! constructed form BER allows and CER requires over 1000 octets is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `0x3C`.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Any Unicode text, written as UCS-4.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1UniversalString, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let text = Asn1UniversalString::new("A\u{1F600}");
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x1C, 0x08, 0x00, 0x00, 0x00, 0x41, 0x00, 0x01, 0xF6, 0x00]);
/// let (_, back) = Asn1UniversalString::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.as_str(), "A\u{1F600}");
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1UniversalString {
    text: String,
}

impl Asn1UniversalString {
    pub const TAG: &'static [u8] = super::tag::UNIVERSAL_STRING;

    pub fn new(text: &str) -> Self {
        Self {
            text: String::from(text),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Four octets per character.
    fn wire_len(&self) -> usize {
        self.text.chars().count() * 4
    }
}

impl From<String> for Asn1UniversalString {
    fn from(text: String) -> Self {
        Self { text }
    }
}

impl core::fmt::Display for Asn1UniversalString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1UniversalString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1Constructed with tag 0x3C.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1UniversalString {}
impl Tagged for Asn1UniversalString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1UniversalString {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let units = value.chunks_exact(4);
        if !units.remainder().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut text = String::with_capacity(units.len());
        for bytes in units {
            let unit = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let ch = char::from_u32(unit).ok_or(Asn1Error::MalformedValue)?;
            text.push(ch);
        }
        Ok(Self { text })
    }
}

impl EncodeContent for Asn1UniversalString {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.wire_len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.wire_len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        for (slot, ch) in out.chunks_exact_mut(4).zip(self.text.chars()) {
            slot.copy_from_slice(&u32::from(ch).to_be_bytes());
        }
        Ok(out.len())
    }
}

impl EncodeTagged for Asn1UniversalString {
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(self.wire_len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1UniversalString {
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

    use super::Asn1UniversalString;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn each_character_is_four_big_endian_octets() {
        let der = EncodingOptions::DER;
        for (text, wire) in [
            ("", &[0x1C, 0x00][..]),
            ("A", &[0x1C, 0x04, 0x00, 0x00, 0x00, 0x41]),
            ("\u{53f0}", &[0x1C, 0x04, 0x00, 0x00, 0x53, 0xF0]),
            ("\u{1F600}", &[0x1C, 0x04, 0x00, 0x01, 0xF6, 0x00]),
        ] {
            let value = Asn1UniversalString::new(text);
            assert_eq!(value.encode_to_vec(&der).unwrap(), wire, "{text:?}");
            let (used, back) = Asn1UniversalString::decode(wire, &options()).unwrap();
            assert_eq!((used, back.as_str()), (wire.len(), text));
            assert_eq!(back.to_string(), text);
        }
        assert_eq!(
            Asn1UniversalString::from(String::from("x")),
            Asn1UniversalString::new("x")
        );
    }

    #[test]
    fn surrogates_values_past_unicode_and_partial_code_points_are_rejected() {
        for wire in [
            &[0x1C, 0x04, 0x00, 0x00, 0xD8, 0x00][..], // a surrogate
            &[0x1C, 0x04, 0x00, 0x11, 0x00, 0x00],     // U+110000
            &[0x1C, 0x03, 0x00, 0x00, 0x41],           // three octets
        ] {
            assert!(
                matches!(
                    Asn1UniversalString::decode(wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{wire:02X?}"
            );
        }
        assert!(matches!(
            Asn1UniversalString::decode(&[0x3C, 0x02, 0x1C, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn cer_counts_wire_octets() {
        let cer = EncodingOptions::CER;
        assert!(
            Asn1UniversalString::new(&"a".repeat(250))
                .encode_to_vec(&cer)
                .is_ok()
        );
        assert!(matches!(
            Asn1UniversalString::new(&"a".repeat(251)).encode_to_vec(&cer),
            Err(Asn1Error::PrimitiveTooLong)
        ));
    }
}
