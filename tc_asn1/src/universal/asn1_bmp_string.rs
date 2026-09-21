//! X.680 §41 `BMPString`, universal tag 30: UCS-2, two big-endian octets
//! per character.
//!
//! Only the Basic Multilingual Plane, `U+0000` to `U+FFFF`, can be
//! written; UCS-2 has no surrogate pairs, so a character beyond it is
//! rejected when building and a surrogate code unit when decoding. The
//! constructed form BER allows and CER requires over 1000 octets is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `0x3E`.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Text within the Basic Multilingual Plane, written as UCS-2.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1BmpString, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let text = Asn1BmpString::new("\u{53f0}\u{5317}")?;
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x1E, 0x04, 0x53, 0xF0, 0x53, 0x17]);
/// let (_, back) = Asn1BmpString::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.as_str(), "\u{53f0}\u{5317}");
///
/// // Outside the BMP there is no UCS-2 form.
/// assert!(matches!(Asn1BmpString::new("\u{1F600}"), Err(Asn1Error::MalformedValue)));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1BmpString {
    text: String,
}

impl Asn1BmpString {
    pub const TAG: &'static [u8] = super::tag::BMP_STRING;

    /// Rejects any character above `U+FFFF`.
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if text.chars().any(|ch| u32::from(ch) > 0xFFFF) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            text: String::from(text),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Two octets per character.
    fn wire_len(&self) -> usize {
        self.text.chars().count() * 2
    }
}

impl core::fmt::Display for Asn1BmpString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1BmpString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1Constructed with tag 0x3E.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1BmpString {}
impl Tagged for Asn1BmpString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1BmpString {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let (units, remainder) = value.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut text = String::with_capacity(units.len());
        for bytes in units {
            let unit = u16::from_be_bytes(*bytes);
            // from_u32 rejects D800-DFFF, which UCS-2 must not contain.
            let ch = char::from_u32(u32::from(unit)).ok_or(Asn1Error::MalformedValue)?;
            text.push(ch);
        }
        Ok(Self { text })
    }
}

impl EncodeContent for Asn1BmpString {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.wire_len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.wire_len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        for (slot, ch) in out.as_chunks_mut::<2>().0.iter_mut().zip(self.text.chars()) {
            // new and decode_content guarantee the code point fits in u16.
            *slot = (ch as u16).to_be_bytes();
        }
        Ok(out.len())
    }
}

impl EncodeTagged for Asn1BmpString {
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

impl Encode for Asn1BmpString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::Asn1BmpString;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn each_character_is_two_big_endian_octets() {
        let der = EncodingOptions::DER;
        for (text, wire) in [
            ("", &[0x1E, 0x00][..]),
            ("A", &[0x1E, 0x02, 0x00, 0x41]),
            ("\u{53f0}\u{5317}", &[0x1E, 0x04, 0x53, 0xF0, 0x53, 0x17]),
            ("\u{ffff}", &[0x1E, 0x02, 0xFF, 0xFF]),
        ] {
            let value = Asn1BmpString::new(text).unwrap();
            assert_eq!(value.encode_to_vec(&der).unwrap(), wire, "{text:?}");
            let (used, back) = Asn1BmpString::decode(wire, &options()).unwrap();
            assert_eq!((used, back.as_str()), (wire.len(), text));
            assert_eq!(back.to_string(), text);
        }
    }

    #[test]
    fn characters_beyond_the_bmp_surrogates_and_odd_lengths_are_rejected() {
        assert!(matches!(
            Asn1BmpString::new("\u{1F600}"),
            Err(Asn1Error::MalformedValue)
        ));
        for wire in [
            &[0x1E, 0x02, 0xD8, 0x00][..],         // a lone high surrogate
            &[0x1E, 0x04, 0xD8, 0x3D, 0xDE, 0x00], // a surrogate pair: UTF-16, not UCS-2
            &[0x1E, 0x01, 0x41],                   // half a code unit
        ] {
            assert!(
                matches!(
                    Asn1BmpString::decode(wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{wire:02X?}"
            );
        }
        assert!(matches!(
            Asn1BmpString::decode(&[0x3E, 0x02, 0x1E, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn cer_counts_wire_octets() {
        let cer = EncodingOptions::CER;
        assert!(
            Asn1BmpString::new(&"a".repeat(500))
                .unwrap()
                .encode_to_vec(&cer)
                .is_ok()
        );
        assert!(matches!(
            Asn1BmpString::new(&"a".repeat(501))
                .unwrap()
                .encode_to_vec(&cer),
            Err(Asn1Error::PrimitiveTooLong)
        ));
    }
}
