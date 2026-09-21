//! X.680 §41 `NumericString`, universal tag 18.
//!
//! Digits and space only (X.680 §41.4); no sign, no point.
//!
//! One octet per character, so the contents are ASCII and the type is a
//! subset of [`Asn1Ia5String`](crate::Asn1Ia5String) in what it accepts.
//! Every rule set writes it the same way; the constructed form BER allows
//! and CER requires over 1000 octets is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `0x32`.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// X.680 §41.4: ASCII digits `0`-`9` and space. Signs are not part of the set.
fn is_numeric(byte: u8) -> bool {
    byte.is_ascii_digit() || byte == b' '
}

/// Digits and spaces.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1NumericString, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let text = Asn1NumericString::new("12 34")?;
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der[..2], [0x12, 5]);
/// assert_eq!(&der[2..], "12 34".as_bytes());
/// let (_, back) = Asn1NumericString::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.as_str(), "12 34");
///
/// // A sign is not a digit.
/// assert!(matches!(Asn1NumericString::new("-1"), Err(Asn1Error::MalformedValue)));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1NumericString {
    text: String,
}

impl Asn1NumericString {
    pub const TAG: &'static [u8] = super::tag::NUMERIC_STRING;

    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text.bytes().all(is_numeric) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            text: String::from(text),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl core::fmt::Display for Asn1NumericString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1NumericString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1Constructed with tag 0x32.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1NumericString {}
impl Tagged for Asn1NumericString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1NumericString {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if !value.iter().all(|b| is_numeric(*b)) {
            return Err(Asn1Error::MalformedValue);
        }
        // The character set is a subset of ASCII, hence valid UTF-8.
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self {
            text: String::from(text),
        })
    }
}

impl EncodeContent for Asn1NumericString {
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

impl EncodeTagged for Asn1NumericString {
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

impl Encode for Asn1NumericString {
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

    use super::Asn1NumericString;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn only_the_character_set_is_accepted_when_built_or_decoded() {
        for text in ["0123456789", "12 34", ""] {
            assert!(Asn1NumericString::new(text).is_ok(), "{text:?}");
        }
        for text in ["-1", "1.5", "a"] {
            assert!(
                matches!(Asn1NumericString::new(text), Err(Asn1Error::MalformedValue)),
                "{text:?}"
            );
            let mut wire = alloc::vec![0x12, text.len() as u8];
            wire.extend_from_slice(text.as_bytes());
            assert!(
                matches!(
                    Asn1NumericString::decode(&wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_wire_form_is_one_octet_per_character() {
        let der = EncodingOptions::DER;
        let value = Asn1NumericString::new("0123456789").unwrap();
        let wire = value.encode_to_vec(&der).unwrap();
        assert_eq!(wire[..2], [0x12, 10]);
        assert_eq!(&wire[2..], "0123456789".as_bytes());
        let (used, back) = Asn1NumericString::decode(&wire, &options()).unwrap();
        assert_eq!((used, &back), (wire.len(), &value));
        assert_eq!(back.to_string(), "0123456789");
        assert_eq!(
            Asn1NumericString::decode_der(&wire, &options()).unwrap().1,
            value
        );
        assert_eq!(Asn1NumericString::default().as_str(), "");
    }

    #[test]
    fn the_constructed_form_and_other_tags_are_unexpected_and_cer_limits_the_length() {
        assert!(matches!(
            Asn1NumericString::decode(&[0x32, 0x02, 0x12, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Asn1NumericString::decode(&[0x04, 0x01, 0x31], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        let long =
            Asn1NumericString::new(&String::from_utf8(alloc::vec![b'1'; 1001]).unwrap()).unwrap();
        assert!(matches!(
            long.encode_to_vec(&EncodingOptions::CER),
            Err(Asn1Error::PrimitiveTooLong)
        ));
        assert!(long.encode_to_vec(&EncodingOptions::DER).is_ok());
    }
}
