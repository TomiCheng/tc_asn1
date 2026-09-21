//! X.680 §41 `Ia5String`, universal tag 22.
//!
//! Every character of ISO 646 IA5 (X.680 §41.4), which is 7-bit ASCII
//! including the control characters: the type for e-mail addresses, DNS
//! names and URIs in certificates.
//!
//! One octet per character, so the contents are ASCII and the type is a
//! subset of [`Asn1Ia5String`](crate::Asn1Ia5String) in what it accepts.
//! Every rule set writes it the same way; the constructed form BER allows
//! and CER requires over 1000 octets is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `0x36`.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Text in 7-bit ASCII.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Ia5String, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let text = Asn1Ia5String::new("user@example.com")?;
/// let der = text.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der[..2], [0x16, 16]);
/// assert_eq!(&der[2..], "user@example.com".as_bytes());
/// let (_, back) = Asn1Ia5String::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.as_str(), "user@example.com");
///
/// // Anything above 0x7F is out; use UTF8String.
/// assert!(matches!(Asn1Ia5String::new("café"), Err(Asn1Error::MalformedValue)));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1Ia5String {
    text: String,
}

impl Asn1Ia5String {
    pub const TAG: &'static [u8] = super::tag::IA5_STRING;

    /// Rejects any non-ASCII character.
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text.is_ascii() {
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

impl core::fmt::Display for Asn1Ia5String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1Ia5String {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1Constructed with tag 0x36.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Ia5String {}
impl Tagged for Asn1Ia5String {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Ia5String {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if !value.is_ascii() {
            return Err(Asn1Error::MalformedValue);
        }
        // ASCII is a subset of UTF-8, so this cannot fail after the check above.
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self {
            text: String::from(text),
        })
    }
}

impl EncodeContent for Asn1Ia5String {
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

impl EncodeTagged for Asn1Ia5String {
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

impl Encode for Asn1Ia5String {
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

    use super::Asn1Ia5String;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn only_the_character_set_is_accepted_when_built_or_decoded() {
        for text in ["user@example.com", "http://a/b?c=d", "tab\tnl\n", ""] {
            assert!(Asn1Ia5String::new(text).is_ok(), "{text:?}");
        }
        for text in ["café", "台北", "😀"] {
            assert!(
                matches!(Asn1Ia5String::new(text), Err(Asn1Error::MalformedValue)),
                "{text:?}"
            );
            let mut wire = alloc::vec![0x16, text.len() as u8];
            wire.extend_from_slice(text.as_bytes());
            assert!(
                matches!(
                    Asn1Ia5String::decode(&wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_wire_form_is_one_octet_per_character() {
        let der = EncodingOptions::DER;
        let value = Asn1Ia5String::new("user@example.com").unwrap();
        let wire = value.encode_to_vec(&der).unwrap();
        assert_eq!(wire[..2], [0x16, 16]);
        assert_eq!(&wire[2..], "user@example.com".as_bytes());
        let (used, back) = Asn1Ia5String::decode(&wire, &options()).unwrap();
        assert_eq!((used, &back), (wire.len(), &value));
        assert_eq!(back.to_string(), "user@example.com");
        assert_eq!(
            Asn1Ia5String::decode_der(&wire, &options()).unwrap().1,
            value
        );
        assert_eq!(Asn1Ia5String::default().as_str(), "");
    }

    #[test]
    fn the_constructed_form_and_other_tags_are_unexpected_and_cer_limits_the_length() {
        assert!(matches!(
            Asn1Ia5String::decode(&[0x36, 0x02, 0x16, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Asn1Ia5String::decode(&[0x04, 0x01, 0x31], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        let long =
            Asn1Ia5String::new(&String::from_utf8(alloc::vec![b'1'; 1001]).unwrap()).unwrap();
        assert!(matches!(
            long.encode_to_vec(&EncodingOptions::CER),
            Err(Asn1Error::PrimitiveTooLong)
        ));
        assert!(long.encode_to_vec(&EncodingOptions::DER).is_ok());
    }
}
