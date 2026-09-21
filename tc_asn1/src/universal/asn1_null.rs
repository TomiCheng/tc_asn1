//! X.690 §8.8 NULL, universal tag 5.
//!
//! No contents octets: the whole encoding is `05 00`. It marks a value that
//! is present but carries nothing, most often the parameters of an
//! AlgorithmIdentifier.

use core::fmt::{Display, Formatter};

use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodingOptions, Tagged,
};

/// The one NULL value.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Null, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let der = Asn1Null.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x05, 0x00]);
/// let (used, _) = Asn1Null::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(used, 2);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Asn1Null;

impl Asn1Null {
    pub const TAG: &'static [u8] = super::tag::NULL;
}

/// `NULL`.
impl Display for Asn1Null {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("NULL")
    }
}

impl DecodeInner for Asn1Null {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}
impl Decode for Asn1Null {}
impl Tagged for Asn1Null {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Null {
    /// Any contents octet is `MalformedValue`.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if value.is_empty() {
            Ok(Asn1Null)
        } else {
            Err(Asn1Error::MalformedValue)
        }
    }
}

impl crate::EncodeContent for Asn1Null {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        0
    }

    fn encode_content(&self, _: &EncodingOptions, _: &mut [u8]) -> Result<usize, Asn1Error> {
        Ok(0)
    }
}

impl crate::EncodeTagged for Asn1Null {}

impl Encode for Asn1Null {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::Asn1Null;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn null_is_the_two_octets_05_00() {
        let der = EncodingOptions::DER;
        assert_eq!(Asn1Null.encoded_len(&der), 2);
        assert_eq!(Asn1Null.encode_to_vec(&der).unwrap(), [0x05, 0x00]);
        let (used, value) = Asn1Null::decode(&[0x05, 0x00, 0xAA], &options()).unwrap();
        assert_eq!((used, value), (2, Asn1Null));
        assert!(Asn1Null::decode_der(&[0x05, 0x00], &options()).is_ok());
    }

    #[test]
    fn contents_octets_are_malformed_and_another_tag_is_unexpected() {
        assert!(matches!(
            Asn1Null::decode(&[0x05, 0x01, 0x00], &options()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            Asn1Null::decode(&[0x04, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn it_is_the_default_and_displays_as_null() {
        assert_eq!(<Asn1Null as Default>::default(), Asn1Null);
        assert_eq!(Asn1Null.to_string(), "NULL");
    }
}
