//! X.690 §8.7 OCTET STRING, universal tag 4.
//!
//! The contents are the octets themselves, any number of them including
//! none. This type reads and writes the primitive form only; the
//! constructed form BER allows and CER requires over 1000 octets (§9.2) is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `24`.

use alloc::vec::Vec;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Arbitrary octets, the carrier of every opaque value from a key
/// identifier to a whole encoded structure inside an extension.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let value = Asn1OctetString::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
///
/// let (_, back) = Asn1OctetString::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.as_bytes(), [0xDE, 0xAD, 0xBE, 0xEF]);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Asn1OctetString {
    bytes: Vec<u8>,
}

impl Asn1OctetString {
    /// The identifier octets, [`tag::OCTET_STRING`](crate::tag::OCTET_STRING).
    pub const TAG: &'static [u8] = super::tag::OCTET_STRING;

    /// Copies the octets; [`From<Vec<u8>>`](#impl-From<Vec<u8>>-for-Asn1OctetString)
    /// takes them without copying.
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// The octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for Asn1OctetString {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl DecodeInner for Asn1OctetString {
    /// The primitive form only: the constructed tag `24` is
    /// `UnexpectedTag` here.
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

impl Decode for Asn1OctetString {}
impl Tagged for Asn1OctetString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1OctetString {
    /// Any contents are valid, including none; only the length limit
    /// applies.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Ok(Self::new(value))
    }
}

impl EncodeContent for Asn1OctetString {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.bytes.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.bytes.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

impl EncodeTagged for Asn1OctetString {
    /// Always primitive. Under CER a value over 1000 octets cannot be written by
    /// this type: `encode_tagged` returns [`Asn1Error::PrimitiveTooLong`], and the
    /// caller splits it into an [`Asn1Constructed`](crate::Asn1Constructed) instead.
    /// Variable time: branches only on the encoding structure.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(self.bytes.len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1OctetString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::Asn1OctetString;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_octets_round_trip_unchanged_including_none() {
        for (bytes, wire) in [
            (&[][..], &[0x04, 0x00][..]),
            (&[0x00], &[0x04, 0x01, 0x00]),
            (&[0x01, 0x02, 0x03], &[0x04, 0x03, 0x01, 0x02, 0x03]),
        ] {
            let value = Asn1OctetString::new(bytes);
            assert_eq!(value.encode_to_vec(&der()).unwrap(), wire);
            let (used, back) = Asn1OctetString::decode(wire, &options()).unwrap();
            assert_eq!((used, back.as_bytes()), (wire.len(), bytes));
            assert_eq!(
                Asn1OctetString::decode_der(wire, &options()).unwrap().1,
                value
            );
        }
    }

    #[test]
    fn a_long_value_gets_the_long_length_form() {
        let value = Asn1OctetString::from(vec![0xAB; 300]);
        let wire = value.encode_to_vec(&der()).unwrap();
        assert_eq!(wire[..4], [0x04, 0x82, 0x01, 0x2C]);
        assert_eq!(wire.len(), 304);
        let (used, back) = Asn1OctetString::decode(&wire, &options()).unwrap();
        assert_eq!((used, back), (304, value));
    }

    #[test]
    fn from_vec_keeps_the_buffer_and_new_copies_the_slice() {
        let bytes = vec![1, 2, 3];
        assert_eq!(
            Asn1OctetString::from(bytes.clone()),
            Asn1OctetString::new(&bytes)
        );
        assert_eq!(Asn1OctetString::default().as_bytes(), &[] as &[u8]);
    }

    #[test]
    fn cer_refuses_the_primitive_form_over_1000_octets() {
        let cer = EncodingOptions::CER;
        assert!(
            Asn1OctetString::from(vec![0; 1000])
                .encode_to_vec(&cer)
                .is_ok()
        );
        assert!(matches!(
            Asn1OctetString::from(vec![0; 1001]).encode_to_vec(&cer),
            Err(Asn1Error::PrimitiveTooLong)
        ));
        // the other rule sets do not care
        assert_eq!(
            Asn1OctetString::from(vec![0; 1001])
                .encode_to_vec(&der())
                .unwrap()
                .len(),
            1005
        );
    }

    #[test]
    fn the_constructed_form_and_other_tags_are_unexpected() {
        assert!(matches!(
            Asn1OctetString::decode(&[0x24, 0x02, 0x04, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Asn1OctetString::decode(&[0x03, 0x01, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn the_content_length_limit_applies_before_the_octets_are_copied() {
        let mut wire = Vec::from([0x04, 0x05]);
        wire.extend_from_slice(&[0; 5]);
        assert!(Asn1OctetString::decode(&wire, &DecodingOptions::new(8, 5, 8)).is_ok());
        assert!(matches!(
            Asn1OctetString::decode(&wire, &DecodingOptions::new(8, 4, 8)),
            Err(Asn1Error::ContentLengthExceeded)
        ));
    }

    #[test]
    fn a_short_output_buffer_is_reported_not_truncated() {
        let value = Asn1OctetString::new(&[1, 2, 3]);
        let mut out = [0u8; 4];
        assert!(matches!(
            value.encode(&der(), &mut out),
            Err(Asn1Error::BufferTooSmall)
        ));
        let mut out = [0u8; 5];
        assert_eq!(value.encode(&der(), &mut out).unwrap(), 5);
    }
}
