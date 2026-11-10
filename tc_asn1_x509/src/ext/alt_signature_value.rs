//! ITU-T X.509 (2019) `AltSignatureValue` alternative-signature extension value.
//!
//! ```text
//! AltSignatureValue ::= BIT STRING
//! ```
//!
//! This is a typed wrapper with the same encoding as `Asn1BitString`.
//! Algorithm suitability, bit lengths, extension combinations and the signed
//! data are the responsibility of the validator or signing layer.

use tc_asn1::{
    Asn1BitString, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// The alternative signature bits, distinct from the primary signature.
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::AltSignatureValue;
///
/// let value = AltSignatureValue::new(Asn1BitString::from_bytes(&[0xaa]));
/// assert_eq!(value.signature_value().as_bytes(), &[0xaa]);
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(AltSignatureValue::decode_der(&der, &DecodingOptions::default())?.1, value);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AltSignatureValue(Asn1BitString);

impl AltSignatureValue {
    /// Wraps signature bits without interpreting the signing algorithm's format.
    pub fn new(signature_value: Asn1BitString) -> Self {
        Self(signature_value)
    }

    /// Returns the alternative signature bits, including their unused-bit count.
    pub fn signature_value(&self) -> &Asn1BitString {
        &self.0
    }
}

impl From<Asn1BitString> for AltSignatureValue {
    fn from(value: Asn1BitString) -> Self {
        Self(value)
    }
}

impl DecodeInner for AltSignatureValue {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, value) = Asn1BitString::decode_inner(buff, context)?;
        Ok((used, Self(value)))
    }
}

impl Decode for AltSignatureValue {}

impl Tagged for AltSignatureValue {
    const TAG: &'static [u8] = Asn1BitString::TAG;
}

impl EncodeContent for AltSignatureValue {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.0.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.0.encode_content(rules, out)
    }
}

impl EncodeTagged for AltSignatureValue {}

impl Encode for AltSignatureValue {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.0.encoded_len(rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.0.encode(rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{
        Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodeContent, EncodingOptions,
    };

    use super::AltSignatureValue;

    #[test]
    fn alt_signature_value_preserves_the_underlying_value_and_der_encoding() {
        let inner = Asn1BitString::from_bytes(&[0xaa]);
        let value = AltSignatureValue::from(inner.clone());
        let wire = b"\x03\x02\x00\xaa";
        assert_eq!(value.signature_value(), &inner);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            AltSignatureValue::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn alt_signature_value_delegates_lengths_and_content_encoding_without_an_extra_wrapper() {
        let inner = Asn1BitString::from_bytes(&[0xaa]);
        let value = AltSignatureValue::from(inner.clone());
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            assert_eq!(value.encoded_len(&rules), inner.encoded_len(&rules));
            assert_eq!(
                value.encode_to_vec(&rules).unwrap(),
                inner.encode_to_vec(&rules).unwrap()
            );
            assert_eq!(value.content_len(&rules), inner.content_len(&rules));
            let mut actual = [0u8; 128];
            let mut expected = [0u8; 128];
            let used = value.encode_content(&rules, &mut actual).unwrap();
            let expected_used = inner.encode_content(&rules, &mut expected).unwrap();
            assert_eq!(used, expected_used);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn alternative_signature_bits_need_not_be_byte_aligned_or_nonempty() {
        for wire in [&b"\x03\x02\x03\xa0"[..], &b"\x03\x01\x00"[..]] {
            let inner = Asn1BitString::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1;
            let value = AltSignatureValue::new(inner.clone());
            assert_eq!(value.signature_value(), &inner);
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                AltSignatureValue::decode_der(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn alt_signature_value_rejects_a_null_in_place_of_its_underlying_tag() {
        assert_eq!(
            AltSignatureValue::decode_der(b"\x05\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
