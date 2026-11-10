//! ITU-T X.509 (2019) `SubjectAltPublicKeyInfo` alternative-signature extension value.
//!
//! ```text
//! SubjectAltPublicKeyInfo ::= SEQUENCE {
//!     algorithm           AlgorithmIdentifier,
//!     subjectAltPublicKey BIT STRING }
//! ```
//!
//! This is a typed wrapper with the same encoding as `SubjectPublicKeyInfo`.
//! Algorithm suitability, bit lengths, extension combinations and the signed
//! data are the responsibility of the validator or signing layer.

use tc_asn1::{
    Asn1BitString, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

use crate::{alg::AlgorithmIdentifier, cert::SubjectPublicKeyInfo};

/// An alternative public key and its algorithm, distinct from the primary key.
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{alg::AlgorithmIdentifier, ext::SubjectAltPublicKeyInfo};
///
/// let value = SubjectAltPublicKeyInfo::new(
///     AlgorithmIdentifier::new("1.3.101.112".parse()?),
///     Asn1BitString::from_bytes(&[0x11; 32]),
/// );
/// assert_eq!(value.as_subject_public_key_info().algorithm(), value.algorithm());
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(SubjectAltPublicKeyInfo::decode_der(&der, &DecodingOptions::default())?.1, value);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SubjectAltPublicKeyInfo(SubjectPublicKeyInfo);

impl SubjectAltPublicKeyInfo {
    /// Creates an alternative key without interpreting its algorithm or bits.
    pub fn new(algorithm: AlgorithmIdentifier, subject_alt_public_key: Asn1BitString) -> Self {
        Self(SubjectPublicKeyInfo::new(algorithm, subject_alt_public_key))
    }

    /// Returns the alternative key's algorithm and parameters.
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        self.0.algorithm()
    }

    /// Returns the alternative public key bits.
    pub fn subject_alt_public_key(&self) -> &Asn1BitString {
        self.0.subject_public_key()
    }

    /// Borrows the key through the existing public-key parsing interface.
    pub fn as_subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.0
    }
}

impl From<SubjectPublicKeyInfo> for SubjectAltPublicKeyInfo {
    fn from(value: SubjectPublicKeyInfo) -> Self {
        Self(value)
    }
}

impl DecodeInner for SubjectAltPublicKeyInfo {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, value) = SubjectPublicKeyInfo::decode_inner(buff, context)?;
        Ok((used, Self(value)))
    }
}

impl Decode for SubjectAltPublicKeyInfo {}

impl Tagged for SubjectAltPublicKeyInfo {
    const TAG: &'static [u8] = SubjectPublicKeyInfo::TAG;
}

impl EncodeContent for SubjectAltPublicKeyInfo {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.0.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.0.encode_content(rules, out)
    }
}

impl EncodeTagged for SubjectAltPublicKeyInfo {}

impl Encode for SubjectAltPublicKeyInfo {
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

    use super::SubjectAltPublicKeyInfo;
    use crate::{alg::AlgorithmIdentifier, cert::SubjectPublicKeyInfo};

    #[test]
    fn subject_alt_public_key_info_preserves_the_underlying_value_and_der_encoding() {
        let inner = SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
            Asn1BitString::from_bytes(&[0xaa]),
        );
        let value = SubjectAltPublicKeyInfo::from(inner.clone());
        let wire = b"\x30\x0b\x30\x05\x06\x03\x2b\x65\x70\x03\x02\x00\xaa";
        assert_eq!(value.as_subject_public_key_info(), &inner);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            SubjectAltPublicKeyInfo::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn subject_alt_public_key_info_delegates_lengths_and_content_encoding_without_an_extra_wrapper()
    {
        let inner = SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
            Asn1BitString::from_bytes(&[0xaa]),
        );
        let value = SubjectAltPublicKeyInfo::from(inner.clone());
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
    fn alternative_public_keys_preserve_partial_bytes_without_algorithm_validation() {
        let bits = Asn1BitString::decode_der(b"\x03\x02\x03\xa0", &DecodingOptions::default())
            .unwrap()
            .1;
        let algorithm = AlgorithmIdentifier::new("1.2.3".parse().unwrap());
        let value = SubjectAltPublicKeyInfo::new(algorithm.clone(), bits.clone());
        assert_eq!(value.algorithm(), &algorithm);
        assert_eq!(value.subject_alt_public_key(), &bits);
        let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            SubjectAltPublicKeyInfo::decode_der(&der, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn subject_alt_public_key_info_rejects_a_null_in_place_of_its_underlying_tag() {
        assert_eq!(
            SubjectAltPublicKeyInfo::decode_der(b"\x05\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
