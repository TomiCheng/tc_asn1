//! ITU-T X.509 (2019) `AltSignatureAlgorithm` alternative-signature extension value.
//!
//! ```text
//! AltSignatureAlgorithm ::= AlgorithmIdentifier
//! ```
//!
//! This is a typed wrapper with the same encoding as `AlgorithmIdentifier`.
//! Algorithm suitability, bit lengths, extension combinations and the signed
//! data are the responsibility of the validator or signing layer.

use tc_asn1::{
    Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Tagged,
};

use crate::alg::AlgorithmIdentifier;

/// The algorithm identifier for an alternative signature.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{alg::AlgorithmIdentifier, ext::AltSignatureAlgorithm};
///
/// let value = AltSignatureAlgorithm::new(AlgorithmIdentifier::new("1.3.101.112".parse()?));
/// assert!(value.algorithm_identifier().parameters().is_none());
/// let der = value.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(AltSignatureAlgorithm::decode_der(&der, &DecodingOptions::default())?.1, value);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AltSignatureAlgorithm(AlgorithmIdentifier);

impl AltSignatureAlgorithm {
    /// Wraps an algorithm identifier without imposing algorithm policy.
    pub fn new(algorithm: AlgorithmIdentifier) -> Self {
        Self(algorithm)
    }

    /// Returns the alternative signature algorithm and its parameters.
    pub fn algorithm_identifier(&self) -> &AlgorithmIdentifier {
        &self.0
    }
}

impl From<AlgorithmIdentifier> for AltSignatureAlgorithm {
    fn from(value: AlgorithmIdentifier) -> Self {
        Self(value)
    }
}

impl DecodeInner for AltSignatureAlgorithm {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, value) = AlgorithmIdentifier::decode_inner(buff, context)?;
        Ok((used, Self(value)))
    }
}

impl Decode for AltSignatureAlgorithm {}

impl Tagged for AltSignatureAlgorithm {
    const TAG: &'static [u8] = AlgorithmIdentifier::TAG;
}

impl EncodeContent for AltSignatureAlgorithm {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.0.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.0.encode_content(rules, out)
    }
}

impl EncodeTagged for AltSignatureAlgorithm {}

impl Encode for AltSignatureAlgorithm {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.0.encoded_len(rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.0.encode(rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodeContent, EncodingOptions};

    use super::AltSignatureAlgorithm;
    use crate::alg::AlgorithmIdentifier;

    #[test]
    fn alt_signature_algorithm_preserves_the_underlying_value_and_der_encoding() {
        let inner = AlgorithmIdentifier::with_null("1.3.101.112".parse().unwrap());
        let value = AltSignatureAlgorithm::from(inner.clone());
        let wire = b"\x30\x07\x06\x03\x2b\x65\x70\x05\x00";
        assert_eq!(value.algorithm_identifier(), &inner);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            AltSignatureAlgorithm::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn alt_signature_algorithm_delegates_lengths_and_content_encoding_without_an_extra_wrapper() {
        let inner = AlgorithmIdentifier::with_null("1.3.101.112".parse().unwrap());
        let value = AltSignatureAlgorithm::from(inner.clone());
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
    fn alt_signature_algorithm_rejects_a_null_in_place_of_its_underlying_tag() {
        assert_eq!(
            AltSignatureAlgorithm::decode_der(b"\x05\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
