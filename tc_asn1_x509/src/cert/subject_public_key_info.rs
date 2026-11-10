//! RFC 5280 §4.1.2.7 `SubjectPublicKeyInfo`.
//!
//! ```text
//! SubjectPublicKeyInfo ::= SEQUENCE {
//!     algorithm         AlgorithmIdentifier,
//!     subjectPublicKey  BIT STRING
//! }
//! ```
//!
//! `subjectPublicKey` holds the key in the algorithm's own format: for RSA the
//! DER of `RSAPublicKey` (RFC 3279 §2.3.1), for EC the uncompressed point
//! (RFC 5480 §2.2), for Ed25519 the raw 32 octets (RFC 8410). The bit string
//! is kept as is; interpreting it is the key type's job.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::alg::AlgorithmIdentifier;

/// A public key with the identifier of its algorithm.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{alg::AlgorithmIdentifier, cert::SubjectPublicKeyInfo};
///
/// // Ed25519 (RFC 8410): no parameters, the key is the 32 raw octets
/// let spki = SubjectPublicKeyInfo::new(
///     AlgorithmIdentifier::new("1.3.101.112".parse()?),
///     Asn1BitString::from_bytes(&[0x11; 32]),
/// );
/// let out = spki.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(&out[..12], [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]);
/// assert_eq!(&out[12..], [0x11; 32]);
/// let (_, back) = SubjectPublicKeyInfo::decode(&out, &DecodingOptions::default())?;
/// assert_eq!(back.subject_public_key().as_bytes(), [0x11; 32]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: Asn1BitString,
}

impl SubjectPublicKeyInfo {
    /// A public key, as its algorithm encodes it, with the algorithm.
    pub fn new(algorithm: AlgorithmIdentifier, subject_public_key: Asn1BitString) -> Self {
        Self {
            algorithm,
            subject_public_key,
        }
    }

    /// The algorithm of the key, with its parameters.
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    /// The key in the algorithm's own encoding, such as a DER `RSAPublicKey`.
    pub fn subject_public_key(&self) -> &Asn1BitString {
        &self.subject_public_key
    }
}

impl DecodeContent for SubjectPublicKeyInfo {
    /// The contents alone, for an `[n] IMPLICIT SubjectPublicKeyInfo` field.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut children = Children::from_contents(value, context)?;
        let algorithm: AlgorithmIdentifier = children.get()?;
        let subject_public_key: Asn1BitString = children.get()?;
        children.end()?;
        Ok(Self {
            algorithm,
            subject_public_key,
        })
    }
}

impl DecodeInner for SubjectPublicKeyInfo {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for SubjectPublicKeyInfo {}

impl Tagged for SubjectPublicKeyInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for SubjectPublicKeyInfo {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.algorithm.encoded_len(rules) + self.subject_public_key.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.algorithm.encode(rules, out)?;
        at += self.subject_public_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for SubjectPublicKeyInfo {}

impl Encode for SubjectPublicKeyInfo {
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
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1BitString, Asn1Error, Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::SubjectPublicKeyInfo;
    use crate::alg::AlgorithmIdentifier;

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    /// The RFC 8410 §10.1 example key, as it appears in a certificate.
    const ED25519: [u8; 44] = [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, 0x19, 0xBF, 0x44,
        0x09, 0x69, 0x84, 0xCD, 0xFE, 0x85, 0x41, 0xBA, 0xC1, 0x67, 0xDC, 0x3B, 0x96, 0xC8, 0x50,
        0x86, 0xAA, 0x30, 0xB6, 0xB6, 0xCB, 0x0C, 0x5C, 0x38, 0xAD, 0x70, 0x31, 0x66, 0xE1,
    ];

    #[test]
    fn the_rfc_8410_ed25519_key_round_trips() {
        let (used, spki) = SubjectPublicKeyInfo::decode(&ED25519, &options()).unwrap();
        assert_eq!(used, ED25519.len());
        assert_eq!(spki.algorithm().algorithm().to_string(), "1.3.101.112");
        assert!(spki.algorithm().parameters().is_none());
        assert_eq!(spki.subject_public_key().as_bytes(), &ED25519[12..]);
        assert_eq!(spki.subject_public_key().unused_bits(), 0);
        assert_eq!(spki.encode_to_vec(&der()).unwrap(), ED25519);
        assert_eq!(
            SubjectPublicKeyInfo::decode_der(&ED25519, &options())
                .unwrap()
                .1,
            spki
        );
    }

    #[test]
    fn an_ec_key_carries_the_curve_as_algorithm_parameters() {
        // ecPublicKey with prime256v1; a made-up uncompressed point of the right length
        let mut point = Vec::from([0x04]);
        point.extend_from_slice(&[0xAB; 64]);
        let spki = SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::with_parameters(
                "1.2.840.10045.2.1".parse().unwrap(),
                "1.2.840.10045.3.1.7".parse::<tc_asn1::Asn1Oid>().unwrap(),
            ),
            Asn1BitString::from_bytes(&point),
        );
        let out = spki.encode_to_vec(&der()).unwrap();
        assert_eq!(out[..2], [0x30, 0x59]);
        let (_, back) = SubjectPublicKeyInfo::decode(&out, &options()).unwrap();
        assert_eq!(back, spki);
        assert!(matches!(
            back.algorithm().parameters(),
            Some(Asn1Object::Oid(curve)) if curve.to_string() == "1.2.840.10045.3.1.7"
        ));
        assert_eq!(back.subject_public_key().as_bytes()[0], 0x04);
    }

    #[test]
    fn the_key_must_be_a_bit_string_and_nothing_may_follow_it() {
        let mut octet_key = ED25519;
        octet_key[9] = 0x04; // OCTET STRING where the BIT STRING belongs
        assert!(matches!(
            SubjectPublicKeyInfo::decode(&octet_key, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        let mut extra: Vec<u8> = ED25519.to_vec();
        extra.extend_from_slice(&[0x05, 0x00]);
        extra[1] += 2;
        assert!(matches!(
            SubjectPublicKeyInfo::decode(&extra, &options()),
            Err(Asn1Error::TrailingData)
        ));
        assert!(matches!(
            SubjectPublicKeyInfo::decode(&ED25519[..9], &options()),
            Err(Asn1Error::Truncated)
        ));
    }
}
