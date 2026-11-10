//! PKCS#1 (RFC 8017 §9.2) `DigestInfo`.
//!
//! ```text
//! DigestInfo ::= SEQUENCE {
//!     digestAlgorithm AlgorithmIdentifier,
//!     digest          OCTET STRING
//! }
//! ```
//!
//! An RSA PKCS#1 v1.5 signature covers its DER encoding (plus padding). The
//! prefix for each hash is a fixed byte string that implementations often
//! hard-code: for SHA-256 it is
//! `30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20` followed by
//! the 32 digest octets.

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::alg::AlgorithmIdentifier;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
/// PKCS #1 `DigestInfo`, `SEQUENCE { digestAlgorithm, digest }`: a digest
/// and the algorithm that made it, as an RSA PKCS #1 v1.5 signature signs.
pub struct DigestInfo {
    digest_algorithm: AlgorithmIdentifier,
    digest: Asn1OctetString,
}

impl DigestInfo {
    /// The digest made by `digest_algorithm`.
    pub fn new(digest_algorithm: AlgorithmIdentifier, digest: &[u8]) -> Self {
        Self {
            digest_algorithm,
            digest: Asn1OctetString::new(digest),
        }
    }

    /// The algorithm that made the digest.
    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        &self.digest_algorithm
    }

    /// The digest octets.
    pub fn digest(&self) -> &[u8] {
        self.digest.as_bytes()
    }
}

impl DecodeInner for DigestInfo {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let digest_algorithm: AlgorithmIdentifier = children.get()?;
        let digest: Asn1OctetString = children.get()?;
        children.end()?;
        Ok((
            element.total_len(),
            Self {
                digest_algorithm,
                digest,
            },
        ))
    }
}

impl Decode for DigestInfo {}

impl Tagged for DigestInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for DigestInfo {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.digest_algorithm.encoded_len(rules) + self.digest.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.digest_algorithm.encode(rules, out)?;
        at += self.digest.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for DigestInfo {}

impl Encode for DigestInfo {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::DigestInfo;
    use crate::alg::AlgorithmIdentifier;

    /// RFC 8017 §9.2, note 1: the fixed SHA-256 prefix implementations hard-code.
    const SHA256_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    fn sha256_info(hash: &[u8; 32]) -> DigestInfo {
        DigestInfo::new(
            AlgorithmIdentifier::with_null("2.16.840.1.101.3.4.2.1".parse().unwrap()),
            hash,
        )
    }

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    #[test]
    fn the_sha256_encoding_starts_with_the_rfc_8017_prefix() {
        let hash = [0xAB; 32];
        let out = sha256_info(&hash).encode_to_vec(&der()).unwrap();
        assert_eq!(out[..19], SHA256_PREFIX);
        assert_eq!(out[19..], hash);
    }

    #[test]
    fn a_der_encoding_decodes_back_to_the_same_value() {
        let info = sha256_info(&[0x11; 32]);
        let out = info.encode_to_vec(&der()).unwrap();
        let (used, decoded) = DigestInfo::decode(&out, &DecodingOptions::default()).unwrap();
        assert_eq!(used, out.len());
        assert_eq!(decoded, info);
        assert_eq!(decoded.digest(), [0x11; 32]);
        assert_eq!(
            decoded.digest_algorithm().algorithm().to_string(),
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(
            DigestInfo::decode_der(&out, &DecodingOptions::default())
                .unwrap()
                .1,
            info
        );
    }

    #[test]
    fn an_indefinite_length_outer_sequence_is_ber_but_not_der() {
        let der_bytes = sha256_info(&[0x22; 32]).encode_to_vec(&der()).unwrap();
        let mut ber: Vec<u8> = vec![0x30, 0x80];
        ber.extend_from_slice(&der_bytes[2..]);
        ber.extend_from_slice(&[0x00, 0x00]);
        assert!(DigestInfo::decode(&ber, &DecodingOptions::default()).is_ok());
        assert!(matches!(
            DigestInfo::decode_der(&ber, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn a_missing_digest_is_truncated_and_an_extra_field_is_trailing_data() {
        let alg_only = [
            0x30, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00,
        ];
        assert!(matches!(
            DigestInfo::decode(&alg_only, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        ));
        let mut extra = sha256_info(&[0x33; 32]).encode_to_vec(&der()).unwrap();
        extra[1] += 2;
        extra.extend_from_slice(&[0x05, 0x00]);
        assert!(matches!(
            DigestInfo::decode(&extra, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        ));
    }

    #[test]
    fn the_digest_must_be_a_primitive_octet_string() {
        // 24 (constructed OCTET STRING) is not accepted by the value type.
        let constructed = [
            0x30, 0x15, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x24, 0x04, 0x04, 0x02, 0xAA, 0xBB,
        ];
        assert!(matches!(
            DigestInfo::decode(&constructed, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
