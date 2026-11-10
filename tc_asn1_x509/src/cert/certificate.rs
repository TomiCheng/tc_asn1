//! RFC 5280 §4.1 `Certificate`.
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate      TBSCertificate,
//!     signatureAlgorithm  AlgorithmIdentifier,
//!     signatureValue      BIT STRING }
//! ```
//!
//! The signed structure, the algorithm it was signed with and the signature.
//! Verifying the signature needs the `tbsCertificate` octets exactly as
//! received, and re-encoding a BER certificate changes them, so the
//! certificate keeps those octets and writes them back unchanged. What the
//! signature means and how to check it belongs to a layer with the
//! algorithms; this type only hands over the three pieces.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Name;

use crate::{
    alg::AlgorithmIdentifier,
    cert::{SubjectPublicKeyInfo, TbsCertificate, Validity},
    ext::Extensions,
};

/// A certificate: the TBS, its original octets, and the signature over them.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{
///     alg::AlgorithmIdentifier,
///     cert::{Certificate, SubjectPublicKeyInfo, TbsCertificate, Time, Validity, Version},
/// };
///
/// // A self-issued Ed25519 certificate: the TBS names the signing algorithm ...
/// let ed25519 = AlgorithmIdentifier::new("1.3.101.112".parse()?);
/// let tbs = TbsCertificate::new(
///     Version::V3,
///     1.into(),
///     ed25519.clone(),
///     "CN=Example Root".parse()?,
///     Validity::new(Time::new(2026, 1, 1, 0, 0, 0)?, Time::new(2036, 1, 1, 0, 0, 0)?)?,
///     "CN=Example Root".parse()?,
///     SubjectPublicKeyInfo::new(ed25519, Asn1BitString::from_bytes(&[0x11; 32])),
/// );
///
/// // ... a signer produces the signature over the TBS's DER (not shown) ...
/// let signature = Asn1BitString::from_bytes(&[0x22; 64]);
/// let certificate = Certificate::new(tbs, signature)?;
///
/// // ... and the result decodes back with the signed octets intact.
/// let der = certificate.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = Certificate::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, certificate);
/// println!("{} issued by {}", back.subject(), back.issuer());
///
/// // What a verifier needs: the signed octets, the algorithm and the signature.
/// let (signed, algorithm, signature) = (back.tbs_raw(), back.signature_algorithm(), back.signature_value());
/// assert_eq!(algorithm.to_string(), "1.3.101.112");
/// # let _ = (signed, signature);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Certificate {
    tbs: TbsCertificate,
    tbs_raw: Vec<u8>,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: Asn1BitString,
}

impl Certificate {
    /// From a TBS and the signature computed over its DER encoding, which
    /// becomes the octets this certificate carries. The signature algorithm
    /// is the one the TBS names.
    pub fn new(tbs: TbsCertificate, signature_value: Asn1BitString) -> Result<Self, Asn1Error> {
        let tbs_raw = tbs.encode_to_vec(&EncodingOptions::DER)?;
        Ok(Self {
            signature_algorithm: tbs.signature().clone(),
            tbs,
            tbs_raw,
            signature_value,
        })
    }

    /// The signed fields.
    pub fn tbs(&self) -> &TbsCertificate {
        &self.tbs
    }

    /// The `tbsCertificate` octets as received, or as first encoded: what
    /// the signature covers.
    pub fn tbs_raw(&self) -> &[u8] {
        &self.tbs_raw
    }

    /// Always equal to `tbs().signature()`, as RFC 5280 requires.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// The signature in the algorithm's own format: an integer for RSA, a
    /// DER `SEQUENCE { r, s }` for ECDSA, raw octets for EdDSA.
    pub fn signature_value(&self) -> &Asn1BitString {
        &self.signature_value
    }

    /// The serial number of the signed fields.
    pub fn serial_number(&self) -> &tc_asn1::Asn1Integer {
        self.tbs.serial_number()
    }

    /// The issuer of the signed fields.
    pub fn issuer(&self) -> &Name {
        self.tbs.issuer()
    }

    /// The subject of the signed fields; empty when the subject alternative
    /// name stands for it.
    pub fn subject(&self) -> &Name {
        self.tbs.subject()
    }

    /// The validity period of the signed fields.
    pub fn validity(&self) -> &Validity {
        self.tbs.validity()
    }

    /// The subject's public key and its algorithm.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        self.tbs.subject_public_key_info()
    }

    /// The extensions of the signed fields, present only in a version 3
    /// certificate.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.tbs.extensions()
    }
}

impl DecodeInner for Certificate {
    /// A `signatureAlgorithm` that differs from the TBS's `signature` is
    /// `MalformedValue` (RFC 5280 §4.1.1.2). Variable time: branches only
    /// on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let tbs_raw = match children.peek() {
            Some(Ok(first)) => first.raw().to_vec(),
            Some(Err(e)) => return Err(e),
            None => return Err(Asn1Error::Truncated),
        };
        let tbs: TbsCertificate = children.get()?;
        let signature_algorithm: AlgorithmIdentifier = children.get()?;
        let signature_value: Asn1BitString = children.get()?;
        children.end()?;
        if signature_algorithm != *tbs.signature() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((
            element.total_len(),
            Self {
                tbs,
                tbs_raw,
                signature_algorithm,
                signature_value,
            },
        ))
    }
}

impl Decode for Certificate {}

impl Tagged for Certificate {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for Certificate {
    /// The TBS octets are written as kept, whatever the rules, so that the
    /// signature stays valid; only the two fields after it follow `rules`.
    /// Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.tbs_raw.len()
            + self.signature_algorithm.encoded_len(rules)
            + self.signature_value.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let raw = self.tbs_raw.len();
        out.get_mut(..raw)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&self.tbs_raw);
        let mut at = raw;
        at += self.signature_algorithm.encode(rules, &mut out[at..])?;
        at += self.signature_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for Certificate {}

impl Encode for Certificate {
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

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::Certificate;
    use crate::cert::{TbsCertificate, Version};

    /// RFC 8410's example certificate; see `tests/data/README.md`.
    const RFC_8410: &[u8] = include_bytes!("../../tests/data/rfc8410.der");

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_rfc_8410_certificate_decodes_and_keeps_the_signed_octets() {
        let bytes = RFC_8410.to_vec();
        let (used, certificate) = Certificate::decode(&bytes, &options()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(certificate.tbs_raw(), &bytes[4..230]);
        assert_eq!(certificate.tbs().version(), Version::V3);
        assert_eq!(certificate.subject().to_string(), "CN=IETF Test Demo");
        assert_eq!(certificate.signature_algorithm().to_string(), "1.3.101.112");
        assert_eq!(certificate.signature_value().as_bytes(), &bytes[240..]);
        assert_eq!(certificate.signature_value().unused_bits(), 0);
    }

    #[test]
    fn a_ber_certificate_is_written_back_unchanged() {
        let bytes = RFC_8410.to_vec();
        let (_, certificate) = Certificate::decode(&bytes, &options()).unwrap();
        // the TBS inside is BER, and comes back byte for byte
        assert!(matches!(
            TbsCertificate::decode_der(certificate.tbs_raw(), &options()),
            Err(Asn1Error::NotDer)
        ));
        assert_eq!(certificate.encode_to_vec(&der()).unwrap(), bytes);
    }

    #[test]
    fn a_new_certificate_carries_the_der_of_its_tbs() {
        let bytes = RFC_8410.to_vec();
        let (_, decoded) = Certificate::decode(&bytes, &options()).unwrap();
        let rebuilt =
            Certificate::new(decoded.tbs().clone(), decoded.signature_value().clone()).unwrap();
        assert_eq!(rebuilt.tbs(), decoded.tbs());
        assert_eq!(rebuilt.signature_algorithm(), decoded.signature_algorithm());
        // the TBS was re-encoded to DER, six octets shorter than the original
        assert_eq!(rebuilt.tbs_raw().len(), decoded.tbs_raw().len() - 6);
        assert_ne!(rebuilt, decoded);
        let (_, again) =
            Certificate::decode_der(&rebuilt.encode_to_vec(&der()).unwrap(), &options()).unwrap();
        assert_eq!(again, rebuilt);
    }

    #[test]
    fn the_outer_algorithm_must_match_the_signed_one() {
        let mut bytes = RFC_8410.to_vec();
        bytes[236] = 0x71; // 1.3.101.112 -> 1.3.101.113 (Ed448) in signatureAlgorithm only
        assert!(matches!(
            Certificate::decode(&bytes, &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_missing_signature_or_trailing_field_is_rejected() {
        let bytes = RFC_8410.to_vec();
        let mut no_signature = Vec::from(&bytes[..237]);
        no_signature[2] = 0x00;
        no_signature[3] = 0xe9; // 237 - 4
        assert!(matches!(
            Certificate::decode(&no_signature, &options()),
            Err(Asn1Error::Truncated)
        ));
        let mut extra = bytes.clone();
        extra.extend_from_slice(&[0x05, 0x00]);
        extra[3] += 2;
        assert!(matches!(
            Certificate::decode(&extra, &options()),
            Err(Asn1Error::TrailingData)
        ));
    }
}
