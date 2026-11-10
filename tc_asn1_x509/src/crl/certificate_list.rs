//! RFC 5280 §5.1 signed certificate revocation list.
//!
//! ```text
//! CertificateList ::= SEQUENCE {
//!     tbsCertList         TBSCertList,
//!     signatureAlgorithm  AlgorithmIdentifier,
//!     signatureValue      BIT STRING }
//! ```
//!
//! Original TBS octets are retained for signature verification. Encoding
//! copies them unchanged, even when DER is requested for a BER-decoded CRL;
//! it does not canonicalize signed data or verify the signature.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Name;

use crate::{
    alg::AlgorithmIdentifier,
    cert::Time,
    crl::{RevokedCertificate, TbsCertList},
    ext::Extensions,
};

/// A CRL with the exact signed bytes and its signature.
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{
///     alg::AlgorithmIdentifier,
///     cert::{Time, Version},
///     crl::{CertificateList, TbsCertList},
/// };
///
/// let tbs = TbsCertList::new(
///     Version::V2, AlgorithmIdentifier::new("1.3.101.112".parse()?),
///     "CN=Example CA".parse()?, Time::new(2026, 1, 1, 0, 0, 0)?,
/// )?;
/// // A signer supplies a signature over tbs.encode_to_vec(DER); this is a placeholder.
/// let crl = CertificateList::new(tbs, Asn1BitString::from_bytes(&[0; 64]))?;
/// let der = crl.encode_to_vec(&EncodingOptions::DER)?;
/// let decoded = CertificateList::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(decoded.tbs_raw(), crl.tbs_raw());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificateList {
    tbs: TbsCertList,
    tbs_raw: Vec<u8>,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: Asn1BitString,
}

impl CertificateList {
    /// Wraps a TBS and a signature computed over its DER encoding.
    /// The outer algorithm is taken from the TBS; signature verification is not performed.
    pub fn new(tbs: TbsCertList, signature_value: Asn1BitString) -> Result<Self, Asn1Error> {
        let tbs_raw = tbs.encode_to_vec(&EncodingOptions::DER)?;
        Ok(Self {
            signature_algorithm: tbs.signature().clone(),
            tbs,
            tbs_raw,
            signature_value,
        })
    }

    /// Returns the decoded signed fields.
    pub fn tbs(&self) -> &TbsCertList {
        &self.tbs
    }

    /// Returns the exact octets covered by the signature, including the TBS tag and length.
    pub fn tbs_raw(&self) -> &[u8] {
        &self.tbs_raw
    }

    /// Returns the signature algorithm, always equal to the TBS algorithm.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature in the signing algorithm's format.
    pub fn signature_value(&self) -> &Asn1BitString {
        &self.signature_value
    }

    /// Returns the CRL issuer.
    pub fn issuer(&self) -> &Name {
        self.tbs.issuer()
    }

    /// Returns the CRL issue time.
    pub fn this_update(&self) -> &Time {
        self.tbs.this_update()
    }

    /// Returns the next scheduled update, if present.
    pub fn next_update(&self) -> Option<&Time> {
        self.tbs.next_update()
    }

    /// Returns revoked entries in wire order.
    pub fn revoked_certificates(&self) -> &[RevokedCertificate] {
        self.tbs.revoked_certificates()
    }

    /// Returns CRL-wide extensions, if present.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.tbs.extensions()
    }
}

impl DecodeInner for CertificateList {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let tbs_raw = match fields.peek() {
            Some(Ok(value)) => value.raw().to_vec(),
            Some(Err(error)) => return Err(error),
            None => return Err(Asn1Error::Truncated),
        };
        let tbs: TbsCertList = fields.get()?;
        let signature_algorithm = fields.get()?;
        let signature_value = fields.get()?;
        fields.end()?;
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

impl EncodeContent for CertificateList {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.tbs_raw.len()
            + self.signature_algorithm.encoded_len(rules)
            + self.signature_value.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.tbs_raw.len();
        out.get_mut(..at)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&self.tbs_raw);
        at += self.signature_algorithm.encode(rules, &mut out[at..])?;
        at += self.signature_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CertificateList {}

impl Tagged for CertificateList {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertificateList {}

impl Encode for CertificateList {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::CertificateList;
    use crate::{
        alg::AlgorithmIdentifier,
        cert::{Time, Version},
        crl::TbsCertList,
    };

    const DER: &[u8] = &[
        0x30, 0x25, 0x30, 0x18, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 0x30, 0, 0x17, 13, b'2', b'6',
        b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x30, 5, 6, 3, 0x2b,
        0x65, 0x70, 3, 2, 0, 0xaa,
    ];

    #[test]
    fn a_new_crl_wraps_der_tbs_bytes_and_the_matching_signature_algorithm() {
        let tbs = TbsCertList::new(
            Version::V1,
            AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
            "".parse().unwrap(),
            Time::new(2026, 1, 1, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let crl = CertificateList::new(tbs, Asn1BitString::from_bytes(&[0xaa])).unwrap();
        assert_eq!(crl.encode_to_vec(&EncodingOptions::DER).unwrap(), DER);
        assert_eq!(
            CertificateList::decode_der(DER, &DecodingOptions::default())
                .unwrap()
                .1,
            crl
        );
        assert_eq!(crl.tbs_raw(), &DER[2..28]);
        assert_eq!(crl.signature_algorithm(), crl.tbs().signature());
    }

    #[test]
    fn indefinite_length_tbs_octets_survive_decoding_and_reencoding_unchanged() {
        let mut wire = DER.to_vec();
        wire[1] += 2;
        wire[3] = 0x80;
        wire.splice(28..28, [0, 0]);
        let crl = CertificateList::decode(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(crl.tbs_raw(), &wire[2..30]);
        assert_eq!(crl.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            CertificateList::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
    }

    #[test]
    fn mismatched_outer_algorithms_are_rejected_before_a_crl_is_returned() {
        let mut wire = DER.to_vec();
        wire[34] = 0x71;
        assert_eq!(
            CertificateList::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn absent_signatures_wrong_signature_tags_and_extra_fields_are_rejected() {
        let mut absent = DER[..35].to_vec();
        absent[1] -= 4;
        assert_eq!(
            CertificateList::decode_der(&absent, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
        let mut wrong = DER.to_vec();
        wrong[35] = 4;
        assert_eq!(
            CertificateList::decode_der(&wrong, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let mut extra = DER.to_vec();
        extra.extend_from_slice(&[5, 0]);
        extra[1] += 2;
        assert_eq!(
            CertificateList::decode_der(&extra, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
