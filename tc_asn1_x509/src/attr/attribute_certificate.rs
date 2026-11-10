//! RFC 5755 §4.1 signed attribute certificate.
//!
//! ```text
//! AttributeCertificate ::= SEQUENCE {
//!     acinfo             AttributeCertificateInfo,
//!     signatureAlgorithm AlgorithmIdentifier,
//!     signatureValue     BIT STRING }
//! ```
//!
//! The original `acinfo` octets are retained for signature verification and
//! copied unchanged during encoding. Asking for DER does not canonicalize
//! BER-decoded signed fields. Signature verification and authorization are
//! performed by the caller.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Attribute;

use crate::{
    alg::AlgorithmIdentifier,
    attr::{AttCertIssuer, AttCertValidityPeriod, AttributeCertificateInfo, Holder},
    ext::Extensions,
};

/// An attribute certificate with its original signed octets.
///
/// ```
/// use tc_asn1::{
///     Asn1BitString, Asn1GeneralizedTime, Asn1Oid, Decode, DecodingOptions,
///     Encode, EncodingOptions,
/// };
/// use tc_asn1_x500::{Attribute, DirectoryString};
/// use tc_asn1_x509::{
///     alg::AlgorithmIdentifier,
///     attr::{AttCertValidityPeriod, AttributeCertificate, AttributeCertificateInfo, Holder, V2Form},
///     name::{GeneralName, GeneralNames},
/// };
///
/// let names = GeneralNames::new(vec![GeneralName::DirectoryName("CN=Example".parse()?)])?;
/// let start = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0)?;
/// let end = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0)?;
/// let info = AttributeCertificateInfo::new(
///     Holder::new(None, Some(names.clone()), None)?,
///     V2Form::new(Some(names), None, None)?.into(),
///     AlgorithmIdentifier::new("1.3.101.112".parse()?), 1.into(),
///     AttCertValidityPeriod::new(start, end)?,
///     vec![Attribute::new(
///         "1.2.3".parse::<Asn1Oid>()?, vec![DirectoryString::new("role")?.into()],
///     )?],
/// )?;
/// // Supply a signature over info's DER encoding; these bytes are only a placeholder.
/// let certificate = AttributeCertificate::new(info, Asn1BitString::from_bytes(&[0; 64]))?;
/// let der = certificate.encode_to_vec(&EncodingOptions::DER)?;
/// let decoded = AttributeCertificate::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(decoded.acinfo_raw(), certificate.acinfo_raw());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttributeCertificate {
    acinfo: AttributeCertificateInfo,
    acinfo_raw: Vec<u8>,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: Asn1BitString,
}

impl AttributeCertificate {
    /// Wraps signed fields and a signature computed over their DER encoding.
    /// The signature is not verified; the outer algorithm is taken from `acinfo`.
    pub fn new(
        acinfo: AttributeCertificateInfo,
        signature_value: Asn1BitString,
    ) -> Result<Self, Asn1Error> {
        let acinfo_raw = acinfo.encode_to_vec(&EncodingOptions::DER)?;
        Ok(Self {
            signature_algorithm: acinfo.signature().clone(),
            acinfo,
            acinfo_raw,
            signature_value,
        })
    }

    /// Returns the decoded signed fields.
    pub fn acinfo(&self) -> &AttributeCertificateInfo {
        &self.acinfo
    }

    /// Returns the signed octets, including the `acinfo` tag and length.
    pub fn acinfo_raw(&self) -> &[u8] {
        &self.acinfo_raw
    }

    /// Returns the signature algorithm, always equal to the one in `acinfo`.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature bits in the signing algorithm's format.
    pub fn signature_value(&self) -> &Asn1BitString {
        &self.signature_value
    }

    /// Returns the holder identification.
    pub fn holder(&self) -> &Holder {
        self.acinfo.holder()
    }

    /// Returns the attribute authority identification.
    pub fn issuer(&self) -> &AttCertIssuer {
        self.acinfo.issuer()
    }

    /// Returns the certificate serial number.
    pub fn serial_number(&self) -> &Asn1Integer {
        self.acinfo.serial_number()
    }

    /// Returns the validity bounds.
    pub fn attr_cert_validity_period(&self) -> &AttCertValidityPeriod {
        self.acinfo.attr_cert_validity_period()
    }

    /// Returns the attributes in wire order.
    pub fn attributes(&self) -> &[Attribute] {
        self.acinfo.attributes()
    }

    /// Returns attribute-certificate extensions, if present.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.acinfo.extensions()
    }
}

impl DecodeContent for AttributeCertificate {
    /// The three fields, as under `30` on its own or under an IMPLICIT tag
    /// such as CMS's `[2]` v2AttrCert.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let acinfo_raw = match fields.peek() {
            Some(Ok(value)) => value.raw().to_vec(),
            Some(Err(error)) => return Err(error),
            None => return Err(Asn1Error::Truncated),
        };
        let acinfo: AttributeCertificateInfo = fields.get()?;
        let signature_algorithm = fields.get()?;
        let signature_value = fields.get()?;
        fields.end()?;
        if signature_algorithm != *acinfo.signature() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            acinfo,
            acinfo_raw,
            signature_algorithm,
            signature_value,
        })
    }
}

impl DecodeInner for AttributeCertificate {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for AttributeCertificate {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.acinfo_raw.len()
            + self.signature_algorithm.encoded_len(rules)
            + self.signature_value.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.acinfo_raw.len();
        out.get_mut(..at)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&self.acinfo_raw);
        at += self.signature_algorithm.encode(rules, &mut out[at..])?;
        at += self.signature_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for AttributeCertificate {}

impl Tagged for AttributeCertificate {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AttributeCertificate {}

impl Encode for AttributeCertificate {
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

    use tc_asn1::{
        Asn1BitString, Asn1Error, Asn1GeneralizedTime, Asn1Oid, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };

    use tc_asn1_x500::{Attribute, DirectoryString};

    use super::AttributeCertificate;
    use crate::{
        alg::AlgorithmIdentifier,
        attr::{AttCertValidityPeriod, AttributeCertificateInfo, Holder, V2Form},
        name::{GeneralName, GeneralNames},
    };

    fn sample() -> AttributeCertificateInfo {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let start = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let end = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0).unwrap();
        AttributeCertificateInfo::new(
            Holder::new(None, Some(names.clone()), None).unwrap(),
            V2Form::new(Some(names), None, None).unwrap().into(),
            AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
            1.into(),
            AttCertValidityPeriod::new(start, end).unwrap(),
            vec![
                Attribute::new(
                    "1.2.3".parse::<Asn1Oid>().unwrap(),
                    vec![DirectoryString::new("x").unwrap().into()],
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn certificate() -> AttributeCertificate {
        AttributeCertificate::new(sample(), Asn1BitString::from_bytes(&[0xaa])).unwrap()
    }

    #[test]
    fn new_attribute_certificates_keep_the_der_info_and_its_signing_algorithm() {
        let value = certificate();
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(&wire[..2], &[0x30, 0x57]);
        assert_eq!(
            value.acinfo_raw(),
            sample().encode_to_vec(&EncodingOptions::DER).unwrap()
        );
        assert_eq!(value.signature_algorithm(), value.acinfo().signature());
        assert_eq!(
            AttributeCertificate::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn ber_signed_info_is_preserved_byte_for_byte_including_its_end_of_contents() {
        let value = certificate();
        let mut wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        let end = 2 + value.acinfo_raw().len();
        wire[1] += 2;
        wire[3] = 0x80;
        wire.splice(end..end, [0, 0]);
        let decoded = AttributeCertificate::decode(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(decoded.acinfo_raw(), &wire[2..end + 2]);
        assert_eq!(decoded.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            AttributeCertificate::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
    }

    #[test]
    fn mismatched_attribute_certificate_signature_algorithms_are_rejected() {
        let value = certificate();
        let mut wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        let algorithm = 2 + value.acinfo_raw().len();
        wire[algorithm + 5] = 4;
        assert_eq!(
            AttributeCertificate::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn attribute_certificate_signatures_are_required_and_no_fourth_field_is_allowed() {
        let mut absent = certificate().encode_to_vec(&EncodingOptions::DER).unwrap();
        absent.truncate(absent.len() - 4);
        absent[1] -= 4;
        assert_eq!(
            AttributeCertificate::decode_der(&absent, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
        let mut wrong = certificate().encode_to_vec(&EncodingOptions::DER).unwrap();
        let tag = wrong.len() - 4;
        wrong[tag] = 4;
        assert_eq!(
            AttributeCertificate::decode_der(&wrong, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let mut extra = certificate().encode_to_vec(&EncodingOptions::DER).unwrap();
        extra.extend_from_slice(&[5, 0]);
        extra[1] += 2;
        assert_eq!(
            AttributeCertificate::decode_der(&extra, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
