//! Delta certificate descriptor of draft-bonnell-lamps-chameleon-certs, which
//! carries a second, "delta" certificate inside an extension of the base certificate.
//!
//! ```text
//! DeltaCertificateDescriptor ::= SEQUENCE {
//!     serialNumber         CertificateSerialNumber,
//!     signature            [0] EXPLICIT AlgorithmIdentifier OPTIONAL,
//!     issuer               [1] EXPLICIT Name OPTIONAL,
//!     validity             [2] EXPLICIT Validity OPTIONAL,
//!     subject              [3] EXPLICIT Name OPTIONAL,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     extensions           [4] EXPLICIT Extensions OPTIONAL,
//!     signatureValue       BIT STRING }
//! ```
//!
//! An absent field means the delta certificate repeats the base certificate's
//! value. Rebuilding the delta certificate and checking its signature belong to
//! the caller.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x500::Name;

use crate::{
    alg::AlgorithmIdentifier,
    cert::{SubjectPublicKeyInfo, Validity},
    ext::Extensions,
};

const SIGNATURE: &[u8] = &[0xa0];
const ISSUER: &[u8] = &[0xa1];
const VALIDITY: &[u8] = &[0xa2];
const SUBJECT: &[u8] = &[0xa3];
const EXTENSIONS: &[u8] = &[0xa4];

/// The fields in which a delta certificate differs from its base certificate.
///
/// ```
/// use tc_asn1::{Asn1BitString, Decode, DecodingOptions};
/// use tc_asn1_x509::{cert::Certificate, ext::DeltaCertificateDescriptor};
///
/// # let der = include_bytes!("../../tests/data/rfc8410.der");
/// let (_, base) = Certificate::decode(der, &DecodingOptions::default())?;
/// let delta = DeltaCertificateDescriptor::new(
///     2.into(),
///     base.subject_public_key_info().clone(),
///     Asn1BitString::from_bytes(&[0xaa; 64]),
/// )
/// .with_subject(base.subject().clone());
/// assert!(delta.issuer().is_none());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DeltaCertificateDescriptor {
    serial_number: Asn1Integer,
    signature: Option<AlgorithmIdentifier>,
    issuer: Option<Name>,
    validity: Option<Validity>,
    subject: Option<Name>,
    subject_public_key_info: SubjectPublicKeyInfo,
    extensions: Option<Extensions>,
    signature_value: Asn1BitString,
}

impl DeltaCertificateDescriptor {
    /// Creates a descriptor with the required fields; every optional field starts absent.
    pub fn new(
        serial_number: Asn1Integer,
        subject_public_key_info: SubjectPublicKeyInfo,
        signature_value: Asn1BitString,
    ) -> Self {
        Self {
            serial_number,
            signature: None,
            issuer: None,
            validity: None,
            subject: None,
            subject_public_key_info,
            extensions: None,
            signature_value,
        }
    }

    /// Sets the delta certificate's `signature` algorithm.
    pub fn with_signature(mut self, signature: AlgorithmIdentifier) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Sets the delta certificate's `issuer`.
    pub fn with_issuer(mut self, issuer: Name) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Sets the delta certificate's `validity`.
    pub fn with_validity(mut self, validity: Validity) -> Self {
        self.validity = Some(validity);
        self
    }

    /// Sets the delta certificate's `subject`.
    pub fn with_subject(mut self, subject: Name) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Sets the extensions that differ in the delta certificate.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Returns the delta certificate's serial number.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }

    /// Returns `signature`, if it differs from the base certificate.
    pub fn signature(&self) -> Option<&AlgorithmIdentifier> {
        self.signature.as_ref()
    }

    /// Returns `issuer`, if it differs from the base certificate.
    pub fn issuer(&self) -> Option<&Name> {
        self.issuer.as_ref()
    }

    /// Returns `validity`, if it differs from the base certificate.
    pub fn validity(&self) -> Option<&Validity> {
        self.validity.as_ref()
    }

    /// Returns `subject`, if it differs from the base certificate.
    pub fn subject(&self) -> Option<&Name> {
        self.subject.as_ref()
    }

    /// Returns the delta certificate's public key.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key_info
    }

    /// Returns the extensions that differ, if any.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }

    /// Returns the delta certificate's signature.
    pub fn signature_value(&self) -> &Asn1BitString {
        &self.signature_value
    }
}

impl DecodeContent for DeltaCertificateDescriptor {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let serial_number = fields.get()?;
        let signature = fields.get_explicit_opt::<AlgorithmIdentifier>(SIGNATURE)?;
        let issuer = fields.get_explicit_opt::<Name>(ISSUER)?;
        let validity = fields.get_explicit_opt::<Validity>(VALIDITY)?;
        let subject = fields.get_explicit_opt::<Name>(SUBJECT)?;
        let subject_public_key_info = fields.get()?;
        let extensions = fields.get_explicit_opt::<Extensions>(EXTENSIONS)?;
        let signature_value = fields.get()?;
        fields.end()?;
        Ok(Self {
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
            signature_value,
        })
    }
}

impl DecodeInner for DeltaCertificateDescriptor {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        Ok((
            element.total_len(),
            Self::decode_content(element.value(), context)?,
        ))
    }
}

impl EncodeContent for DeltaCertificateDescriptor {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let explicit = |tag: &[u8], value: Option<&dyn Encode>| {
            value.map_or(0, |value| Explicit::new(tag, value).encoded_len(rules))
        };
        self.serial_number.encoded_len(rules)
            + explicit(SIGNATURE, self.signature.as_ref().map(|v| v as &dyn Encode))
            + explicit(ISSUER, self.issuer.as_ref().map(|v| v as &dyn Encode))
            + explicit(VALIDITY, self.validity.as_ref().map(|v| v as &dyn Encode))
            + explicit(SUBJECT, self.subject.as_ref().map(|v| v as &dyn Encode))
            + self.subject_public_key_info.encoded_len(rules)
            + explicit(
                EXTENSIONS,
                self.extensions.as_ref().map(|v| v as &dyn Encode),
            )
            + self.signature_value.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.serial_number.encode(rules, out)?;
        let optional: [(&[u8], Option<&dyn Encode>); 4] = [
            (SIGNATURE, self.signature.as_ref().map(|v| v as &dyn Encode)),
            (ISSUER, self.issuer.as_ref().map(|v| v as &dyn Encode)),
            (VALIDITY, self.validity.as_ref().map(|v| v as &dyn Encode)),
            (SUBJECT, self.subject.as_ref().map(|v| v as &dyn Encode)),
        ];
        for (tag, value) in optional {
            if let Some(value) = value {
                at += Explicit::new(tag, value).encode(rules, &mut out[at..])?;
            }
        }
        at += self.subject_public_key_info.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.extensions {
            at += Explicit::new(EXTENSIONS, value).encode(rules, &mut out[at..])?;
        }
        at += self.signature_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for DeltaCertificateDescriptor {}

impl Tagged for DeltaCertificateDescriptor {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for DeltaCertificateDescriptor {}

impl Encode for DeltaCertificateDescriptor {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{
        Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodingContext, DecodingOptions,
        Encode, EncodingOptions,
    };

    use super::DeltaCertificateDescriptor;
    use crate::cert::Certificate;

    /// RFC 8410's example certificate; see `tests/data/README.md`.
    const RFC_8410: &[u8] = include_bytes!("../../tests/data/rfc8410.der");

    fn base() -> Certificate {
        Certificate::decode(RFC_8410, &DecodingOptions::default())
            .unwrap()
            .1
    }

    fn minimal(base: &Certificate) -> DeltaCertificateDescriptor {
        DeltaCertificateDescriptor::new(
            2.into(),
            base.subject_public_key_info().clone(),
            Asn1BitString::from_bytes(&[0xaa; 4]),
        )
    }

    /// The tag of each top-level field, in wire order.
    fn field_tags(wire: &[u8]) -> alloc::vec::Vec<u8> {
        let mut context = DecodingContext::new(DecodingOptions::default());
        let outer = Asn1Ref::parse(wire, &mut context).unwrap();
        Children::from_contents(outer.value(), &mut context)
            .unwrap()
            .map(|field| field.unwrap().tag()[0])
            .collect()
    }

    #[test]
    fn a_descriptor_with_only_the_required_fields_round_trips() {
        let value = minimal(&base());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(field_tags(&wire), [0x02, 0x30, 0x03]);
        assert_eq!(
            DeltaCertificateDescriptor::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn every_optional_field_uses_its_explicit_tag_in_order() {
        let base = base();
        let value = minimal(&base)
            .with_signature(base.signature_algorithm().clone())
            .with_issuer(base.issuer().clone())
            .with_validity(*base.validity())
            .with_subject(base.subject().clone())
            .with_extensions(base.extensions().unwrap().clone());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            field_tags(&wire),
            [0x02, 0xa0, 0xa1, 0xa2, 0xa3, 0x30, 0xa4, 0x03]
        );
        let back = DeltaCertificateDescriptor::decode(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back, value);
        assert_eq!(back.subject(), Some(base.subject()));
    }

    #[test]
    fn a_missing_public_key_or_signature_is_rejected() {
        let options = DecodingOptions::default();
        // serialNumber and signatureValue only
        assert!(
            DeltaCertificateDescriptor::decode_der(b"\x30\x06\x02\x01\x02\x03\x01\x00", &options)
                .is_err()
        );
        assert!(matches!(
            DeltaCertificateDescriptor::decode_der(b"\x31\x00", &options),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
