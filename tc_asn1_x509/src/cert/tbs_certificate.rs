//! RFC 5280 §4.1.2 `TBSCertificate`, the signed part of a certificate.
//!
//! ```text
//! TBSCertificate ::= SEQUENCE {
//!     version              [0] EXPLICIT Version DEFAULT v1,
//!     serialNumber         CertificateSerialNumber,
//!     signature            AlgorithmIdentifier,
//!     issuer               Name,
//!     validity             Validity,
//!     subject              Name,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     issuerUniqueID       [1] IMPLICIT UniqueIdentifier OPTIONAL,  -- v2 or v3
//!     subjectUniqueID      [2] IMPLICIT UniqueIdentifier OPTIONAL,  -- v2 or v3
//!     extensions           [3] EXPLICIT Extensions OPTIONAL         -- v3
//! }
//!
//! Version ::= INTEGER { v1(0), v2(1), v3(2) }
//! CertificateSerialNumber ::= INTEGER
//! UniqueIdentifier ::= BIT STRING
//! ```
//!
//! The version is implied by what is present: extensions need v3, unique
//! identifiers need v2 or v3. The serial number is meant to be positive and
//! at most 20 octets, but RFC 5280 asks decoders to accept what CAs have
//! issued, so it is kept as is. The unique identifiers are obsolete; they
//! are read for old certificates and MUST NOT be generated.
//!
//! Signature verification needs the octets exactly as received, not a
//! re-encoding; the enclosing `Certificate` keeps those.

use core::fmt;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Implicit, Tagged, tag,
};
use tc_asn1_x500::Name;

use crate::{
    alg::AlgorithmIdentifier,
    cert::{SubjectPublicKeyInfo, Validity},
    ext::Extensions,
};

/// The certificate version, `Version ::= INTEGER { v1(0), v2(1), v3(2) }`.
/// Note the offset: v1 is encoded as 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Version {
    /// Version 1, encoded as 0: no unique identifiers and no extensions.
    V1 = 0,
    /// Version 2, encoded as 1: unique identifiers but no extensions.
    V2 = 1,
    /// Version 3, encoded as 2: extensions.
    V3 = 2,
}

impl Version {
    /// The INTEGER value: 0, 1 or 2.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// From the INTEGER value; anything but 0, 1 or 2 is `MalformedValue`.
    pub fn from_number(number: u8) -> Result<Self, Asn1Error> {
        match number {
            0 => Ok(Self::V1),
            1 => Ok(Self::V2),
            2 => Ok(Self::V3),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

/// `v1`, `v2` or `v3`.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.number() + 1)
    }
}

/// The fields a CA signs.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TbsCertificate {
    version: Version,
    serial_number: Asn1Integer,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_id: Option<Asn1BitString>,
    subject_unique_id: Option<Asn1BitString>,
    extensions: Option<Extensions>,
}

impl TbsCertificate {
    /// The mandatory fields; the optional ones are added with the `with_`
    /// methods, which check them against the version.
    pub fn new(
        version: Version,
        serial_number: Asn1Integer,
        signature: AlgorithmIdentifier,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
    ) -> Self {
        Self {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        }
    }

    /// The unique identifiers, which RFC 5280 allows only from v2 on;
    /// `MalformedValue` for a v1 certificate.
    pub fn with_unique_ids(
        mut self,
        issuer_unique_id: Option<Asn1BitString>,
        subject_unique_id: Option<Asn1BitString>,
    ) -> Result<Self, Asn1Error> {
        if self.version == Version::V1
            && (issuer_unique_id.is_some() || subject_unique_id.is_some())
        {
            return Err(Asn1Error::MalformedValue);
        }
        self.issuer_unique_id = issuer_unique_id;
        self.subject_unique_id = subject_unique_id;
        Ok(self)
    }

    /// The extensions, which RFC 5280 allows only in v3; `MalformedValue`
    /// otherwise.
    pub fn with_extensions(mut self, extensions: Extensions) -> Result<Self, Asn1Error> {
        if self.version != Version::V3 {
            return Err(Asn1Error::MalformedValue);
        }
        self.extensions = Some(extensions);
        Ok(self)
    }

    /// The version; V1 when the field is absent.
    pub fn version(&self) -> Version {
        self.version
    }

    /// As issued; may be negative or longer than 20 octets in old or
    /// non-conforming certificates.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }

    /// The signature algorithm, which must match the outer certificate's.
    pub fn signature(&self) -> &AlgorithmIdentifier {
        &self.signature
    }

    /// The issuer's name.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// The validity period.
    pub fn validity(&self) -> &Validity {
        &self.validity
    }

    /// The subject's name; empty when the subject alternative name stands
    /// for it.
    pub fn subject(&self) -> &Name {
        &self.subject
    }

    /// The subject's public key and its algorithm.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key_info
    }

    /// The issuer's unique identifier, of version 2 and 3 only, which RFC
    /// 5280 advises against.
    pub fn issuer_unique_id(&self) -> Option<&Asn1BitString> {
        self.issuer_unique_id.as_ref()
    }

    /// The subject's unique identifier, of version 2 and 3 only, which RFC
    /// 5280 advises against.
    pub fn subject_unique_id(&self) -> Option<&Asn1BitString> {
        self.subject_unique_id.as_ref()
    }

    /// The extensions, of version 3 only.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeInner for TbsCertificate {
    /// The optional fields are recognized by their context tags. A version
    /// other than 0, 1 or 2, unique identifiers in v1 or extensions outside
    /// v3 are `MalformedValue`; a written v1 is `NotDer` under DER.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let version: Asn1Integer = children.get_explicit_default([0xA0], Asn1Integer::from(0))?;
        let serial_number: Asn1Integer = children.get()?;
        let signature: AlgorithmIdentifier = children.get()?;
        let issuer: Name = children.get()?;
        let validity: Validity = children.get()?;
        let subject: Name = children.get()?;
        let subject_public_key_info: SubjectPublicKeyInfo = children.get()?;
        let issuer_unique_id = children.get_implicit_opt::<Asn1BitString>([0x81])?;
        let subject_unique_id = children.get_implicit_opt::<Asn1BitString>([0x82])?;
        let extensions = children.get_explicit_opt::<Extensions>([0xA3])?;
        children.end()?;

        let version =
            Version::from_number(u8::try_from(&version).map_err(|_| Asn1Error::MalformedValue)?)?;
        let tbs = Self::new(
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
        )
        .with_unique_ids(issuer_unique_id, subject_unique_id)?;
        let tbs = match extensions {
            Some(extensions) => tbs.with_extensions(extensions)?,
            None => tbs,
        };
        Ok((element.total_len(), tbs))
    }
}

impl Decode for TbsCertificate {}

impl Tagged for TbsCertificate {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for TbsCertificate {
    /// The fields' TLVs back to back: the version only from v2 on, v1 being
    /// the DEFAULT, and the optional fields only when present.
    /// Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = 0;
        if self.version != Version::V1 {
            let version = Asn1Integer::from(self.version.number());
            len += Explicit::new(&[0xA0], &version).encoded_len(rules);
        }
        len += self.serial_number.encoded_len(rules);
        len += self.signature.encoded_len(rules);
        len += self.issuer.encoded_len(rules);
        len += self.validity.encoded_len(rules);
        len += self.subject.encoded_len(rules);
        len += self.subject_public_key_info.encoded_len(rules);
        if let Some(id) = &self.issuer_unique_id {
            len += Implicit::new(&[0x81], id).encoded_len(rules);
        }
        if let Some(id) = &self.subject_unique_id {
            len += Implicit::new(&[0x82], id).encoded_len(rules);
        }
        if let Some(extensions) = &self.extensions {
            len += Explicit::new(&[0xA3], extensions).encoded_len(rules);
        }
        len
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if self.version != Version::V1 {
            let version = Asn1Integer::from(self.version.number());
            at += Explicit::new(&[0xA0], &version).encode(rules, &mut out[at..])?;
        }
        at += self.serial_number.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        at += self.issuer.encode(rules, &mut out[at..])?;
        at += self.validity.encode(rules, &mut out[at..])?;
        at += self.subject.encode(rules, &mut out[at..])?;
        at += self.subject_public_key_info.encode(rules, &mut out[at..])?;
        if let Some(id) = &self.issuer_unique_id {
            at += Implicit::new(&[0x81], id).encode(rules, &mut out[at..])?;
        }
        if let Some(id) = &self.subject_unique_id {
            at += Implicit::new(&[0x82], id).encode(rules, &mut out[at..])?;
        }
        if let Some(extensions) = &self.extensions {
            at += Explicit::new(&[0xA3], extensions).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for TbsCertificate {}

impl Encode for TbsCertificate {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1BitString, Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions,
    };

    use super::{TbsCertificate, Version};
    use crate::{
        alg::AlgorithmIdentifier,
        cert::{SubjectPublicKeyInfo, Validity},
        ext::{ExtensionId, Extensions, KeyUsage},
    };

    /// RFC 8410's example certificate; see `tests/data/README.md`.
    const RFC_8410: &[u8] = include_bytes!("../../tests/data/rfc8410.der");

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    /// The TBSCertificate: the outer SEQUENCE's first element.
    fn tbs_bytes() -> Vec<u8> {
        RFC_8410.to_vec()[4..230].to_vec()
    }

    fn v1_from(v3: &TbsCertificate) -> TbsCertificate {
        TbsCertificate::new(
            Version::V1,
            v3.serial_number().clone(),
            v3.signature().clone(),
            v3.issuer().clone(),
            *v3.validity(),
            v3.subject().clone(),
            v3.subject_public_key_info().clone(),
        )
    }

    #[test]
    fn the_rfc_8410_certificate_decodes_field_by_field() {
        let bytes = tbs_bytes();
        let (used, tbs) = TbsCertificate::decode(&bytes, &options()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(tbs.version(), Version::V3);
        assert_eq!(format!("{:x}", tbs.serial_number()), "5601474a2a8dc330");
        assert_eq!(tbs.signature().to_string(), "1.3.101.112");
        assert_eq!(tbs.issuer().to_string(), "CN=IETF Test Demo");
        assert_eq!(tbs.subject(), tbs.issuer());
        assert_eq!(
            tbs.validity().not_before().to_string(),
            "2016-08-01T12:19:24Z"
        );
        assert_eq!(tbs.validity().not_after().year(), 2040);
        assert_eq!(
            tbs.subject_public_key_info().algorithm().to_string(),
            "1.3.101.110"
        );
        assert_eq!(
            tbs.subject_public_key_info()
                .subject_public_key()
                .as_bytes()
                .len(),
            32
        );
        assert!(tbs.issuer_unique_id().is_none());
        assert!(tbs.subject_unique_id().is_none());

        let extensions = tbs.extensions().unwrap();
        assert_eq!(extensions.extensions().len(), 3);
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_key_usage(&mut context).unwrap(),
            Some(KeyUsage::KEY_AGREEMENT)
        );
        // basicConstraints is critical and its value writes cA FALSE, which
        // DER forbids: the extension is there, its value is not DER.
        assert!(
            extensions
                .get(ExtensionId::BASIC_CONSTRAINTS)
                .unwrap()
                .critical()
        );
        assert!(matches!(
            extensions.get_basic_constraints(&mut context),
            Err(Asn1Error::NotDer)
        ));
        assert_eq!(
            extensions
                .get(ExtensionId::SUBJECT_KEY_IDENTIFIER)
                .unwrap()
                .extn_value()[..2],
            [0x04, 0x14]
        );
    }

    #[test]
    fn the_example_is_ber_and_re_encodes_shorter_under_der() {
        let bytes = tbs_bytes();
        assert!(matches!(
            TbsCertificate::decode_der(&bytes, &options()),
            Err(Asn1Error::NotDer)
        ));
        let (_, tbs) = TbsCertificate::decode(&bytes, &options()).unwrap();
        let canonical = tbs.encode_to_vec(&der()).unwrap();
        // two `critical FALSE` of three octets each are dropped
        assert_eq!(canonical.len(), bytes.len() - 6);
        assert_ne!(canonical, bytes);
        let (_, again) = TbsCertificate::decode_der(&canonical, &options()).unwrap();
        assert_eq!(again, tbs);
    }

    #[test]
    fn a_v1_certificate_writes_neither_version_nor_extensions() {
        let (_, v3) = TbsCertificate::decode(&tbs_bytes(), &options()).unwrap();
        let v1 = v1_from(&v3);
        let out = v1.encode_to_vec(&der()).unwrap();
        assert_eq!(out[..4], [0x30, 0x81, 0x93, 0x02]); // straight to the serial number
        let (_, back) = TbsCertificate::decode_der(&out, &options()).unwrap();
        assert_eq!(back, v1);
        assert_eq!(back.version(), Version::V1);
        assert!(back.extensions().is_none());

        assert!(matches!(
            v1.clone().with_extensions(v3.extensions().unwrap().clone()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            v1.with_unique_ids(Some(Asn1BitString::from_bytes(&[1])), None),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn the_version_field_is_checked_against_the_contents() {
        // extensions in what claims to be v1: drop `A0 03 02 01 02`, fix the length
        let bytes = tbs_bytes();
        let mut v1_with_extensions = Vec::from(&bytes[..3]);
        v1_with_extensions.extend_from_slice(&bytes[8..]);
        v1_with_extensions[2] -= 5;
        assert!(matches!(
            TbsCertificate::decode(&v1_with_extensions, &options()),
            Err(Asn1Error::MalformedValue)
        ));

        // an unknown version number
        let mut v4 = bytes.clone();
        v4[7] = 0x03;
        assert!(matches!(
            TbsCertificate::decode(&v4, &options()),
            Err(Asn1Error::MalformedValue)
        ));

        // v1 written out, no extensions: BER accepts it, DER does not
        let (_, v3) = TbsCertificate::decode(&bytes, &options()).unwrap();
        let plain = v1_from(&v3).encode_to_vec(&der()).unwrap();
        let mut explicit_v1 = Vec::from(&plain[..3]);
        explicit_v1.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x00]);
        explicit_v1.extend_from_slice(&plain[3..]);
        explicit_v1[2] += 5;
        let (_, back) = TbsCertificate::decode(&explicit_v1, &options()).unwrap();
        assert_eq!(back.version(), Version::V1);
        assert!(matches!(
            TbsCertificate::decode_der(&explicit_v1, &options()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn the_parts_can_be_decoded_on_their_own() {
        let certificate = RFC_8410.to_vec();
        let (_, validity) = Validity::decode(&certificate[56..88], &options()).unwrap();
        assert_eq!(validity.not_after().to_string(), "2040-12-31T23:59:59Z");
        let (_, spki) = SubjectPublicKeyInfo::decode(&certificate[115..159], &options()).unwrap();
        assert_eq!(
            spki.algorithm(),
            &AlgorithmIdentifier::new("1.3.101.110".parse().unwrap())
        );
        let (_, extensions) = Extensions::decode(&certificate[161..230], &options()).unwrap();
        assert_eq!(extensions.extensions().len(), 3);
    }
}
