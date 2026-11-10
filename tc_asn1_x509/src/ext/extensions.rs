//! RFC 5280 §4.1.2.9 `Extensions`.
//!
//! ```text
//! Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
//! ```
//!
//! The extension list of a certificate or CRL, in wire order. It is never
//! empty and, per RFC 5280 §4.2, never holds two extensions with the same
//! OID; both are enforced. Whether an unrecognized critical extension makes
//! the certificate unusable is the validator's call, made with [`get`] and
//! [`Extension::critical`].
//!
//! [`get`]: Extensions::get

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::{
    crl::{CrlDistributionPoints, CrlReason, IssuingDistributionPoint},
    ext::{
        AltSignatureAlgorithm, AltSignatureValue, AuthorityKeyIdentifier, BasicConstraints,
        CertificatePolicies, ExtendedKeyUsage, Extension, ExtensionId, InformationAccess,
        InhibitAnyPolicy, KeyUsage, NameConstraints, PolicyConstraints, PolicyMappings,
        PrivateKeyUsagePeriod, SubjectAltPublicKeyInfo, SubjectDirectoryAttributes,
        SubjectKeyIdentifier,
    },
    name::GeneralNames,
};

/// A non-empty list of extensions with unique OIDs.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::{BasicConstraints, Extension, ExtensionId, Extensions, KeyUsage};
///
/// // A CA certificate's extensions: both critical, as RFC 5280 recommends.
/// let extensions = Extensions::new(vec![
///     Extension::with_value(ExtensionId::BASIC_CONSTRAINTS, true, &BasicConstraints::ca(None))?,
///     Extension::with_value(ExtensionId::KEY_USAGE, true, &(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN))?,
/// ])?;
///
/// // The known extensions have typed accessors ...
/// let mut context = DecodingContext::new(DecodingOptions::default());
/// let usage = extensions.get_key_usage(&mut context)?.unwrap();
/// assert!(usage.contains(KeyUsage::KEY_CERT_SIGN));
/// assert!(extensions.get_extended_key_usage(&mut context)?.is_none());
///
/// // ... and anything can be looked up by OID.
/// let raw = extensions.get(ExtensionId::BASIC_CONSTRAINTS).unwrap();
/// assert!(raw.critical());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Extensions {
    extensions: Asn1SequenceOf<Extension>,
}

impl Extensions {
    /// An empty list or a repeated OID is `MalformedValue`.
    pub fn new(extensions: Vec<Extension>) -> Result<Self, Asn1Error> {
        Self::check(&extensions)?;
        Ok(Self {
            extensions: Asn1SequenceOf::new(extensions),
        })
    }

    fn check(extensions: &[Extension]) -> Result<(), Asn1Error> {
        if extensions.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        for (i, extension) in extensions.iter().enumerate() {
            if extensions[..i]
                .iter()
                .any(|earlier| earlier.extn_id() == extension.extn_id())
            {
                return Err(Asn1Error::MalformedValue);
            }
        }
        Ok(())
    }

    /// The extensions in wire order, never empty.
    pub fn extensions(&self) -> &[Extension] {
        self.extensions.elements()
    }

    /// The extension with this OID, if present; takes a `NamedOid` constant
    /// such as [`ExtensionId::KEY_USAGE`](ExtensionId::KEY_USAGE) or an `Asn1Oid`.
    /// Variable time; for public values.
    pub fn get(&self, extn_id: impl PartialEq<Asn1Oid>) -> Option<&Extension> {
        self.extensions()
            .iter()
            .find(|extension| extn_id == *extension.extn_id())
    }

    /// [`get`](Self::get) followed by [`Extension::extn_value_as`]: `None`
    /// when the extension is absent, an error when it is present but its
    /// value does not decode as `T`.
    pub fn get_as<T: DecodeInner>(
        &self,
        extn_id: impl PartialEq<Asn1Oid>,
        context: &mut DecodingContext,
    ) -> Result<Option<T>, Asn1Error> {
        self.get(extn_id)
            .map(|extension| extension.extn_value_as(context))
            .transpose()
    }

    /// [`get_as`](Self::get_as) for the keyUsage extension.
    pub fn get_key_usage(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<KeyUsage>, Asn1Error> {
        self.get_as(ExtensionId::KEY_USAGE, context)
    }

    /// [`get_as`](Self::get_as) for the basicConstraints extension.
    pub fn get_basic_constraints(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<BasicConstraints>, Asn1Error> {
        self.get_as(ExtensionId::BASIC_CONSTRAINTS, context)
    }

    /// [`get_as`](Self::get_as) for the extKeyUsage extension.
    pub fn get_extended_key_usage(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<ExtendedKeyUsage>, Asn1Error> {
        self.get_as(ExtensionId::EXT_KEY_USAGE, context)
    }

    /// [`get_as`](Self::get_as) for the subjectKeyIdentifier extension.
    pub fn get_subject_key_identifier(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<SubjectKeyIdentifier>, Asn1Error> {
        self.get_as(ExtensionId::SUBJECT_KEY_IDENTIFIER, context)
    }

    /// [`get_as`](Self::get_as) for the authorityKeyIdentifier extension.
    pub fn get_authority_key_identifier(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<AuthorityKeyIdentifier>, Asn1Error> {
        self.get_as(ExtensionId::AUTHORITY_KEY_IDENTIFIER, context)
    }

    /// [`get_as`](Self::get_as) for the subjectAltName extension, whose
    /// value is a plain `GeneralNames`.
    pub fn get_subject_alt_name(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<GeneralNames>, Asn1Error> {
        self.get_as(ExtensionId::SUBJECT_ALT_NAME, context)
    }

    /// [`get_as`](Self::get_as) for the issuerAltName extension.
    pub fn get_issuer_alt_name(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<GeneralNames>, Asn1Error> {
        self.get_as(ExtensionId::ISSUER_ALT_NAME, context)
    }

    /// [`get_as`](Self::get_as) for the nameConstraints extension.
    pub fn get_name_constraints(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<NameConstraints>, Asn1Error> {
        self.get_as(ExtensionId::NAME_CONSTRAINTS, context)
    }

    /// [`get_as`](Self::get_as) for the authorityInfoAccess extension.
    pub fn get_authority_info_access(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<InformationAccess>, Asn1Error> {
        self.get_as(ExtensionId::AUTHORITY_INFO_ACCESS, context)
    }

    /// [`get_as`](Self::get_as) for the subjectInfoAccess extension.
    pub fn get_subject_info_access(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<InformationAccess>, Asn1Error> {
        self.get_as(ExtensionId::SUBJECT_INFO_ACCESS, context)
    }

    /// [`get_as`](Self::get_as) for the PolicyMappings extension.
    pub fn get_policy_mappings(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<PolicyMappings>, Asn1Error> {
        self.get_as(ExtensionId::POLICY_MAPPINGS, context)
    }

    /// [`get_as`](Self::get_as) for the PolicyConstraints extension.
    pub fn get_policy_constraints(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<PolicyConstraints>, Asn1Error> {
        self.get_as(ExtensionId::POLICY_CONSTRAINTS, context)
    }

    /// [`get_as`](Self::get_as) for the InhibitAnyPolicy extension.
    pub fn get_inhibit_any_policy(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<InhibitAnyPolicy>, Asn1Error> {
        self.get_as(ExtensionId::INHIBIT_ANY_POLICY, context)
    }

    /// [`get_as`](Self::get_as) for the PrivateKeyUsagePeriod extension.
    pub fn get_private_key_usage_period(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<PrivateKeyUsagePeriod>, Asn1Error> {
        self.get_as(ExtensionId::PRIVATE_KEY_USAGE_PERIOD, context)
    }

    /// [`get_as`](Self::get_as) for the SubjectDirectoryAttributes extension.
    pub fn get_subject_directory_attributes(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<SubjectDirectoryAttributes>, Asn1Error> {
        self.get_as(ExtensionId::SUBJECT_DIRECTORY_ATTRIBUTES, context)
    }

    /// [`get_as`](Self::get_as) for the X.509 (2019) `SubjectAltPublicKeyInfo` extension.
    pub fn get_subject_alt_public_key_info(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<SubjectAltPublicKeyInfo>, Asn1Error> {
        self.get_as(ExtensionId::SUBJECT_ALT_PUBLIC_KEY_INFO, context)
    }

    /// [`get_as`](Self::get_as) for the X.509 (2019) `AltSignatureAlgorithm` extension.
    pub fn get_alt_signature_algorithm(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<AltSignatureAlgorithm>, Asn1Error> {
        self.get_as(ExtensionId::ALT_SIGNATURE_ALGORITHM, context)
    }

    /// [`get_as`](Self::get_as) for the X.509 (2019) `AltSignatureValue` extension.
    pub fn get_alt_signature_value(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<AltSignatureValue>, Asn1Error> {
        self.get_as(ExtensionId::ALT_SIGNATURE_VALUE, context)
    }

    /// [`get_as`](Self::get_as) for the CRL entry reasonCode extension.
    pub fn get_crl_reason(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<CrlReason>, Asn1Error> {
        self.get_as(ExtensionId::CRL_REASONS, context)
    }

    /// [`get_as`](Self::get_as) for the issuingDistributionPoint CRL extension.
    pub fn get_issuing_distribution_point(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<IssuingDistributionPoint>, Asn1Error> {
        self.get_as(ExtensionId::ISSUING_DISTRIBUTION_POINT, context)
    }

    /// [`get_as`](Self::get_as) for the certificatePolicies extension.
    pub fn get_certificate_policies(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<CertificatePolicies>, Asn1Error> {
        self.get_as(ExtensionId::CERTIFICATE_POLICIES, context)
    }

    /// [`get_as`](Self::get_as) for the cRLDistributionPoints extension.
    pub fn get_crl_distribution_points(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<CrlDistributionPoints>, Asn1Error> {
        self.get_as(ExtensionId::CRL_DISTRIBUTION_POINTS, context)
    }

    /// [`get_as`](Self::get_as) for the freshestCRL extension's delta CRL locations.
    pub fn get_freshest_crl(
        &self,
        context: &mut DecodingContext,
    ) -> Result<Option<CrlDistributionPoints>, Asn1Error> {
        self.get_as(ExtensionId::FRESHEST_CRL, context)
    }
}

impl DecodeContent for Extensions {
    /// The contents alone, for an `[n] IMPLICIT Extensions` field. An empty
    /// SEQUENCE or a repeated OID is `MalformedValue`. Variable time: branches
    /// only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let extensions = Asn1SequenceOf::<Extension>::decode_content(value, context)?;
        Self::check(extensions.elements())?;
        Ok(Self { extensions })
    }
}

impl DecodeInner for Extensions {
    /// An empty SEQUENCE or a repeated OID is `MalformedValue`. Variable
    /// time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, extensions) = Asn1SequenceOf::<Extension>::decode_inner(buff, context)?;
        Self::check(extensions.elements())?;
        Ok((used, Self { extensions }))
    }
}

impl Decode for Extensions {}

impl Tagged for Extensions {
    const TAG: &'static [u8] = Asn1SequenceOf::<Extension>::TAG;
}

impl EncodeContent for Extensions {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.extensions.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.extensions.encode_content(rules, out)
    }
}

impl EncodeTagged for Extensions {}

impl Encode for Extensions {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use tc_asn1::{Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};

    use super::Extensions;
    use crate::{
        ext::{
            AccessDescription, AccessMethod, BasicConstraints, ExtendedKeyUsage, Extension,
            ExtensionId, GeneralSubtree, GeneralSubtrees, InformationAccess, KeyUsage,
            NameConstraints,
        },
        name::{GeneralName, GeneralNames},
    };

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn crl_reason_and_scope_accessors_select_their_own_oids_and_propagate_decode_errors() {
        use crate::crl::{CrlReason, IssuingDistributionPoint};

        let scope = IssuingDistributionPoint::new(None, false, true, None, true, false).unwrap();
        let extensions = Extensions::new(Vec::from([
            Extension::with_value(ExtensionId::CRL_REASONS, false, &CrlReason::RemoveFromCrl)
                .unwrap(),
            Extension::with_value(ExtensionId::ISSUING_DISTRIBUTION_POINT, true, &scope).unwrap(),
        ]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_crl_reason(&mut context).unwrap(),
            Some(CrlReason::RemoveFromCrl)
        );
        assert_eq!(
            extensions
                .get_issuing_distribution_point(&mut context)
                .unwrap(),
            Some(scope)
        );
        let absent = ca_extensions();
        assert_eq!(absent.get_crl_reason(&mut context).unwrap(), None);
        assert_eq!(
            absent.get_issuing_distribution_point(&mut context).unwrap(),
            None
        );
        let malformed = Extensions::new(Vec::from([
            Extension::new(ExtensionId::CRL_REASONS, false, b"\x02\x01\x01"),
            Extension::new(ExtensionId::ISSUING_DISTRIBUTION_POINT, true, b"\x05\x00"),
        ]))
        .unwrap();
        assert_eq!(
            malformed.get_crl_reason(&mut context),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            malformed.get_issuing_distribution_point(&mut context),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn the_subject_alt_public_key_info_accessor_selects_its_oid_and_propagates_decode_errors() {
        use crate::ext::SubjectAltPublicKeyInfo;

        let expected = SubjectAltPublicKeyInfo::decode_der(
            b"\x30\x0b\x30\x05\x06\x03\x2b\x65\x70\x03\x02\x00\xaa",
            &options(),
        )
        .unwrap()
        .1;
        let extensions = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::SUBJECT_ALT_PUBLIC_KEY_INFO,
            false,
            &expected,
        )
        .unwrap()]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions
                .get_subject_alt_public_key_info(&mut context)
                .unwrap(),
            Some(expected)
        );
        assert_eq!(
            ca_extensions()
                .get_subject_alt_public_key_info(&mut context)
                .unwrap(),
            None
        );
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::SUBJECT_ALT_PUBLIC_KEY_INFO,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert_eq!(
            malformed.get_subject_alt_public_key_info(&mut context),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn the_alt_signature_algorithm_accessor_selects_its_oid_and_propagates_decode_errors() {
        use crate::ext::AltSignatureAlgorithm;

        let expected =
            AltSignatureAlgorithm::decode_der(b"\x30\x07\x06\x03\x2b\x65\x70\x05\x00", &options())
                .unwrap()
                .1;
        let extensions = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::ALT_SIGNATURE_ALGORITHM,
            false,
            &expected,
        )
        .unwrap()]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions
                .get_alt_signature_algorithm(&mut context)
                .unwrap(),
            Some(expected)
        );
        assert_eq!(
            ca_extensions()
                .get_alt_signature_algorithm(&mut context)
                .unwrap(),
            None
        );
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::ALT_SIGNATURE_ALGORITHM,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert_eq!(
            malformed.get_alt_signature_algorithm(&mut context),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn the_alt_signature_value_accessor_selects_its_oid_and_propagates_decode_errors() {
        use crate::ext::AltSignatureValue;

        let expected = AltSignatureValue::decode_der(b"\x03\x02\x00\xaa", &options())
            .unwrap()
            .1;
        let extensions = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::ALT_SIGNATURE_VALUE,
            false,
            &expected,
        )
        .unwrap()]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_alt_signature_value(&mut context).unwrap(),
            Some(expected)
        );
        assert_eq!(
            ca_extensions()
                .get_alt_signature_value(&mut context)
                .unwrap(),
            None
        );
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::ALT_SIGNATURE_VALUE,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert_eq!(
            malformed.get_alt_signature_value(&mut context),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    fn ca_extensions() -> Extensions {
        Extensions::new(Vec::from([
            Extension::new(
                ExtensionId::BASIC_CONSTRAINTS,
                true,
                &BasicConstraints::ca(Some(0)).encode_to_vec(&der()).unwrap(),
            ),
            Extension::new(
                ExtensionId::KEY_USAGE,
                true,
                &(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
                    .encode_to_vec(&der())
                    .unwrap(),
            ),
        ]))
        .unwrap()
    }

    /// basicConstraints { cA, pathLen 0 } critical, keyUsage { keyCertSign, cRLSign } critical.
    const CA: &[u8] = b"\x30\x24\
        \x30\x12\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x08\x30\x06\x01\x01\xff\x02\x01\x00\
        \x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x06";

    #[test]
    fn the_policy_mappings_accessor_decodes_and_reports_absence() {
        let wire = b"\x30\x0a\x30\x08\x06\x02\x2a\x03\x06\x02\x2a\x04";
        let expected = crate::ext::PolicyMappings::decode_der(wire, &options())
            .unwrap()
            .1;
        let extensions = Extensions::new(Vec::from([Extension::new(
            ExtensionId::POLICY_MAPPINGS,
            false,
            wire,
        )]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_policy_mappings(&mut context).unwrap(),
            Some(expected)
        );
        let absent = Extensions::new(Vec::from([Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            b"\x03\x02\x07\x80",
        )]))
        .unwrap();
        assert_eq!(absent.get_policy_mappings(&mut context).unwrap(), None);
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::POLICY_MAPPINGS,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert!(matches!(
            malformed.get_policy_mappings(&mut context),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn the_policy_constraints_accessor_decodes_and_reports_absence() {
        let wire = b"\x30\x03\x80\x01\x00";
        let expected = crate::ext::PolicyConstraints::decode_der(wire, &options())
            .unwrap()
            .1;
        let extensions = Extensions::new(Vec::from([Extension::new(
            ExtensionId::POLICY_CONSTRAINTS,
            false,
            wire,
        )]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_policy_constraints(&mut context).unwrap(),
            Some(expected)
        );
        let absent = Extensions::new(Vec::from([Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            b"\x03\x02\x07\x80",
        )]))
        .unwrap();
        assert_eq!(absent.get_policy_constraints(&mut context).unwrap(), None);
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::POLICY_CONSTRAINTS,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert!(matches!(
            malformed.get_policy_constraints(&mut context),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn the_inhibit_any_policy_accessor_decodes_and_reports_absence() {
        let wire = b"\x02\x01\x00";
        let expected = crate::ext::InhibitAnyPolicy::decode_der(wire, &options())
            .unwrap()
            .1;
        let extensions = Extensions::new(Vec::from([Extension::new(
            ExtensionId::INHIBIT_ANY_POLICY,
            false,
            wire,
        )]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_inhibit_any_policy(&mut context).unwrap(),
            Some(expected)
        );
        let absent = Extensions::new(Vec::from([Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            b"\x03\x02\x07\x80",
        )]))
        .unwrap();
        assert_eq!(absent.get_inhibit_any_policy(&mut context).unwrap(), None);
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::INHIBIT_ANY_POLICY,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert!(matches!(
            malformed.get_inhibit_any_policy(&mut context),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn the_private_key_usage_period_accessor_decodes_and_reports_absence() {
        let wire = b"\x30\x11\x80\x0f20300101000000Z";
        let expected = crate::ext::PrivateKeyUsagePeriod::decode_der(wire, &options())
            .unwrap()
            .1;
        let extensions = Extensions::new(Vec::from([Extension::new(
            ExtensionId::PRIVATE_KEY_USAGE_PERIOD,
            false,
            wire,
        )]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions
                .get_private_key_usage_period(&mut context)
                .unwrap(),
            Some(expected)
        );
        let absent = Extensions::new(Vec::from([Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            b"\x03\x02\x07\x80",
        )]))
        .unwrap();
        assert_eq!(
            absent.get_private_key_usage_period(&mut context).unwrap(),
            None
        );
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::PRIVATE_KEY_USAGE_PERIOD,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert!(matches!(
            malformed.get_private_key_usage_period(&mut context),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn the_subject_directory_attributes_accessor_decodes_and_reports_absence() {
        let wire = b"\x30\x0b\x30\x09\x06\x02\x2a\x03\x31\x03\x02\x01\x01";
        let expected = crate::ext::SubjectDirectoryAttributes::decode_der(wire, &options())
            .unwrap()
            .1;
        let extensions = Extensions::new(Vec::from([Extension::new(
            ExtensionId::SUBJECT_DIRECTORY_ATTRIBUTES,
            false,
            wire,
        )]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions
                .get_subject_directory_attributes(&mut context)
                .unwrap(),
            Some(expected)
        );
        let absent = Extensions::new(Vec::from([Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            b"\x03\x02\x07\x80",
        )]))
        .unwrap();
        assert_eq!(
            absent
                .get_subject_directory_attributes(&mut context)
                .unwrap(),
            None
        );
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::SUBJECT_DIRECTORY_ATTRIBUTES,
            false,
            b"\x05\x00",
        )]))
        .unwrap();
        assert!(matches!(
            malformed.get_subject_directory_attributes(&mut context),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn extensions_round_trip_in_order() {
        let extensions = ca_extensions();
        assert_eq!(extensions.encode_to_vec(&der()).unwrap(), CA);
        let (used, decoded) = Extensions::decode(CA, &options()).unwrap();
        assert_eq!((used, &decoded), (CA.len(), &extensions));
        assert_eq!(
            decoded.extensions()[0].extn_id(),
            &ExtensionId::BASIC_CONSTRAINTS.oid()
        );
        assert_eq!(
            decoded.extensions()[1].extn_id(),
            &ExtensionId::KEY_USAGE.oid()
        );
    }

    #[test]
    fn lookup_by_oid_finds_decodes_or_says_absent() {
        let (_, extensions) = Extensions::decode(CA, &options()).unwrap();
        let mut context = DecodingContext::new(options());
        assert!(extensions.get(ExtensionId::KEY_USAGE).unwrap().critical());
        assert!(extensions.get(ExtensionId::EXT_KEY_USAGE).is_none());
        assert!(
            extensions
                .get("2.5.29.15".parse::<tc_asn1::Asn1Oid>().unwrap())
                .is_some()
        );

        let usage: KeyUsage = extensions
            .get_as(ExtensionId::KEY_USAGE, &mut context)
            .unwrap()
            .unwrap();
        assert_eq!(usage, KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN);
        let bc: BasicConstraints = extensions
            .get_as(ExtensionId::BASIC_CONSTRAINTS, &mut context)
            .unwrap()
            .unwrap();
        assert_eq!(bc.path_len_constraint(), Some(0));
        assert!(
            extensions
                .get_as::<ExtendedKeyUsage>(ExtensionId::EXT_KEY_USAGE, &mut context)
                .unwrap()
                .is_none()
        );
        // present, but the value is not what was asked for
        assert!(
            extensions
                .get_as::<KeyUsage>(ExtensionId::BASIC_CONSTRAINTS, &mut context)
                .is_err()
        );
    }

    #[test]
    fn the_typed_accessors_return_the_present_extensions_and_none_for_absent_ones() {
        let (_, extensions) = Extensions::decode(CA, &options()).unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_key_usage(&mut context).unwrap(),
            Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
        );
        assert_eq!(
            extensions.get_basic_constraints(&mut context).unwrap(),
            Some(BasicConstraints::ca(Some(0)))
        );
        assert_eq!(
            extensions.get_extended_key_usage(&mut context).unwrap(),
            None
        );
    }

    #[test]
    fn the_alt_name_accessors_return_general_names() {
        let san = GeneralNames::new(Vec::from([
            GeneralName::dns_name("x.tw").unwrap(),
            GeneralName::rfc822_name("a@x.tw").unwrap(),
        ]))
        .unwrap();
        let extensions = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::SUBJECT_ALT_NAME,
            false,
            &san,
        )
        .unwrap()]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_subject_alt_name(&mut context).unwrap(),
            Some(san)
        );
        assert_eq!(extensions.get_issuer_alt_name(&mut context).unwrap(), None);
    }

    #[test]
    fn the_name_constraints_accessor_returns_the_typed_value() {
        let constraints = NameConstraints::permitted(
            GeneralSubtrees::new(Vec::from([GeneralSubtree::new(
                GeneralName::dns_name("x.tw").unwrap(),
            )
            .unwrap()]))
            .unwrap(),
        );
        let extensions = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::NAME_CONSTRAINTS,
            true,
            &constraints,
        )
        .unwrap()]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_name_constraints(&mut context).unwrap(),
            Some(constraints)
        );
    }

    #[test]
    fn the_information_accessors_return_their_typed_values() {
        let aia = InformationAccess::new(Vec::from([AccessDescription::new(
            AccessMethod::OCSP,
            GeneralName::uri("http://ocsp.x.tw").unwrap(),
        )]))
        .unwrap();
        let sia = InformationAccess::new(Vec::from([AccessDescription::new(
            AccessMethod::CA_REPOSITORY,
            GeneralName::uri("http://repo.x.tw").unwrap(),
        )]))
        .unwrap();
        let extensions = Extensions::new(Vec::from([
            Extension::with_value(ExtensionId::AUTHORITY_INFO_ACCESS, false, &aia).unwrap(),
            Extension::with_value(ExtensionId::SUBJECT_INFO_ACCESS, false, &sia).unwrap(),
        ]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_authority_info_access(&mut context).unwrap(),
            Some(aia)
        );
        assert_eq!(
            extensions.get_subject_info_access(&mut context).unwrap(),
            Some(sia)
        );
    }

    #[test]
    fn an_empty_list_and_a_repeated_oid_are_rejected_when_built_or_decoded() {
        assert!(matches!(
            Extensions::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            Extensions::decode(b"\x30\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
        let usage = Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            &KeyUsage::DIGITAL_SIGNATURE.encode_to_vec(&der()).unwrap(),
        );
        assert!(matches!(
            Extensions::new(Vec::from([usage.clone(), usage.clone()])),
            Err(Asn1Error::MalformedValue)
        ));
        let mut twice: Vec<u8> = CA.to_vec();
        twice.extend_from_slice(&CA[22..]); // the keyUsage extension again
        twice[1] += 16;
        assert!(matches!(
            Extensions::decode(&twice, &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn anything_but_extensions_in_a_sequence_is_rejected() {
        let mut as_set: Vec<u8> = CA.to_vec();
        as_set[0] = 0x31;
        assert!(matches!(
            Extensions::decode(&as_set, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Extensions::decode(b"\x30\x03\x02\x01\x01", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn the_certificate_policies_accessor_decodes_and_reports_absence() {
        use crate::ext::{CertificatePolicies, PolicyInformation};

        let policies = CertificatePolicies::new(Vec::from([PolicyInformation::new(
            PolicyInformation::ANY_POLICY,
        )]))
        .unwrap();
        let extensions = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::CERTIFICATE_POLICIES,
            false,
            &policies,
        )
        .unwrap()]))
        .unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            extensions.get_certificate_policies(&mut context).unwrap(),
            Some(policies)
        );
        let absent = Extensions::new(Vec::from([Extension::new(
            ExtensionId::KEY_USAGE,
            false,
            b"\x03\x02\x07\x80",
        )]))
        .unwrap();
        assert_eq!(absent.get_certificate_policies(&mut context).unwrap(), None);
        let malformed = Extensions::new(Vec::from([Extension::new(
            ExtensionId::CERTIFICATE_POLICIES,
            false,
            b"\x30\x00",
        )]))
        .unwrap();
        assert!(matches!(
            malformed.get_certificate_policies(&mut context),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn the_extension_accessors_select_their_own_oid_and_report_absence() {
        use crate::crl::{CrlDistributionPoints, DistributionPoint};

        let point = |dns: &str| {
            DistributionPoint::new(
                Some(
                    GeneralNames::new(Vec::from([GeneralName::dns_name(dns).unwrap()]))
                        .unwrap()
                        .into(),
                ),
                None,
                None,
            )
            .unwrap()
        };
        let base = CrlDistributionPoints::new(Vec::from([point("base")])).unwrap();
        let delta = CrlDistributionPoints::new(Vec::from([point("delta")])).unwrap();
        let mut context = DecodingContext::new(DecodingOptions::default());
        let extensions = Extensions::new(Vec::from([
            Extension::with_value(ExtensionId::CRL_DISTRIBUTION_POINTS, false, &base).unwrap(),
            Extension::with_value(ExtensionId::FRESHEST_CRL, false, &delta).unwrap(),
        ]))
        .unwrap();
        assert_eq!(
            extensions
                .get_crl_distribution_points(&mut context)
                .unwrap(),
            Some(base.clone())
        );
        assert_eq!(
            extensions.get_freshest_crl(&mut context).unwrap(),
            Some(delta.clone())
        );
        let base_only = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::CRL_DISTRIBUTION_POINTS,
            false,
            &base,
        )
        .unwrap()]))
        .unwrap();
        assert_eq!(base_only.get_freshest_crl(&mut context).unwrap(), None);
        let delta_only = Extensions::new(Vec::from([Extension::with_value(
            ExtensionId::FRESHEST_CRL,
            false,
            &delta,
        )
        .unwrap()]))
        .unwrap();
        assert_eq!(
            delta_only
                .get_crl_distribution_points(&mut context)
                .unwrap(),
            None
        );
    }
}
