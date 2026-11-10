//! The OIDs that identify certificate and CRL extensions.
//!
//! RFC 5280 §4.2 defines the standard ones under `id-ce` (2.5.29) and the
//! private ones under `id-pe` (1.3.6.1.5.5.7.1); the rest come from the
//! documents named on each constant. An extension's OID lives here rather
//! than on the value type because some value types serve several OIDs
//! (`GeneralNames` for both alternative names, one distribution point list
//! for cRLDistributionPoints and freshestCRL).

use tc_asn1::{Asn1Oid, NamedOid};

/// The known extension OIDs, as [`NamedOid`] constants with a lookup.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::ext::ExtensionId;
///
/// assert_eq!(ExtensionId::KEY_USAGE.name(), "keyUsage");
/// assert_eq!(ExtensionId::KEY_USAGE.oid().to_string(), "2.5.29.15");
/// assert_eq!(ExtensionId::from_oid(&"2.5.29.19".parse()?), Some(ExtensionId::BASIC_CONSTRAINTS));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct ExtensionId;

impl ExtensionId {
    /// RFC 5280 §4.2.1.8: attributes of the subject.
    pub const SUBJECT_DIRECTORY_ATTRIBUTES: NamedOid = NamedOid::new(
        &[0x55, 0x1d, 0x09],
        "2.5.29.9",
        "subjectDirectoryAttributes",
    );
    /// RFC 5280 §4.2.1.2: identifies the subject's key.
    pub const SUBJECT_KEY_IDENTIFIER: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x0e], "2.5.29.14", "subjectKeyIdentifier");
    /// RFC 5280 §4.2.1.3: what the key may be used for.
    pub const KEY_USAGE: NamedOid = NamedOid::new(&[0x55, 0x1d, 0x0f], "2.5.29.15", "keyUsage");
    /// The period the private key may be used; RFC 5280 advises against it.
    pub const PRIVATE_KEY_USAGE_PERIOD: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x10], "2.5.29.16", "privateKeyUsagePeriod");
    /// RFC 5280 §4.2.1.6: other names of the subject.
    pub const SUBJECT_ALT_NAME: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x11], "2.5.29.17", "subjectAltName");
    /// RFC 5280 §4.2.1.7: other names of the issuer.
    pub const ISSUER_ALT_NAME: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x12], "2.5.29.18", "issuerAltName");
    /// RFC 5280 §4.2.1.9: whether the subject is a CA, and its path length.
    pub const BASIC_CONSTRAINTS: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x13], "2.5.29.19", "basicConstraints");
    /// CRL extension.
    pub const CRL_NUMBER: NamedOid = NamedOid::new(&[0x55, 0x1d, 0x14], "2.5.29.20", "cRLNumber");
    /// CRL entry extension.
    pub const CRL_REASONS: NamedOid = NamedOid::new(&[0x55, 0x1d, 0x15], "2.5.29.21", "cRLReasons");
    /// CRL entry extension; deprecated by RFC 5280.
    pub const HOLD_INSTRUCTION_CODE: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x17], "2.5.29.23", "holdInstructionCode");
    /// CRL entry extension.
    pub const INVALIDITY_DATE: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x18], "2.5.29.24", "invalidityDate");
    /// CRL extension.
    pub const DELTA_CRL_INDICATOR: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x1b], "2.5.29.27", "deltaCRLIndicator");
    /// CRL extension.
    pub const ISSUING_DISTRIBUTION_POINT: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x1c], "2.5.29.28", "issuingDistributionPoint");
    /// CRL entry extension.
    pub const CERTIFICATE_ISSUER: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x1d], "2.5.29.29", "certificateIssuer");
    /// RFC 5280 §4.2.1.10: the names a CA may issue for.
    pub const NAME_CONSTRAINTS: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x1e], "2.5.29.30", "nameConstraints");
    /// RFC 5280 §4.2.1.13: where to fetch the CRL.
    pub const CRL_DISTRIBUTION_POINTS: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x1f], "2.5.29.31", "cRLDistributionPoints");
    /// RFC 5280 §4.2.1.4: the policies the certificate was issued under.
    pub const CERTIFICATE_POLICIES: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x20], "2.5.29.32", "certificatePolicies");
    /// RFC 5280 §4.2.1.5: the equivalence of policies between domains.
    pub const POLICY_MAPPINGS: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x21], "2.5.29.33", "policyMappings");
    /// RFC 5280 §4.2.1.1: identifies the issuer's key; also a CRL extension.
    pub const AUTHORITY_KEY_IDENTIFIER: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x23], "2.5.29.35", "authorityKeyIdentifier");
    /// RFC 5280 §4.2.1.11: constraints on policy mapping and validation.
    pub const POLICY_CONSTRAINTS: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x24], "2.5.29.36", "policyConstraints");
    /// RFC 5280 §4.2.1.12: the purposes the key may be used for.
    pub const EXT_KEY_USAGE: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x25], "2.5.29.37", "extKeyUsage");
    /// Same value type as cRLDistributionPoints.
    pub const FRESHEST_CRL: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x2e], "2.5.29.46", "freshestCRL");
    /// RFC 5280 §4.2.1.14: when `anyPolicy` stops matching.
    pub const INHIBIT_ANY_POLICY: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x36], "2.5.29.54", "inhibitAnyPolicy");
    /// RFC 5755 attribute certificates.
    pub const TARGET_INFORMATION: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x37], "2.5.29.55", "targetInformation");
    /// RFC 5755; for public-key certificates per RFC 9608.
    pub const NO_REV_AVAIL: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x38], "2.5.29.56", "noRevAvail");
    /// CRL extension, X.509 (2005).
    pub const EXPIRED_CERTS_ON_CRL: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x3c], "2.5.29.60", "expiredCertsOnCRL");
    /// X.509 (2019) alternative signatures.
    pub const SUBJECT_ALT_PUBLIC_KEY_INFO: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x48], "2.5.29.72", "subjectAltPublicKeyInfo");
    /// X.509 (2019) alternative signatures.
    pub const ALT_SIGNATURE_ALGORITHM: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x49], "2.5.29.73", "altSignatureAlgorithm");
    /// X.509 (2019) alternative signatures.
    pub const ALT_SIGNATURE_VALUE: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x4a], "2.5.29.74", "altSignatureValue");
    /// RFC 5280 §4.2.2.1, private extension.
    pub const AUTHORITY_INFO_ACCESS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01],
        "1.3.6.1.5.5.7.1.1",
        "authorityInfoAccess",
    );
    /// RFC 3739.
    pub const BIOMETRIC_INFO: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x02],
        "1.3.6.1.5.5.7.1.2",
        "biometricInfo",
    );
    /// RFC 3739.
    pub const QC_STATEMENTS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03],
        "1.3.6.1.5.5.7.1.3",
        "qcStatements",
    );
    /// RFC 5755.
    pub const AUDIT_IDENTITY: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x04],
        "1.3.6.1.5.5.7.1.4",
        "auditIdentity",
    );
    /// RFC 5280 §4.2.2.2; same value type as authorityInfoAccess.
    pub const SUBJECT_INFO_ACCESS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0b],
        "1.3.6.1.5.5.7.1.11",
        "subjectInfoAccess",
    );
    /// RFC 3709.
    pub const LOGOTYPE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0c],
        "1.3.6.1.5.5.7.1.12",
        "logotype",
    );
    /// RFC 9763.
    pub const RELATED_CERTIFICATE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x24],
        "1.3.6.1.5.5.7.1.36",
        "relatedCertificate",
    );

    /// Every known extension, for lookups.
    pub const ALL: &'static [NamedOid] = &[
        Self::SUBJECT_DIRECTORY_ATTRIBUTES,
        Self::SUBJECT_KEY_IDENTIFIER,
        Self::KEY_USAGE,
        Self::PRIVATE_KEY_USAGE_PERIOD,
        Self::SUBJECT_ALT_NAME,
        Self::ISSUER_ALT_NAME,
        Self::BASIC_CONSTRAINTS,
        Self::CRL_NUMBER,
        Self::CRL_REASONS,
        Self::HOLD_INSTRUCTION_CODE,
        Self::INVALIDITY_DATE,
        Self::DELTA_CRL_INDICATOR,
        Self::ISSUING_DISTRIBUTION_POINT,
        Self::CERTIFICATE_ISSUER,
        Self::NAME_CONSTRAINTS,
        Self::CRL_DISTRIBUTION_POINTS,
        Self::CERTIFICATE_POLICIES,
        Self::POLICY_MAPPINGS,
        Self::AUTHORITY_KEY_IDENTIFIER,
        Self::POLICY_CONSTRAINTS,
        Self::EXT_KEY_USAGE,
        Self::FRESHEST_CRL,
        Self::INHIBIT_ANY_POLICY,
        Self::TARGET_INFORMATION,
        Self::NO_REV_AVAIL,
        Self::EXPIRED_CERTS_ON_CRL,
        Self::SUBJECT_ALT_PUBLIC_KEY_INFO,
        Self::ALT_SIGNATURE_ALGORITHM,
        Self::ALT_SIGNATURE_VALUE,
        Self::AUTHORITY_INFO_ACCESS,
        Self::BIOMETRIC_INFO,
        Self::QC_STATEMENTS,
        Self::AUDIT_IDENTITY,
        Self::SUBJECT_INFO_ACCESS,
        Self::LOGOTYPE,
        Self::RELATED_CERTIFICATE,
    ];

    /// The known extension with this OID, if any. Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::ExtensionId;

    #[test]
    fn every_entry_encodes_its_dotted_form_and_looks_up() {
        for extension in ExtensionId::ALL {
            let parsed: tc_asn1::Asn1Oid = extension.dotted().parse().unwrap();
            assert_eq!(parsed, extension.oid(), "{}", extension.dotted());
            assert_eq!(extension.oid().to_string(), extension.dotted());
            assert_eq!(ExtensionId::from_oid(&extension.oid()), Some(*extension));
        }
        assert_eq!(ExtensionId::from_oid(&"1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn entries_are_unique() {
        for (i, a) in ExtensionId::ALL.iter().enumerate() {
            for b in &ExtensionId::ALL[i + 1..] {
                assert_ne!(a.oid(), b.oid());
                assert_ne!(a.name(), b.name());
            }
        }
    }
}
