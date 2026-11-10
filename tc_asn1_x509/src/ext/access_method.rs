//! The known access method OIDs used by [`AccessDescription`](crate::ext::AccessDescription).
//!
//! RFC 5280 defines OCSP and CA issuers and carries forward the time-stamping
//! and CA repository methods. An `AccessDescription` may contain other OIDs;
//! this table only supplies names for these standard methods.

use tc_asn1::{Asn1Oid, NamedOid};

/// The standard PKIX access methods, as [`NamedOid`] constants with a lookup.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::ext::AccessMethod;
///
/// assert_eq!(AccessMethod::OCSP.name(), "OCSP");
/// assert_eq!(AccessMethod::CA_ISSUERS.oid().to_string(), "1.3.6.1.5.5.7.48.2");
/// assert_eq!(
///     AccessMethod::from_oid(&"1.3.6.1.5.5.7.48.5".parse()?),
///     Some(AccessMethod::CA_REPOSITORY),
/// );
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct AccessMethod;

impl AccessMethod {
    /// RFC 5280: Online Certificate Status Protocol responder.
    pub const OCSP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01],
        "1.3.6.1.5.5.7.48.1",
        "OCSP",
    );
    /// RFC 5280: certificates issued to the certificate issuer.
    pub const CA_ISSUERS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02],
        "1.3.6.1.5.5.7.48.2",
        "caIssuers",
    );
    /// RFC 3161: time-stamping service.
    pub const TIME_STAMPING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x03],
        "1.3.6.1.5.5.7.48.3",
        "timeStamping",
    );
    /// RFC 5280: repository maintained by a CA.
    pub const CA_REPOSITORY: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05],
        "1.3.6.1.5.5.7.48.5",
        "caRepository",
    );

    /// Every method named by this table, for lookups.
    pub const ALL: &'static [NamedOid] = &[
        Self::OCSP,
        Self::CA_ISSUERS,
        Self::TIME_STAMPING,
        Self::CA_REPOSITORY,
    ];

    /// The known access method with this OID, if any. Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::AccessMethod;

    #[test]
    fn every_entry_encodes_its_dotted_form_and_looks_up() {
        for method in AccessMethod::ALL {
            let parsed: tc_asn1::Asn1Oid = method.dotted().parse().unwrap();
            assert_eq!(parsed, method.oid(), "{}", method.dotted());
            assert_eq!(method.oid().to_string(), method.dotted());
            assert_eq!(AccessMethod::from_oid(&method.oid()), Some(*method));
        }
        assert_eq!(AccessMethod::from_oid(&"1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn entries_are_unique() {
        for (i, a) in AccessMethod::ALL.iter().enumerate() {
            for b in &AccessMethod::ALL[i + 1..] {
                assert_ne!(a.oid(), b.oid());
                assert_ne!(a.name(), b.name());
            }
        }
    }
}
