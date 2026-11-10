//! The OIDs of the German Signature Interoperability specification (SigI,
//! now part of Common PKI), under `id-sigi` (1.3.36.8).
//!
//! The arcs hold different kinds of identifier: a key purpose under
//! `id-sigi-kp`, a certificate policy under `id-sigi-cp` and an `OtherName`
//! type under `id-sigi-on`. As in Bouncy Castle they are kept in one table.

use tc_asn1::{Asn1Oid, NamedOid};

/// The known SigI OIDs, as [`NamedOid`] constants with a lookup.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::sigi::SigiId;
///
/// assert_eq!(SigiId::PERSONAL_DATA.oid().to_string(), "1.3.36.8.4.1");
/// assert_eq!(SigiId::from_oid(&"1.3.36.8.1.1".parse()?), Some(SigiId::SIG_CONFORM));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct SigiId;

impl SigiId {
    /// Certificate policy: the certificate conforms to the German signature law.
    pub const SIG_CONFORM: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x01, 0x01],
        "1.3.36.8.1.1",
        "sigConform",
    );
    /// Key purpose: generating directory service certificates.
    pub const DIRECTORY_SERVICE: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x02, 0x01],
        "1.3.36.8.2.1",
        "directoryService",
    );
    /// `OtherName` type whose value is a `PersonalData`.
    pub const PERSONAL_DATA: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x04, 0x01],
        "1.3.36.8.4.1",
        "personalData",
    );

    /// Every known OID, for lookups.
    pub const ALL: &'static [NamedOid] = &[
        Self::SIG_CONFORM,
        Self::DIRECTORY_SERVICE,
        Self::PERSONAL_DATA,
    ];

    /// The known OID equal to this one, if any. Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::SigiId;

    #[test]
    fn every_entry_encodes_its_dotted_form_and_looks_up() {
        for entry in SigiId::ALL {
            let parsed: tc_asn1::Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(parsed, entry.oid(), "{}", entry.dotted());
            assert_eq!(entry.oid().to_string(), entry.dotted());
            assert_eq!(SigiId::from_oid(&entry.oid()), Some(*entry));
        }
        assert_eq!(SigiId::from_oid(&"1.3.36.8".parse().unwrap()), None);
    }

    #[test]
    fn entries_are_unique() {
        for (i, a) in SigiId::ALL.iter().enumerate() {
            for b in &SigiId::ALL[i + 1..] {
                assert_ne!(a.oid(), b.oid());
                assert_ne!(a.name(), b.name());
            }
        }
    }
}
