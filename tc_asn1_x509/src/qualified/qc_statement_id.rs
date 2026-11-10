//! The OIDs that identify qualified certificate statements.
//!
//! RFC 3739 §3.2.6 defines the two `id-qcs` (1.3.6.1.5.5.7.11) semantics
//! identifiers; ETSI EN 319 412-5 defines the `id-etsi-qcs` (0.4.0.1862.1)
//! statements. The set follows Bouncy Castle.

use tc_asn1::{Asn1Oid, NamedOid};

/// The known statement OIDs, as [`NamedOid`] constants with a lookup.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::qualified::QcStatementId;
///
/// assert_eq!(QcStatementId::QC_COMPLIANCE.oid().to_string(), "0.4.0.1862.1.1");
/// assert_eq!(
///     QcStatementId::from_oid(&"1.3.6.1.5.5.7.11.2".parse()?),
///     Some(QcStatementId::PKIX_QC_SYNTAX_V2)
/// );
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct QcStatementId;

impl QcStatementId {
    /// RFC 3739; superseded by v2. Info is a `SemanticsInformation`.
    pub const PKIX_QC_SYNTAX_V1: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0b, 0x01],
        "1.3.6.1.5.5.7.11.1",
        "pkixQCSyntax-v1",
    );
    /// RFC 3739. Info is a `SemanticsInformation`.
    pub const PKIX_QC_SYNTAX_V2: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0b, 0x02],
        "1.3.6.1.5.5.7.11.2",
        "pkixQCSyntax-v2",
    );
    /// ETSI: the certificate is an EU qualified certificate; no info.
    pub const QC_COMPLIANCE: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x8e, 0x46, 0x01, 0x01],
        "0.4.0.1862.1.1",
        "QcCompliance",
    );
    /// ETSI: a transaction limit. Info is a `MonetaryValue`.
    pub const QC_LIMIT_VALUE: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x8e, 0x46, 0x01, 0x02],
        "0.4.0.1862.1.2",
        "QcLimitValue",
    );
    /// ETSI: years the registration data is kept. Info is an INTEGER.
    pub const QC_RETENTION_PERIOD: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x8e, 0x46, 0x01, 0x03],
        "0.4.0.1862.1.3",
        "QcRetentionPeriod",
    );
    /// ETSI: the private key lives in a secure signature creation device; no info.
    pub const QC_SSCD: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x8e, 0x46, 0x01, 0x04],
        "0.4.0.1862.1.4",
        "QcSSCD",
    );
    /// ETSI: the legislations the certificate is qualified under.
    pub const QC_CC_LEGISLATION: NamedOid = NamedOid::new(
        &[0x04, 0x00, 0x8e, 0x46, 0x01, 0x07],
        "0.4.0.1862.1.7",
        "QcCClegislation",
    );

    /// Every known statement, for lookups.
    pub const ALL: &'static [NamedOid] = &[
        Self::PKIX_QC_SYNTAX_V1,
        Self::PKIX_QC_SYNTAX_V2,
        Self::QC_COMPLIANCE,
        Self::QC_LIMIT_VALUE,
        Self::QC_RETENTION_PERIOD,
        Self::QC_SSCD,
        Self::QC_CC_LEGISLATION,
    ];

    /// The known statement with this OID, if any. Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::QcStatementId;

    #[test]
    fn every_entry_encodes_its_dotted_form_and_looks_up() {
        for statement in QcStatementId::ALL {
            let parsed: tc_asn1::Asn1Oid = statement.dotted().parse().unwrap();
            assert_eq!(parsed, statement.oid(), "{}", statement.dotted());
            assert_eq!(statement.oid().to_string(), statement.dotted());
            assert_eq!(QcStatementId::from_oid(&statement.oid()), Some(*statement));
        }
        assert_eq!(
            QcStatementId::from_oid(&"0.4.0.1862.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn entries_are_unique() {
        for (i, a) in QcStatementId::ALL.iter().enumerate() {
            for b in &QcStatementId::ALL[i + 1..] {
                assert_ne!(a.oid(), b.oid());
                assert_ne!(a.name(), b.name());
            }
        }
    }
}
