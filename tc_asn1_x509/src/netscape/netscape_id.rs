//! Netscape certificate extension identifiers, as Bouncy Castle's
//! `MiscObjectIdentifiers` names them.
//!
//! This table names known extensions without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// The Netscape certificate extensions.
///
/// ```
/// use tc_asn1_x509::netscape::NetscapeId;
///
/// assert_eq!(NetscapeId::CERT_TYPE.dotted(), "2.16.840.1.113730.1.1");
/// assert_eq!(
///     NetscapeId::from_oid(&NetscapeId::NETSCAPE.oid()),
///     Some(NetscapeId::NETSCAPE),
/// );
/// ```
pub struct NetscapeId;

impl NetscapeId {
    /// The arc of Netscape certificate extensions.
    pub const NETSCAPE: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01],
        "2.16.840.1.113730.1",
        "netscape-cert-extension",
    );

    /// A `NetscapeCertType`.
    pub const CERT_TYPE: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01],
        "2.16.840.1.113730.1.1",
        "netscape-cert-type",
    );

    /// The base of the relative URLs below.
    pub const BASE_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x02],
        "2.16.840.1.113730.1.2",
        "netscape-base-url",
    );

    /// A `NetscapeRevocationUrl`.
    pub const REVOCATION_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x03],
        "2.16.840.1.113730.1.3",
        "netscape-revocation-url",
    );

    /// Where to check a CA certificate.
    pub const CA_REVOCATION_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x04],
        "2.16.840.1.113730.1.4",
        "netscape-ca-revocation-url",
    );

    /// Where to renew the certificate.
    pub const RENEWAL_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x07],
        "2.16.840.1.113730.1.7",
        "netscape-cert-renewal-url",
    );

    /// The CA's policy.
    pub const CA_POLICY_URL: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x08],
        "2.16.840.1.113730.1.8",
        "netscape-ca-policy-url",
    );

    /// A host name pattern for the server.
    pub const SSL_SERVER_NAME: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0c],
        "2.16.840.1.113730.1.12",
        "netscape-ssl-server-name",
    );

    /// A comment to show the user.
    pub const CERT_COMMENT: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0d],
        "2.16.840.1.113730.1.13",
        "netscape-comment",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::NETSCAPE,
        Self::CERT_TYPE,
        Self::BASE_URL,
        Self::REVOCATION_URL,
        Self::CA_REVOCATION_URL,
        Self::RENEWAL_URL,
        Self::CA_POLICY_URL,
        Self::SSL_SERVER_NAME,
        Self::CERT_COMMENT,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
