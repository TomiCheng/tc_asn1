//! `KeyPurposeId`, the OIDs an `ExtendedKeyUsage` lists.
//!
//! ```text
//! KeyPurposeId ::= OBJECT IDENTIFIER
//! ```
//!
//! RFC 5280 §4.2.1.12 defines the first few; the rest are registered in
//! IANA's "SMI Security for PKIX Extended Key Purpose Identifiers" (under
//! `id-kp`, 1.3.6.1.5.5.7.3) or come from vendors. Any OID may appear in an
//! `ExtendedKeyUsage`; this table only supplies names for the known ones.

use tc_asn1::{Asn1Oid, NamedOid};

/// The known key purposes, as [`NamedOid`] constants with a lookup.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::ext::KeyPurposeId;
///
/// assert_eq!(KeyPurposeId::SERVER_AUTH.name(), "serverAuth");
/// assert_eq!(KeyPurposeId::SERVER_AUTH.oid().to_string(), "1.3.6.1.5.5.7.3.1");
/// assert_eq!(KeyPurposeId::from_oid(&"1.3.6.1.5.5.7.3.2".parse()?), Some(KeyPurposeId::CLIENT_AUTH));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct KeyPurposeId;

impl KeyPurposeId {
    /// RFC 5280: any purpose.
    pub const ANY_EXTENDED_KEY_USAGE: NamedOid = NamedOid::new(
        &[0x55, 0x1d, 0x25, 0x00],
        "2.5.29.37.0",
        "anyExtendedKeyUsage",
    );
    /// RFC 5280: TLS server.
    pub const SERVER_AUTH: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
        "1.3.6.1.5.5.7.3.1",
        "serverAuth",
    );
    /// RFC 5280: TLS client.
    pub const CLIENT_AUTH: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02],
        "1.3.6.1.5.5.7.3.2",
        "clientAuth",
    );
    /// RFC 5280.
    pub const CODE_SIGNING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03],
        "1.3.6.1.5.5.7.3.3",
        "codeSigning",
    );
    /// RFC 5280: S/MIME.
    pub const EMAIL_PROTECTION: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04],
        "1.3.6.1.5.5.7.3.4",
        "emailProtection",
    );
    /// RFC 2459; withdrawn by RFC 3280.
    pub const IPSEC_END_SYSTEM: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x05],
        "1.3.6.1.5.5.7.3.5",
        "ipsecEndSystem",
    );
    /// RFC 2459; withdrawn by RFC 3280.
    pub const IPSEC_TUNNEL: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x06],
        "1.3.6.1.5.5.7.3.6",
        "ipsecTunnel",
    );
    /// RFC 2459; withdrawn by RFC 3280.
    pub const IPSEC_USER: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x07],
        "1.3.6.1.5.5.7.3.7",
        "ipsecUser",
    );
    /// RFC 5280.
    pub const TIME_STAMPING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08],
        "1.3.6.1.5.5.7.3.8",
        "timeStamping",
    );
    /// RFC 5280.
    pub const OCSP_SIGNING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09],
        "1.3.6.1.5.5.7.3.9",
        "OCSPSigning",
    );
    /// RFC 3029.
    pub const DVCS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0a],
        "1.3.6.1.5.5.7.3.10",
        "dvcs",
    );
    /// `id-kp-sbgpCertAAServerAuth`, 1.3.6.1.5.5.7.3.11.
    pub const SBGP_CERT_AA_SERVER_AUTH: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0b],
        "1.3.6.1.5.5.7.3.11",
        "sbgpCertAAServerAuth",
    );
    /// `id-kp-scvp-responder`, 1.3.6.1.5.5.7.3.12.
    pub const SCVP_RESPONDER: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0c],
        "1.3.6.1.5.5.7.3.12",
        "scvpResponder",
    );
    /// RFC 4334.
    pub const EAP_OVER_PPP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0d],
        "1.3.6.1.5.5.7.3.13",
        "eapOverPPP",
    );
    /// RFC 4334.
    pub const EAP_OVER_LAN: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0e],
        "1.3.6.1.5.5.7.3.14",
        "eapOverLAN",
    );
    /// RFC 5055.
    pub const SCVP_SERVER: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0f],
        "1.3.6.1.5.5.7.3.15",
        "scvpServer",
    );
    /// RFC 5055.
    pub const SCVP_CLIENT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x10],
        "1.3.6.1.5.5.7.3.16",
        "scvpClient",
    );
    /// RFC 4945.
    pub const IPSEC_IKE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x11],
        "1.3.6.1.5.5.7.3.17",
        "ipsecIKE",
    );
    /// RFC 5415.
    pub const CAPWAP_AC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x12],
        "1.3.6.1.5.5.7.3.18",
        "capwapAC",
    );
    /// RFC 5415.
    pub const CAPWAP_WTP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x13],
        "1.3.6.1.5.5.7.3.19",
        "capwapWTP",
    );
    /// RFC 6187.
    pub const SECURE_SHELL_CLIENT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x15],
        "1.3.6.1.5.5.7.3.21",
        "secureShellClient",
    );
    /// RFC 6187.
    pub const SECURE_SHELL_SERVER: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x16],
        "1.3.6.1.5.5.7.3.22",
        "secureShellServer",
    );
    /// RFC 6402.
    pub const CMC_CA: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x1b],
        "1.3.6.1.5.5.7.3.27",
        "cmcCA",
    );
    /// RFC 6402.
    pub const CMC_RA: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x1c],
        "1.3.6.1.5.5.7.3.28",
        "cmcRA",
    );
    /// RFC 6402.
    pub const CMC_ARCHIVE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x1d],
        "1.3.6.1.5.5.7.3.29",
        "cmcArchive",
    );
    /// RFC 9509 (draft ietf-lamps-cmp-updates).
    pub const CM_KGA: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x20],
        "1.3.6.1.5.5.7.3.32",
        "cmKGA",
    );
    /// RFC 9174.
    pub const BUNDLE_SECURITY: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x23],
        "1.3.6.1.5.5.7.3.35",
        "bundleSecurity",
    );
    /// RFC 9336.
    pub const DOCUMENT_SIGNING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x24],
        "1.3.6.1.5.5.7.3.36",
        "documentSigning",
    );
    /// RFC 9509.
    pub const JWT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x25],
        "1.3.6.1.5.5.7.3.37",
        "jwt",
    );
    /// RFC 9509.
    pub const HTTP_CONTENT_ENCRYPT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x26],
        "1.3.6.1.5.5.7.3.38",
        "httpContentEncrypt",
    );
    /// RFC 9509.
    pub const OAUTH_ACCESS_TOKEN_SIGNING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x27],
        "1.3.6.1.5.5.7.3.39",
        "oauthAccessTokenSigning",
    );
    /// `id-kp-imUri`, 1.3.6.1.5.5.7.3.40: an instant messaging URI.
    pub const IM_URI: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x28],
        "1.3.6.1.5.5.7.3.40",
        "imUri",
    );
    /// `id-kp-configSigning`, 1.3.6.1.5.5.7.3.41: signing configuration data.
    pub const CONFIG_SIGNING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x29],
        "1.3.6.1.5.5.7.3.41",
        "configSigning",
    );
    /// `id-kp-trustAnchorConfigSigning`, 1.3.6.1.5.5.7.3.42: signing trust anchor
    /// configuration data.
    pub const TRUST_ANCHOR_CONFIG_SIGNING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x2a],
        "1.3.6.1.5.5.7.3.42",
        "trustAnchorConfigSigning",
    );
    /// `id-kp-updatePackageSigning`, 1.3.6.1.5.5.7.3.43: signing update packages.
    pub const UPDATE_PACKAGE_SIGNING: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x2b],
        "1.3.6.1.5.5.7.3.43",
        "updatePackageSigning",
    );
    /// `id-kp-safetyCommunication`, 1.3.6.1.5.5.7.3.44: safety communication.
    pub const SAFETY_COMMUNICATION: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x2c],
        "1.3.6.1.5.5.7.3.44",
        "safetyCommunication",
    );
    /// Microsoft.
    pub const SMARTCARD_LOGON: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x02],
        "1.3.6.1.4.1.311.20.2.2",
        "smartcardLogon",
    );
    /// IEEE 802.1AR use of the RFC 2307 attribute.
    pub const MAC_ADDRESS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x01, 0x01, 0x01, 0x16],
        "1.3.6.1.1.1.1.22",
        "macAddress",
    );
    /// Microsoft Server Gated Crypto, historical.
    pub const MS_SGC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x03],
        "1.3.6.1.4.1.311.10.3.3",
        "msSGC",
    );
    /// Netscape Server Gated Crypto, historical.
    pub const NS_SGC: NamedOid = NamedOid::new(
        &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x04, 0x01],
        "2.16.840.1.113730.4.1",
        "nsSGC",
    );

    /// Every known purpose, for lookups.
    pub const ALL: &'static [NamedOid] = &[
        Self::ANY_EXTENDED_KEY_USAGE,
        Self::SERVER_AUTH,
        Self::CLIENT_AUTH,
        Self::CODE_SIGNING,
        Self::EMAIL_PROTECTION,
        Self::IPSEC_END_SYSTEM,
        Self::IPSEC_TUNNEL,
        Self::IPSEC_USER,
        Self::TIME_STAMPING,
        Self::OCSP_SIGNING,
        Self::DVCS,
        Self::SBGP_CERT_AA_SERVER_AUTH,
        Self::SCVP_RESPONDER,
        Self::EAP_OVER_PPP,
        Self::EAP_OVER_LAN,
        Self::SCVP_SERVER,
        Self::SCVP_CLIENT,
        Self::IPSEC_IKE,
        Self::CAPWAP_AC,
        Self::CAPWAP_WTP,
        Self::SECURE_SHELL_CLIENT,
        Self::SECURE_SHELL_SERVER,
        Self::CMC_CA,
        Self::CMC_RA,
        Self::CMC_ARCHIVE,
        Self::CM_KGA,
        Self::BUNDLE_SECURITY,
        Self::DOCUMENT_SIGNING,
        Self::JWT,
        Self::HTTP_CONTENT_ENCRYPT,
        Self::OAUTH_ACCESS_TOKEN_SIGNING,
        Self::IM_URI,
        Self::CONFIG_SIGNING,
        Self::TRUST_ANCHOR_CONFIG_SIGNING,
        Self::UPDATE_PACKAGE_SIGNING,
        Self::SAFETY_COMMUNICATION,
        Self::SMARTCARD_LOGON,
        Self::MAC_ADDRESS,
        Self::MS_SGC,
        Self::NS_SGC,
    ];

    /// The known purpose with this OID, if any. Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::KeyPurposeId;

    #[test]
    fn every_entry_encodes_its_dotted_form_and_looks_up() {
        for purpose in KeyPurposeId::ALL {
            let parsed: tc_asn1::Asn1Oid = purpose.dotted().parse().unwrap();
            assert_eq!(parsed, purpose.oid(), "{}", purpose.dotted());
            assert_eq!(purpose.oid().to_string(), purpose.dotted());
            assert_eq!(KeyPurposeId::from_oid(&purpose.oid()), Some(*purpose));
        }
        assert_eq!(KeyPurposeId::from_oid(&"1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn entries_are_unique() {
        for (i, a) in KeyPurposeId::ALL.iter().enumerate() {
            for b in &KeyPurposeId::ALL[i + 1..] {
                assert_ne!(a.oid(), b.oid());
                assert_ne!(a.name(), b.name());
            }
        }
    }
}
