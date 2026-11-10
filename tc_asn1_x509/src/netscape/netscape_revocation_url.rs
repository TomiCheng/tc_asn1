//! The Netscape revocation URL, the value of extension 2.16.840.1.113730.1.3.

use tc_asn1::Asn1Ia5String;

/// A URL to which the certificate's serial number is appended to check revocation.
pub type NetscapeRevocationUrl = Asn1Ia5String;
