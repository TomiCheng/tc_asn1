//! RFC 5280 §4.2.1.2 `SubjectKeyIdentifier`, the value of extension 2.5.29.14.
//!
//! ```text
//! SubjectKeyIdentifier ::= KeyIdentifier
//! KeyIdentifier        ::= OCTET STRING
//! ```
//!
//! An identifier for the certified public key, matched against the
//! `keyIdentifier` of the authorityKeyIdentifier extension in the
//! certificates the key signs. RFC 5280 suggests deriving it from the key
//! (typically a SHA-1 of the subjectPublicKey BIT STRING) but any octets
//! will do, as long as issuer and subject agree; the extension is never
//! critical. This type carries the octets and does no hashing.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1OctetString, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

/// A non-empty key identifier.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::SubjectKeyIdentifier;
///
/// // The identifier is whatever the issuer chose; here a truncated hash.
/// let ski = SubjectKeyIdentifier::new([0x9b, 0x1f, 0x5e, 0xed, 0xed, 0x04, 0x33, 0x85])?;
/// assert_eq!(ski.key_identifier().len(), 8);
/// println!("{ski}");   // 9b1f5eeded043385
///
/// let der = ski.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = SubjectKeyIdentifier::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, ski);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SubjectKeyIdentifier {
    key_identifier: Asn1OctetString,
}

impl SubjectKeyIdentifier {
    /// An empty identifier is `MalformedValue`: the schema allows it, but
    /// it can identify nothing.
    pub fn new(key_identifier: impl Into<Vec<u8>>) -> Result<Self, Asn1Error> {
        let key_identifier = key_identifier.into();
        if key_identifier.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            key_identifier: Asn1OctetString::from(key_identifier),
        })
    }

    /// The identifier octets, never empty.
    pub fn key_identifier(&self) -> &[u8] {
        self.key_identifier.as_bytes()
    }
}

/// The octets as lowercase hex.
impl fmt::Display for SubjectKeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.key_identifier() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl DecodeInner for SubjectKeyIdentifier {
    /// An empty OCTET STRING is `MalformedValue`. Variable time: branches
    /// only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, key_identifier) = Asn1OctetString::decode_inner(buff, context)?;
        if key_identifier.as_bytes().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((used, Self { key_identifier }))
    }
}

impl DecodeContent for SubjectKeyIdentifier {
    /// The OCTET STRING contents, as under an IMPLICIT tag such as CMS's
    /// `[0]` subjectKeyIdentifier; empty is `MalformedValue`. Variable time:
    /// branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let key_identifier = Asn1OctetString::decode_content(value, context)?;
        if key_identifier.as_bytes().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { key_identifier })
    }
}

impl Decode for SubjectKeyIdentifier {}

impl Tagged for SubjectKeyIdentifier {
    const TAG: &'static [u8] = Asn1OctetString::TAG;
}

impl EncodeContent for SubjectKeyIdentifier {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_identifier.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.key_identifier.encode_content(rules, out)
    }
}

impl EncodeTagged for SubjectKeyIdentifier {}

impl Encode for SubjectKeyIdentifier {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};

    use super::SubjectKeyIdentifier;
    use crate::ext::{ExtensionId, Extensions};

    const RFC_8410: &[u8] = include_bytes!("../../tests/data/rfc8410.der");

    /// The subjectKeyIdentifier of the RFC 8410 example certificate.
    const KEY_ID: [u8; 20] = [
        0x9b, 0x1f, 0x5e, 0xed, 0xed, 0x04, 0x33, 0x85, 0xe4, 0xf7, 0xbc, 0x62, 0x3c, 0x59, 0x75,
        0xb9, 0x0b, 0xc8, 0xbb, 0x3b,
    ];

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_identifier_round_trips_as_an_octet_string() {
        let ski = SubjectKeyIdentifier::new(KEY_ID).unwrap();
        let mut wire = Vec::from([0x04, 0x14]);
        wire.extend_from_slice(&KEY_ID);
        assert_eq!(ski.encode_to_vec(&der()).unwrap(), wire);
        let (used, back) = SubjectKeyIdentifier::decode(&wire, &options()).unwrap();
        assert_eq!((used, &back), (wire.len(), &ski));
        assert_eq!(back.key_identifier(), KEY_ID);
        assert_eq!(back.to_string(), "9b1f5eeded043385e4f7bc623c5975b90bc8bb3b");
    }

    #[test]
    fn the_rfc_8410_certificate_carries_one_in_a_non_critical_extension() {
        let (_, extensions) = Extensions::decode(&RFC_8410[161..230], &options()).unwrap();
        let extension = extensions.get(ExtensionId::SUBJECT_KEY_IDENTIFIER).unwrap();
        assert!(!extension.critical());
        let mut context = DecodingContext::new(options());
        let ski = extensions
            .get_subject_key_identifier(&mut context)
            .unwrap()
            .unwrap();
        assert_eq!(ski.key_identifier(), KEY_ID);
    }

    #[test]
    fn an_empty_identifier_is_rejected_when_built_or_decoded() {
        assert!(matches!(
            SubjectKeyIdentifier::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            SubjectKeyIdentifier::decode(b"\x04\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn anything_but_an_octet_string_is_rejected() {
        assert!(matches!(
            SubjectKeyIdentifier::decode(b"\x03\x02\x00\x01", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
