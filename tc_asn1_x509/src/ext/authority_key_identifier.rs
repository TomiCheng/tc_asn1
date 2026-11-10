//! RFC 5280 §4.2.1.1 `AuthorityKeyIdentifier`, the value of extension 2.5.29.35.
//!
//! ```text
//! AuthorityKeyIdentifier ::= SEQUENCE {
//!     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
//!     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
//!     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
//! ```
//!
//! Which key signed the certificate: by the issuer's subjectKeyIdentifier,
//! or by the issuer's own issuer and serial number, or both. Path building
//! matches `keyIdentifier` against the candidate issuer's
//! subjectKeyIdentifier. RFC 5280 requires the issuer and serial number to
//! be present or absent together, which is enforced; it also requires
//! `keyIdentifier` in every certificate a conforming CA issues except a
//! self-signed one, which is a profile rule left to the validator. All
//! three fields are IMPLICIT, the second one an IMPLICIT SEQUENCE OF.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};

use crate::name::GeneralNames;

const KEY_IDENTIFIER: &[u8] = &[0x80];
const AUTHORITY_CERT_ISSUER: &[u8] = &[0xA1];
const AUTHORITY_CERT_SERIAL_NUMBER: &[u8] = &[0x82];

/// The issuing key, by identifier and/or by issuer and serial number.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::AuthorityKeyIdentifier;
///
/// // What nearly every certificate carries: the issuer's key identifier alone.
/// let aki = AuthorityKeyIdentifier::from_key_identifier(&[0x9b, 0x1f, 0x5e, 0xed])?;
/// assert_eq!(aki.to_string(), "keyid:9b1f5eed");
///
/// let der = aki.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = AuthorityKeyIdentifier::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.key_identifier(), Some(&[0x9b, 0x1f, 0x5e, 0xed][..]));
/// assert!(back.authority_cert_issuer().is_none());
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AuthorityKeyIdentifier {
    key_identifier: Option<Asn1OctetString>,
    authority_cert_issuer: Option<GeneralNames>,
    authority_cert_serial_number: Option<Asn1Integer>,
}

impl AuthorityKeyIdentifier {
    /// The key identifier alone; an empty one is `MalformedValue`.
    pub fn from_key_identifier(key_identifier: &[u8]) -> Result<Self, Asn1Error> {
        if key_identifier.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            key_identifier: Some(Asn1OctetString::new(key_identifier)),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        })
    }

    /// The issuer's issuer and serial number, without a key identifier.
    pub fn from_issuer_and_serial(issuer: GeneralNames, serial_number: Asn1Integer) -> Self {
        Self {
            key_identifier: None,
            authority_cert_issuer: Some(issuer),
            authority_cert_serial_number: Some(serial_number),
        }
    }

    /// Adds the issuer's issuer and serial number, which go together.
    pub fn with_issuer_and_serial(
        mut self,
        issuer: GeneralNames,
        serial_number: Asn1Integer,
    ) -> Self {
        self.authority_cert_issuer = Some(issuer);
        self.authority_cert_serial_number = Some(serial_number);
        self
    }

    /// The key identifier, usually the issuer's subjectKeyIdentifier.
    pub fn key_identifier(&self) -> Option<&[u8]> {
        self.key_identifier.as_ref().map(Asn1OctetString::as_bytes)
    }

    /// The issuer of the issuer's certificate, given with its serial number.
    pub fn authority_cert_issuer(&self) -> Option<&GeneralNames> {
        self.authority_cert_issuer.as_ref()
    }

    /// The serial number of the issuer's certificate, given with its issuer.
    pub fn authority_cert_serial_number(&self) -> Option<&Asn1Integer> {
        self.authority_cert_serial_number.as_ref()
    }
}

/// `keyid:` and the identifier in hex, `DirName:...` for the issuer's
/// names and `serial:` for the number, whichever are present, joined with
/// `, `.
impl fmt::Display for AuthorityKeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut separate = |f: &mut fmt::Formatter<'_>| {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            Ok(())
        };
        if let Some(id) = self.key_identifier() {
            separate(f)?;
            f.write_str("keyid:")?;
            for byte in id {
                write!(f, "{byte:02x}")?;
            }
        }
        if let Some(issuer) = &self.authority_cert_issuer {
            separate(f)?;
            write!(f, "{issuer}")?;
        }
        if let Some(serial) = &self.authority_cert_serial_number {
            separate(f)?;
            write!(f, "serial:{serial:x}")?;
        }
        Ok(())
    }
}

impl DecodeInner for AuthorityKeyIdentifier {
    /// Each field is taken when its context tag comes next. An empty
    /// SEQUENCE, an empty key identifier, or an issuer without a serial
    /// number or the reverse is `MalformedValue`. Variable time: branches
    /// only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let key_identifier = fields.get_implicit_opt::<Asn1OctetString>(KEY_IDENTIFIER)?;
        let authority_cert_issuer =
            fields.get_implicit_opt::<GeneralNames>(AUTHORITY_CERT_ISSUER)?;
        let authority_cert_serial_number =
            fields.get_implicit_opt::<Asn1Integer>(AUTHORITY_CERT_SERIAL_NUMBER)?;
        fields.end()?;

        if key_identifier
            .as_ref()
            .is_some_and(|id| id.as_bytes().is_empty())
            || authority_cert_issuer.is_some() != authority_cert_serial_number.is_some()
            || (key_identifier.is_none() && authority_cert_issuer.is_none())
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((
            element.total_len(),
            Self {
                key_identifier,
                authority_cert_issuer,
                authority_cert_serial_number,
            },
        ))
    }
}

impl Decode for AuthorityKeyIdentifier {}

impl Tagged for AuthorityKeyIdentifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for AuthorityKeyIdentifier {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_identifier
            .as_ref()
            .map_or(0, |id| Implicit::new(KEY_IDENTIFIER, id).encoded_len(rules))
            + self.authority_cert_issuer.as_ref().map_or(0, |issuer| {
                Implicit::new(AUTHORITY_CERT_ISSUER, issuer).encoded_len(rules)
            })
            + self
                .authority_cert_serial_number
                .as_ref()
                .map_or(0, |serial| {
                    Implicit::new(AUTHORITY_CERT_SERIAL_NUMBER, serial).encoded_len(rules)
                })
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(id) = &self.key_identifier {
            at += Implicit::new(KEY_IDENTIFIER, id).encode(rules, out)?;
        }
        if let Some(issuer) = &self.authority_cert_issuer {
            at += Implicit::new(AUTHORITY_CERT_ISSUER, issuer).encode(rules, &mut out[at..])?;
        }
        if let Some(serial) = &self.authority_cert_serial_number {
            at += Implicit::new(AUTHORITY_CERT_SERIAL_NUMBER, serial)
                .encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for AuthorityKeyIdentifier {}

impl Encode for AuthorityKeyIdentifier {
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

    use tc_asn1::{Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::AuthorityKeyIdentifier;
    use crate::name::{GeneralName, GeneralNames};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn issuer() -> GeneralNames {
        GeneralNames::new(Vec::from([GeneralName::DirectoryName(
            "CN=CA".parse().unwrap(),
        )]))
        .unwrap()
    }

    #[test]
    fn the_key_identifier_alone_is_the_usual_form() {
        let aki = AuthorityKeyIdentifier::from_key_identifier(&[0x9b, 0x1f]).unwrap();
        let der = aki.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der, [0x30, 0x04, 0x80, 0x02, 0x9b, 0x1f]);
        let (used, back) = AuthorityKeyIdentifier::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &aki));
        assert_eq!(back.key_identifier(), Some(&[0x9b, 0x1f][..]));
        assert_eq!(back.to_string(), "keyid:9b1f");
        assert_eq!(
            AuthorityKeyIdentifier::decode_der(&der, &options())
                .unwrap()
                .1,
            aki
        );
    }

    #[test]
    fn issuer_and_serial_travel_as_implicit_sequence_of_and_integer() {
        let aki = AuthorityKeyIdentifier::from_key_identifier(&[0x01])
            .unwrap()
            .with_issuer_and_serial(issuer(), Asn1Integer::from(0x1234));
        let der = aki.encode_to_vec(&EncodingOptions::DER).unwrap();
        // 80 01 01 | A1 11 { A4 0F { 30 0D ... } } | 82 02 12 34
        assert_eq!(&der[..5], &[0x30, 0x1A, 0x80, 0x01, 0x01]);
        assert_eq!(&der[5..9], &[0xA1, 0x11, 0xA4, 0x0F]);
        assert_eq!(&der[der.len() - 4..], &[0x82, 0x02, 0x12, 0x34]);
        let (_, back) = AuthorityKeyIdentifier::decode(&der, &options()).unwrap();
        assert_eq!(back, aki);
        assert_eq!(back.authority_cert_issuer(), Some(&issuer()));
        assert_eq!(
            back.authority_cert_serial_number(),
            Some(&Asn1Integer::from(0x1234))
        );
        assert_eq!(back.to_string(), "keyid:01, DirName:CN=CA, serial:1234");

        let without_id =
            AuthorityKeyIdentifier::from_issuer_and_serial(issuer(), Asn1Integer::from(7));
        let der = without_id.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der[2], 0xA1);
        assert_eq!(
            AuthorityKeyIdentifier::decode(&der, &options()).unwrap().1,
            without_id
        );
        assert_eq!(without_id.to_string(), "DirName:CN=CA, serial:7");
    }

    #[test]
    fn the_pair_rule_an_empty_identifier_and_an_empty_sequence_are_rejected() {
        assert!(matches!(
            AuthorityKeyIdentifier::from_key_identifier(&[]),
            Err(Asn1Error::MalformedValue)
        ));
        for wire in [
            &[0x30, 0x00][..],                                             // nothing at all
            &[0x30, 0x02, 0x80, 0x00],                                     // empty identifier
            &[0x30, 0x03, 0x82, 0x01, 0x07],                               // serial without issuer
            &[0x30, 0x08, 0xA1, 0x06, 0x82, 0x04, b'x', b'.', b't', b'w'], // issuer without serial
        ] {
            assert!(
                matches!(
                    AuthorityKeyIdentifier::decode(wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{wire:02X?}"
            );
        }
        // fields out of order: the serial number is not what comes after [0]
        assert!(matches!(
            AuthorityKeyIdentifier::decode(
                &[0x30, 0x06, 0x82, 0x01, 0x07, 0x80, 0x01, 0x01],
                &options()
            ),
            Err(Asn1Error::TrailingData)
        ));
    }
}
