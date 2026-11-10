//! RFC 5280 §4.2.2 `AccessDescription`.
//!
//! ```text
//! AccessDescription ::= SEQUENCE {
//!     accessMethod    OBJECT IDENTIFIER,
//!     accessLocation  GeneralName }
//! ```
//!
//! One way to obtain information about a certificate's issuer or subject.
//! The method OID defines the information and retrieval semantics; the
//! location says where it is available. Unknown method OIDs are preserved.
//! Whether a method permits a particular kind of `GeneralName` belongs to
//! the profile or protocol using this structure.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{ext::AccessMethod, name::GeneralName};

/// An access method and the location at which it is available.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{ext::{AccessDescription, AccessMethod}, name::GeneralName};
///
/// let description = AccessDescription::new(
///     AccessMethod::OCSP,
///     GeneralName::uri("http://ocsp.example.com")?,
/// );
/// assert_eq!(description.to_string(), "OCSP: URI:http://ocsp.example.com");
///
/// let der = description.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = AccessDescription::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, description);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AccessDescription {
    access_method: Asn1Oid,
    access_location: GeneralName,
}

impl AccessDescription {
    /// Creates a description. Unknown method OIDs and every `GeneralName`
    /// alternative are retained as given.
    pub fn new(access_method: impl Into<Asn1Oid>, access_location: GeneralName) -> Self {
        Self {
            access_method: access_method.into(),
            access_location,
        }
    }

    /// How the information is reached, such as `id-ad-ocsp` or `id-ad-caIssuers`.
    pub fn access_method(&self) -> &Asn1Oid {
        &self.access_method
    }

    /// Where the information is, usually a URI.
    pub fn access_location(&self) -> &GeneralName {
        &self.access_location
    }
}

/// The method by name where [`AccessMethod`] knows it, as a dotted OID
/// otherwise, followed by the location as [`GeneralName`] prints it.
impl fmt::Display for AccessDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match AccessMethod::from_oid(&self.access_method) {
            Some(known) => write!(f, "{known}: {}", self.access_location),
            None => write!(f, "{}: {}", self.access_method, self.access_location),
        }
    }
}

impl DecodeInner for AccessDescription {
    /// Both fields are required and no field may follow the location.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let access_method = fields.get()?;
        let access_location = fields.get()?;
        fields.end()?;
        Ok((
            element.total_len(),
            Self {
                access_method,
                access_location,
            },
        ))
    }
}

impl Decode for AccessDescription {}

impl Tagged for AccessDescription {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for AccessDescription {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.access_method.encoded_len(rules) + self.access_location.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.access_method.encode(rules, out)?;
        at += self.access_location.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for AccessDescription {}

impl Encode for AccessDescription {
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

    use tc_asn1::{Asn1Error, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::AccessDescription;
    use crate::{ext::AccessMethod, name::GeneralName};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn oid(text: &str) -> Asn1Oid {
        text.parse().unwrap()
    }

    #[test]
    fn an_ocsp_uri_round_trips_with_a_fixed_der_encoding() {
        let description = AccessDescription::new(
            AccessMethod::OCSP,
            GeneralName::uri("http://ocsp.x.tw").unwrap(),
        );
        let der = description.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            der,
            b"\x30\x1c\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01\x86\x10http://ocsp.x.tw"
        );
        let (used, back) = AccessDescription::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &description));
        assert_eq!(
            AccessDescription::decode_der(&der, &options()).unwrap().1,
            description
        );
        assert_eq!(back.to_string(), "OCSP: URI:http://ocsp.x.tw");
    }

    #[test]
    fn an_unknown_method_and_another_location_kind_are_preserved() {
        let description =
            AccessDescription::new(oid("1.2.3.4"), GeneralName::dns_name("repo.x.tw").unwrap());
        let der = description.encode_to_vec(&EncodingOptions::DER).unwrap();
        let (_, back) = AccessDescription::decode(&der, &options()).unwrap();
        assert_eq!(back.access_method(), &oid("1.2.3.4"));
        assert_eq!(
            back.access_location(),
            &GeneralName::dns_name("repo.x.tw").unwrap()
        );
        assert_eq!(back.to_string(), "1.2.3.4: DNS:repo.x.tw");
    }

    #[test]
    fn a_missing_or_extra_field_is_rejected() {
        for wire in [
            &b"\x30\x00"[..],
            &b"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01"[..],
            &b"\x30\x12\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01\x82\x04x.tw\x05\x00"[..],
        ] {
            assert!(
                AccessDescription::decode(wire, &options()).is_err(),
                "{wire:02X?}"
            );
        }
    }

    #[test]
    fn wrong_field_types_or_an_outer_set_are_rejected() {
        assert!(matches!(
            AccessDescription::decode(b"\x30\x08\x16\x00\x82\x04x.tw", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            AccessDescription::decode(b"\x30\x07\x06\x01\x2a\x16\x02hi", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            AccessDescription::decode(b"\x31\x09\x06\x01\x2a\x82\x04x.tw", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
