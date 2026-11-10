//! RFC 3739 §3.2.6.1 semantics information, the info of the `pkixQCSyntax`
//! statements.
//!
//! ```text
//! SemanticsInformation ::= SEQUENCE {
//!     semanticsIdentifier         OBJECT IDENTIFIER OPTIONAL,
//!     nameRegistrationAuthorities NameRegistrationAuthorities OPTIONAL }
//!     (WITH COMPONENTS {..., semanticsIdentifier PRESENT} |
//!      WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
//!
//! NameRegistrationAuthorities ::= SEQUENCE SIZE (1..MAX) OF GeneralName
//! ```
//!
//! At least one field must be present, otherwise `MalformedValue`.
//! `NameRegistrationAuthorities` has the shape of [`GeneralNames`] and is
//! kept as one.

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::name::GeneralNames;

/// A semantics OID, the authorities that register the names, or both.
///
/// ```
/// use tc_asn1_x509::qualified::SemanticsInformation;
///
/// // id-etsi-qcs-semanticsId-Natural
/// let natural = SemanticsInformation::new(Some("0.4.0.194121.1.1".parse()?), None)?;
/// assert!(natural.name_registration_authorities().is_none());
/// assert!(SemanticsInformation::new(None, None).is_err());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SemanticsInformation {
    semantics_identifier: Option<Asn1Oid>,
    name_registration_authorities: Option<GeneralNames>,
}

impl SemanticsInformation {
    /// Creates the information; both fields absent returns `MalformedValue`.
    pub fn new(
        semantics_identifier: Option<Asn1Oid>,
        name_registration_authorities: Option<GeneralNames>,
    ) -> Result<Self, Asn1Error> {
        if semantics_identifier.is_none() && name_registration_authorities.is_none() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            semantics_identifier,
            name_registration_authorities,
        })
    }

    /// Returns `semanticsIdentifier`, if present.
    pub fn semantics_identifier(&self) -> Option<&Asn1Oid> {
        self.semantics_identifier.as_ref()
    }

    /// Returns `nameRegistrationAuthorities`, if present.
    pub fn name_registration_authorities(&self) -> Option<&GeneralNames> {
        self.name_registration_authorities.as_ref()
    }
}

impl DecodeContent for SemanticsInformation {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let semantics_identifier = fields.get_opt()?;
        let name_registration_authorities = fields.get_opt()?;
        fields.end()?;
        Self::new(semantics_identifier, name_registration_authorities)
    }
}

impl DecodeInner for SemanticsInformation {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        Ok((
            element.total_len(),
            Self::decode_content(element.value(), context)?,
        ))
    }
}

impl EncodeContent for SemanticsInformation {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.semantics_identifier
            .as_ref()
            .map_or(0, |value| value.encoded_len(rules))
            + self
                .name_registration_authorities
                .as_ref()
                .map_or(0, |value| value.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(value) = &self.semantics_identifier {
            at += value.encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.name_registration_authorities {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SemanticsInformation {}

impl Tagged for SemanticsInformation {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SemanticsInformation {}

impl Encode for SemanticsInformation {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::SemanticsInformation;
    use crate::name::{GeneralName, GeneralNames};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn each_field_alone_and_both_round_trip() {
        let oid: tc_asn1::Asn1Oid = "1.2.3".parse().unwrap();
        let authorities = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        for (value, wire) in [
            (
                SemanticsInformation::new(Some(oid.clone()), None).unwrap(),
                &b"\x30\x04\x06\x02\x2a\x03"[..],
            ),
            (
                SemanticsInformation::new(None, Some(authorities.clone())).unwrap(),
                b"\x30\x05\x30\x03\x82\x01a",
            ),
            (
                SemanticsInformation::new(Some(oid), Some(authorities)).unwrap(),
                b"\x30\x09\x06\x02\x2a\x03\x30\x03\x82\x01a",
            ),
        ] {
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                SemanticsInformation::decode_der(wire, &options())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn an_empty_sequence_is_rejected_when_constructed_or_decoded() {
        assert_eq!(
            SemanticsInformation::new(None, None),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            SemanticsInformation::decode_der(b"\x30\x00", &options()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_authority_list_or_fields_out_of_order_are_rejected() {
        assert!(SemanticsInformation::decode_der(b"\x30\x02\x30\x00", &options()).is_err());
        assert!(
            SemanticsInformation::decode_der(
                b"\x30\x09\x30\x03\x82\x01a\x06\x02\x2a\x03",
                &options()
            )
            .is_err()
        );
    }
}
