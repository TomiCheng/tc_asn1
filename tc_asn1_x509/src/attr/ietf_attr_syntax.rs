//! RFC 5755 §4.4 syntax shared by the authentication, access identity, charging
//! identity and group attributes of an attribute certificate.
//!
//! ```text
//! IetfAttrSyntax ::= SEQUENCE {
//!     policyAuthority [0] GeneralNames OPTIONAL,
//!     values SEQUENCE OF CHOICE {
//!         octets OCTET STRING,
//!         oid    OBJECT IDENTIFIER,
//!         string UTF8String } }
//! ```
//!
//! `policyAuthority` is IMPLICIT. As in Bouncy Castle, every value must use the
//! same alternative; a mix is `MalformedValue`. An empty list is kept.

use alloc::vec::Vec;
use core::mem;

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Oid, Asn1Ref, Asn1SequenceOf, Asn1Utf8String, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Implicit, Tagged, tag,
};

use crate::name::GeneralNames;

const POLICY_AUTHORITY: &[u8] = &[0xa0];

/// One value of an [`IetfAttrSyntax`].
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum IetfAttrValue {
    /// `octets`, an OCTET STRING.
    Octets(Asn1OctetString),
    /// `oid`, an OBJECT IDENTIFIER.
    Oid(Asn1Oid),
    /// `string`, a UTF8String.
    String(Asn1Utf8String),
}

impl DecodeInner for IetfAttrValue {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // BER may send OCTET STRING and UTF8String in constructed form
        Ok(match Asn1Ref::parse(buff, context)?.tag() {
            [0x04] | [0x24] => {
                let (used, value) = Asn1OctetString::decode_inner(buff, context)?;
                (used, Self::Octets(value))
            }
            [0x06] => {
                let (used, value) = Asn1Oid::decode_inner(buff, context)?;
                (used, Self::Oid(value))
            }
            [0x0c] | [0x2c] => {
                let (used, value) = Asn1Utf8String::decode_inner(buff, context)?;
                (used, Self::String(value))
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        })
    }
}

impl Decode for IetfAttrValue {}

impl EncodeContent for IetfAttrValue {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Octets(value) => value.content_len(rules),
            Self::Oid(value) => value.content_len(rules),
            Self::String(value) => value.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Octets(value) => value.encode_content(rules, out),
            Self::Oid(value) => value.encode_content(rules, out),
            Self::String(value) => value.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for IetfAttrValue {}

// Each alternative writes its own tag, so CER segmentation stays with the string types.
impl Encode for IetfAttrValue {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Octets(value) => value.encoded_len(rules),
            Self::Oid(value) => value.encoded_len(rules),
            Self::String(value) => value.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Octets(value) => value.encode(rules, out),
            Self::Oid(value) => value.encode(rules, out),
            Self::String(value) => value.encode(rules, out),
        }
    }
}

/// Values of one kind, optionally with the authorities that define them.
///
/// ```
/// use tc_asn1_x509::attr::{IetfAttrSyntax, IetfAttrValue};
///
/// let groups = IetfAttrSyntax::new(
///     None,
///     vec![
///         IetfAttrValue::String(tc_asn1::Asn1Utf8String::new("staff")),
///         IetfAttrValue::String(tc_asn1::Asn1Utf8String::new("admins")),
///     ],
/// )?;
/// assert_eq!(groups.values().len(), 2);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IetfAttrSyntax {
    policy_authority: Option<GeneralNames>,
    values: Asn1SequenceOf<IetfAttrValue>,
}

impl IetfAttrSyntax {
    /// Creates the syntax; values of more than one alternative are `MalformedValue`.
    pub fn new(
        policy_authority: Option<GeneralNames>,
        values: Vec<IetfAttrValue>,
    ) -> Result<Self, Asn1Error> {
        if let Some(first) = values.first() {
            let kind = mem::discriminant(first);
            if values.iter().any(|value| mem::discriminant(value) != kind) {
                return Err(Asn1Error::MalformedValue);
            }
        }
        Ok(Self {
            policy_authority,
            values: Asn1SequenceOf::new(values),
        })
    }

    /// Returns `policyAuthority`, if supplied.
    pub fn policy_authority(&self) -> Option<&GeneralNames> {
        self.policy_authority.as_ref()
    }

    /// The values in wire order, all of the same alternative.
    pub fn values(&self) -> &[IetfAttrValue] {
        self.values.elements()
    }
}

impl DecodeContent for IetfAttrSyntax {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let policy_authority = fields.get_implicit_opt::<GeneralNames>(POLICY_AUTHORITY)?;
        let values = fields.get::<Asn1SequenceOf<IetfAttrValue>>()?;
        fields.end()?;
        Self::new(policy_authority, values.into_elements())
    }
}

impl DecodeInner for IetfAttrSyntax {
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

impl EncodeContent for IetfAttrSyntax {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.policy_authority.as_ref().map_or(0, |value| {
            Implicit::new(POLICY_AUTHORITY, value).encoded_len(rules)
        }) + self.values.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(value) = &self.policy_authority {
            at += Implicit::new(POLICY_AUTHORITY, value).encode(rules, &mut out[at..])?;
        }
        at += self.values.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for IetfAttrSyntax {}

impl Tagged for IetfAttrSyntax {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for IetfAttrSyntax {}

impl Encode for IetfAttrSyntax {
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

    use tc_asn1::{
        Asn1Error, Asn1OctetString, Asn1Utf8String, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };

    use super::{IetfAttrSyntax, IetfAttrValue};
    use crate::name::{GeneralName, GeneralNames};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn object_identifier_values_round_trip_without_an_authority() {
        let value = IetfAttrSyntax::new(
            None,
            vec![
                IetfAttrValue::Oid("1.2.3".parse().unwrap()),
                IetfAttrValue::Oid("1.2.4".parse().unwrap()),
            ],
        )
        .unwrap();
        let wire = b"\x30\x0a\x30\x08\x06\x02\x2a\x03\x06\x02\x2a\x04";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            IetfAttrSyntax::decode_der(wire, &options()).unwrap().1,
            value
        );
    }

    #[test]
    fn the_authority_uses_an_implicit_a0_before_the_values() {
        let authority = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let value = IetfAttrSyntax::new(
            Some(authority.clone()),
            vec![IetfAttrValue::String(Asn1Utf8String::new("g"))],
        )
        .unwrap();
        let wire = b"\x30\x0a\xa0\x03\x82\x01a\x30\x03\x0c\x01g";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        let back = IetfAttrSyntax::decode_der(wire, &options()).unwrap().1;
        assert_eq!(back.policy_authority(), Some(&authority));
        assert_eq!(back.values(), value.values());
    }

    #[test]
    fn mixed_alternatives_are_rejected_when_constructed_or_decoded() {
        assert_eq!(
            IetfAttrSyntax::new(
                None,
                vec![
                    IetfAttrValue::Oid("1.2".parse().unwrap()),
                    IetfAttrValue::Octets(Asn1OctetString::new(&[0])),
                ],
            ),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            IetfAttrSyntax::decode_der(b"\x30\x08\x30\x06\x06\x01\x2a\x04\x01\x00", &options()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_value_list_is_kept_but_other_value_types_are_rejected() {
        let empty = IetfAttrSyntax::decode_der(b"\x30\x02\x30\x00", &options())
            .unwrap()
            .1;
        assert!(empty.values().is_empty());
        assert!(matches!(
            IetfAttrSyntax::decode_der(b"\x30\x05\x30\x03\x02\x01\x00", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
