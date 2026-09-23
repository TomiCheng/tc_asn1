//! X.501 `AttributeTypeAndValue`, as profiled by RFC 5280 §4.1.2.4.
//!
//! ```text
//! AttributeTypeAndValue ::= SEQUENCE {
//!     type   AttributeType,      -- OBJECT IDENTIFIER
//!     value  AttributeValue      -- ANY DEFINED BY type
//! }
//! ```
//!
//! One `type = value` pair of a distinguished name, such as `CN=Example`. The
//! value's type depends on the OID, but the values that actually occur in
//! names are a handful of string types, so [`AttributeValue`] classifies the
//! value by its identifier alone and keeps anything else as a decoded tree. The
//! OID is not consulted while decoding; profile checks such as countryName
//! being exactly two PrintableString characters belong to a later layer.

use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1Object, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::DirectoryString;
use crate::string_prep::text_equivalent;

/// The value of an attribute, classified by its identifier.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AttributeValue {
    /// PrintableString, UTF8String, TeletexString, BMPString or
    /// UniversalString: most X.520 attributes, including countryName.
    DirectoryString(DirectoryString),
    /// IA5String: domainComponent and emailAddress.
    Ia5String(Asn1Ia5String),
    /// Any other identifier, as an [`Asn1Object`].
    Other(Asn1Object),
}

impl AttributeValue {
    /// RFC 5280 §7.1 relaxed comparison: strings by [`DirectoryString::equivalent`],
    /// IA5Strings under the same string preparation, anything else by DER.
    /// Alternatives of different kinds never match. Variable time; for public values.
    pub fn equivalent(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::DirectoryString(a), Self::DirectoryString(b)) => a.equivalent(b),
            (Self::Ia5String(a), Self::Ia5String(b)) => text_equivalent(a.as_str(), b.as_str()),
            (Self::Other(a), Self::Other(b)) => a == b,
            _ => false,
        }
    }
}

impl From<DirectoryString> for AttributeValue {
    fn from(value: DirectoryString) -> Self {
        Self::DirectoryString(value)
    }
}

impl From<Asn1Ia5String> for AttributeValue {
    fn from(value: Asn1Ia5String) -> Self {
        Self::Ia5String(value)
    }
}

impl From<Asn1Object> for AttributeValue {
    fn from(value: Asn1Object) -> Self {
        Self::Other(value)
    }
}

impl DecodeInner for AttributeValue {
    /// The identifier selects the alternative; every identifier is accepted.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let tag = element.tag();
        if tag == tag::PRINTABLE_STRING
            || tag == tag::UTF8_STRING
            || tag == tag::TELETEX_STRING
            || tag == tag::BMP_STRING
            || tag == tag::UNIVERSAL_STRING
        {
            let (used, value) = DirectoryString::decode_inner(buff, context)?;
            Ok((used, Self::DirectoryString(value)))
        } else if tag == Asn1Ia5String::TAG {
            let (used, value) = Asn1Ia5String::decode_inner(buff, context)?;
            Ok((used, Self::Ia5String(value)))
        } else {
            let (used, value) = Asn1Object::decode_inner(buff, context)?;
            Ok((used, Self::Other(value)))
        }
    }
}

impl Decode for AttributeValue {}

impl EncodeContent for AttributeValue {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::DirectoryString(s) => s.content_len(rules),
            Self::Ia5String(s) => s.content_len(rules),
            Self::Other(object) => object.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::DirectoryString(s) => s.encode_content(rules, out),
            Self::Ia5String(s) => s.encode_content(rules, out),
            Self::Other(object) => object.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for AttributeValue {}

/// Each alternative writes its own identifier.
impl Encode for AttributeValue {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::DirectoryString(s) => s.encoded_len(rules),
            Self::Ia5String(s) => s.encoded_len(rules),
            Self::Other(object) => object.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::DirectoryString(s) => s.encode(rules, out),
            Self::Ia5String(s) => s.encode(rules, out),
            Self::Other(object) => object.encode(rules, out),
        }
    }
}

/// An attribute type OID with its value.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x500::{AttributeTypeAndValue, AttributeValue, DirectoryString};
///
/// // Build CN=Example: the commonName OID with a DirectoryString value.
/// let cn = AttributeTypeAndValue::new("2.5.4.3".parse()?, DirectoryString::new("Example")?);
///
/// // Encode it as DER ...
/// let der = cn.encode_to_vec(&EncodingOptions::DER)?;
///
/// // ... and read it back. The value is classified by its string type.
/// let (_, decoded) = AttributeTypeAndValue::decode(&der, &DecodingOptions::default())?;
/// if let AttributeValue::DirectoryString(text) = decoded.value() {
///     println!("{} = {}", decoded.attribute_type(), text);   // 2.5.4.3 = Example
/// }
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttributeTypeAndValue {
    attribute_type: Asn1Oid,
    value: AttributeValue,
}

impl AttributeTypeAndValue {
    /// Pairs a type OID with a value; the value is not checked against the
    /// syntax the type declares.
    pub fn new(attribute_type: Asn1Oid, value: impl Into<AttributeValue>) -> Self {
        Self {
            attribute_type,
            value: value.into(),
        }
    }

    /// The attribute type OID.
    pub fn attribute_type(&self) -> &Asn1Oid {
        &self.attribute_type
    }

    /// The value.
    pub fn value(&self) -> &AttributeValue {
        &self.value
    }

    /// The same type and an [`AttributeValue::equivalent`] value.
    pub fn equivalent(&self, other: &Self) -> bool {
        self.attribute_type == other.attribute_type && self.value.equivalent(&other.value)
    }
}

impl DecodeInner for AttributeTypeAndValue {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let attribute_type: Asn1Oid = children.get()?;
        let value: AttributeValue = children.get()?;
        children.end()?;
        Ok((
            element.total_len(),
            Self {
                attribute_type,
                value,
            },
        ))
    }
}

impl Decode for AttributeTypeAndValue {}

impl Tagged for AttributeTypeAndValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for AttributeTypeAndValue {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.attribute_type.encoded_len(rules) + self.value.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.attribute_type.encode(rules, out)?;
        at += self.value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for AttributeTypeAndValue {}

impl Encode for AttributeTypeAndValue {
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

    use tc_asn1::{
        Asn1Error, Asn1Ia5String, Asn1Integer, Asn1Object, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };

    use super::{AttributeTypeAndValue, AttributeValue};
    use crate::DirectoryString;

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    /// CN=Example
    const CN: &[u8] = b"\x30\x0e\x06\x03\x55\x04\x03\x13\x07Example";
    /// DC=example
    const DC: &[u8] = b"\x30\x15\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19\x16\x07example";

    #[test]
    fn string_values_are_classified_by_their_identifier_and_round_trip() {
        let (used, atv) = AttributeTypeAndValue::decode(CN, &options()).unwrap();
        assert_eq!(used, CN.len());
        assert_eq!(atv.attribute_type().to_string(), "2.5.4.3");
        assert!(matches!(
            atv.value(),
            AttributeValue::DirectoryString(s) if s.as_str() == Some("Example")
        ));
        assert_eq!(atv.encode_to_vec(&der()).unwrap(), CN);
        assert_eq!(
            AttributeTypeAndValue::new(
                "2.5.4.3".parse().unwrap(),
                DirectoryString::new("Example").unwrap()
            ),
            atv
        );

        let (_, atv) = AttributeTypeAndValue::decode(DC, &options()).unwrap();
        assert_eq!(
            atv.attribute_type().to_string(),
            "0.9.2342.19200300.100.1.25"
        );
        assert!(matches!(
            atv.value(),
            AttributeValue::Ia5String(s) if s.as_str() == "example"
        ));
        assert_eq!(atv.encode_to_vec(&der()).unwrap(), DC);
        assert_eq!(
            AttributeTypeAndValue::new(
                "0.9.2342.19200300.100.1.25".parse().unwrap(),
                Asn1Ia5String::new("example").unwrap()
            ),
            atv
        );
    }

    #[test]
    fn every_directory_string_alternative_lands_in_that_variant() {
        for value in [
            &b"\x13\x02TW"[..],
            b"\x0c\x02TW",
            b"\x14\x02TW",
            b"\x1e\x04\x00T\x00W",
            b"\x1c\x08\x00\x00\x00T\x00\x00\x00W",
        ] {
            let mut wire = Vec::from(&b"\x30\x00\x06\x03\x55\x04\x06"[..]);
            wire.extend_from_slice(value);
            wire[1] = (wire.len() - 2) as u8;
            let (_, atv) = AttributeTypeAndValue::decode(&wire, &options()).unwrap();
            assert!(matches!(atv.value(), AttributeValue::DirectoryString(_)));
            assert_eq!(atv.encode_to_vec(&der()).unwrap(), wire);
        }
    }

    #[test]
    fn any_other_value_is_kept_as_a_decoded_object() {
        // 1.2.3.4 with an INTEGER value
        let wire = b"\x30\x08\x06\x03\x2a\x03\x04\x02\x01\x2a";
        let (_, atv) = AttributeTypeAndValue::decode(wire, &options()).unwrap();
        assert_eq!(atv.attribute_type().to_string(), "1.2.3.4");
        assert!(matches!(
            atv.value(),
            AttributeValue::Other(Asn1Object::Integer(i)) if *i == Asn1Integer::from(42)
        ));
        assert_eq!(atv.encode_to_vec(&der()).unwrap(), wire);
        assert_eq!(
            AttributeTypeAndValue::new(
                "1.2.3.4".parse().unwrap(),
                Asn1Object::from(Asn1Integer::from(42))
            ),
            atv
        );
    }

    #[test]
    fn equivalence_needs_the_same_type_and_matching_values_of_the_same_kind() {
        let atv = |wire| AttributeTypeAndValue::decode(wire, &options()).unwrap().1;
        let cn = atv(CN);
        assert!(cn.equivalent(&atv(b"\x30\x0e\x06\x03\x55\x04\x03\x0c\x07EXAMPLE")));
        assert!(!cn.equivalent(&atv(b"\x30\x0e\x06\x03\x55\x04\x0a\x13\x07Example"))); // O=
        assert!(!cn.equivalent(&atv(b"\x30\x0e\x06\x03\x55\x04\x03\x16\x07Example"))); // IA5
        let dc = atv(DC);
        assert!(dc.equivalent(&atv(
            b"\x30\x15\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19\x16\x07EXAMPLE"
        )));
        let other = atv(b"\x30\x08\x06\x03\x2a\x03\x04\x02\x01\x2a");
        assert!(other.equivalent(&other.clone()));
        assert!(!other.equivalent(&atv(b"\x30\x08\x06\x03\x2a\x03\x04\x02\x01\x2b")));
    }

    #[test]
    fn an_empty_directory_string_value_is_decoded_and_round_trips() {
        let empty_cn = b"\x30\x07\x06\x03\x55\x04\x03\x13\x00";
        let (_, atv) = AttributeTypeAndValue::decode(empty_cn, &options()).unwrap();
        assert!(matches!(
            atv.value(),
            AttributeValue::DirectoryString(s) if s.as_str() == Some("")
        ));
        assert_eq!(atv.encode_to_vec(&der()).unwrap(), empty_cn);
    }

    #[test]
    fn missing_extra_and_mistagged_fields_are_rejected() {
        let type_only = b"\x30\x05\x06\x03\x55\x04\x03";
        assert!(matches!(
            AttributeTypeAndValue::decode(type_only, &options()),
            Err(Asn1Error::Truncated)
        ));
        let mut extra: Vec<u8> = CN.to_vec();
        extra.extend_from_slice(b"\x05\x00");
        extra[1] += 2;
        assert!(matches!(
            AttributeTypeAndValue::decode(&extra, &options()),
            Err(Asn1Error::TrailingData)
        ));
        let mut as_set: Vec<u8> = CN.to_vec();
        as_set[0] = 0x31;
        assert!(matches!(
            AttributeTypeAndValue::decode(&as_set, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        let value_first = b"\x30\x0e\x13\x07Example\x06\x03\x55\x04\x03";
        assert!(matches!(
            AttributeTypeAndValue::decode(value_first, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
