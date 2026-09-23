//! A directory attribute with one or more ASN.1 values.
//!
//! ```text
//! Attribute ::= SEQUENCE {
//!     type   OBJECT IDENTIFIER,
//!     values SET SIZE (1..MAX) OF ANY }
//! ```
//!
//! Values are classified by tag through `AttributeValue`; unknown types remain
//! ASN.1 objects. DER encoding sorts the SET OF values.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Asn1SetOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::AttributeValue;

/// An attribute OID and a non-empty set of values.
///
/// # Examples
///
/// ```
/// use tc_asn1::Asn1Oid;
/// use tc_asn1_x500::{Attribute, DirectoryString};
///
/// let attribute = Attribute::new("1.2.3".parse::<Asn1Oid>()?,
///     vec![DirectoryString::new("value")?.into()])?;
/// assert_eq!(attribute.values().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Attribute {
    attribute_type: Asn1Oid,
    values: Asn1SetOf<AttributeValue>,
}

impl Attribute {
    /// Creates an attribute. Empty values return `MalformedValue`.
    pub fn new(
        attribute_type: impl Into<Asn1Oid>,
        values: Vec<AttributeValue>,
    ) -> Result<Self, Asn1Error> {
        if values.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            attribute_type: attribute_type.into(),
            values: Asn1SetOf::new(values),
        })
    }

    /// Returns the attribute type OID.
    pub fn attribute_type(&self) -> &Asn1Oid {
        &self.attribute_type
    }

    /// Returns values in construction or wire order.
    pub fn values(&self) -> &[AttributeValue] {
        self.values.members()
    }
}

/// Displays the attribute OID; values remain available through `values()`.
impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.attribute_type.fmt(f)
    }
}

impl DecodeInner for Attribute {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let oid = fields.get::<Asn1Oid>()?;
        let values = fields.get::<Asn1SetOf<AttributeValue>>()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(oid, values.into_members())?))
    }
}

impl EncodeContent for Attribute {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.attribute_type.encoded_len(rules) + self.values.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.attribute_type.encode(rules, out)?;
        Ok(at + self.values.encode(rules, &mut out[at..])?)
    }
}

impl Decode for Attribute {}

impl Tagged for Attribute {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Attribute {}

impl Encode for Attribute {
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
        Asn1Error, Asn1Ia5String, Asn1Integer, Asn1Object, Asn1Oid, Decode, DecodingOptions,
        Encode, EncodingOptions,
    };

    use super::Attribute;
    use crate::{AttributeValue, DirectoryString};

    #[test]
    fn values_are_classified_by_tag_and_der_sorts_their_encodings() {
        let text = AttributeValue::from(DirectoryString::new("A").unwrap());
        let email = AttributeValue::from(Asn1Ia5String::new("a@b").unwrap());
        let number = AttributeValue::from(Asn1Object::from(Asn1Integer::from(7)));
        let attribute = Attribute::new(
            "1.2.3".parse::<Asn1Oid>().unwrap(),
            vec![email.clone(), text.clone(), number.clone()],
        )
        .unwrap();
        let der = attribute.encode_to_vec(&EncodingOptions::DER).unwrap();
        let decoded = Attribute::decode_der(&der, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(decoded, attribute);
        assert_eq!(decoded.values(), &[number, text, email]);
        let ber = attribute.encode_to_vec(&EncodingOptions::BER).unwrap();
        assert_eq!(
            Attribute::decode(&ber, &DecodingOptions::default())
                .unwrap()
                .1
                .values(),
            attribute.values()
        );
    }

    #[test]
    fn single_and_multiple_attribute_values_round_trip_as_a_set() {
        for wire in [
            &b"\x30\x09\x06\x02\x2a\x03\x31\x03\x02\x01\x01"[..],
            &b"\x30\x0c\x06\x02\x2a\x03\x31\x06\x02\x01\x01\x02\x01\x02"[..],
        ] {
            let (used, value) = Attribute::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                Attribute::decode(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn missing_values_empty_sets_wrong_tags_and_extra_fields_are_rejected() {
        assert!(matches!(
            Attribute::decode(
                b"\x30\x06\x06\x02\x2a\x03\x31\x00",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            Attribute::decode(b"\x30\x04\x06\x02\x2a\x03", &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        ));
        assert!(matches!(
            Attribute::decode(
                b"\x30\x09\x06\x02\x2a\x03\x30\x03\x02\x01\x01",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Attribute::decode(
                b"\x30\x0b\x06\x02\x2a\x03\x31\x03\x02\x01\x01\x05\x00",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::TrailingData)
        ));
    }

    #[test]
    fn an_attribute_cannot_be_constructed_without_values() {
        let oid = "1.2.3".parse::<Asn1Oid>().unwrap();
        assert!(matches!(
            Attribute::new(oid, vec![]),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
