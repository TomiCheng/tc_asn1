//! RFC 5280 §4.2.1.8 subject directory attributes.
//!
//! ```text
//! SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
//! ```
//!
//! Attribute OIDs may repeat. Values are preserved without interpreting their OIDs.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use tc_asn1_x500::Attribute;

/// A non-empty list of subject attributes in wire order.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Oid, Asn1Object, Asn1Integer};
/// use tc_asn1_x500::Attribute;
/// use tc_asn1_x509::ext::SubjectDirectoryAttributes;
///
/// let attribute = Attribute::new("1.2.3".parse::<Asn1Oid>()?,
///     vec![Asn1Object::from(Asn1Integer::from(1)).into()])?;
/// let attributes = SubjectDirectoryAttributes::new(vec![attribute])?;
/// assert_eq!(attributes.attributes().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SubjectDirectoryAttributes {
    attributes: Asn1SequenceOf<Attribute>,
}

impl SubjectDirectoryAttributes {
    /// Creates a list. An empty list returns [`Asn1Error::MalformedValue`].
    pub fn new(attributes: Vec<Attribute>) -> Result<Self, Asn1Error> {
        if attributes.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            attributes: Asn1SequenceOf::new(attributes),
        })
    }

    /// Returns the attributes in wire order, never empty.
    pub fn attributes(&self) -> &[Attribute] {
        self.attributes.elements()
    }
}

/// Displays the attributes separated by `, `.
impl fmt::Display for SubjectDirectoryAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, attribute) in self.attributes().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{attribute}")?;
        }
        Ok(())
    }
}

impl DecodeContent for SubjectDirectoryAttributes {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let attributes = Asn1SequenceOf::<Attribute>::decode_content(value, context)?;
        Self::new(attributes.into_elements())
    }
}

impl DecodeInner for SubjectDirectoryAttributes {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for SubjectDirectoryAttributes {}

impl Tagged for SubjectDirectoryAttributes {
    const TAG: &'static [u8] = Asn1SequenceOf::<Attribute>::TAG;
}

impl EncodeContent for SubjectDirectoryAttributes {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.attributes.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.attributes.encode_content(rules, out)
    }
}

impl EncodeTagged for SubjectDirectoryAttributes {}

impl Encode for SubjectDirectoryAttributes {
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

    use super::SubjectDirectoryAttributes;

    #[test]
    fn repeated_attribute_oids_are_preserved_in_wire_order() {
        for wire in [
            &b"\x30\x0b\x30\x09\x06\x02\x2a\x03\x31\x03\x02\x01\x01"[..],
            &b"\x30\x16\x30\x09\x06\x02\x2a\x03\x31\x03\x02\x01\x01\x30\x09\x06\x02\x2a\x03\x31\x03\x02\x01\x02"[..],
        ] {
            let (used, value) = SubjectDirectoryAttributes::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(SubjectDirectoryAttributes::decode(wire, &DecodingOptions::default()).unwrap().1, value);
        }
    }

    #[test]
    fn empty_lists_wrong_containers_and_non_attribute_members_are_rejected() {
        assert!(matches!(
            SubjectDirectoryAttributes::decode(b"\x30\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            SubjectDirectoryAttributes::decode(b"\x31\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            SubjectDirectoryAttributes::decode(b"\x30\x02\x05\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn subject_directory_attributes_cannot_be_empty() {
        assert!(matches!(
            SubjectDirectoryAttributes::new(vec![]),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
