//! An organization and the notice numbers it assigns.
//!
//! ```text
//! NoticeReference ::= SEQUENCE {
//!     organization  DisplayText,
//!     noticeNumbers SEQUENCE OF INTEGER }
//! ```

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::ext::DisplayText;

/// Identifies notices published by an organization. The number list may be empty.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::{DisplayText, NoticeReference};
///
/// let reference = NoticeReference::new(DisplayText::new("Example")?, vec![1.into(), 2.into()]);
/// assert_eq!(reference.to_string(), "Example: 1, 2");
/// let der = reference.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(NoticeReference::decode_der(&der, &DecodingOptions::default())?.1, reference);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NoticeReference {
    organization: DisplayText,
    notice_numbers: Asn1SequenceOf<Asn1Integer>,
}

impl NoticeReference {
    /// Creates a reference; notice numbers are kept in the supplied order.
    pub fn new(organization: DisplayText, notice_numbers: Vec<Asn1Integer>) -> Self {
        Self {
            organization,
            notice_numbers: Asn1SequenceOf::new(notice_numbers),
        }
    }

    /// Returns the organization text.
    pub fn organization(&self) -> &DisplayText {
        &self.organization
    }

    /// Returns the notice numbers, possibly empty.
    pub fn notice_numbers(&self) -> &[Asn1Integer] {
        self.notice_numbers.elements()
    }
}

impl fmt::Display for NoticeReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.organization)?;
        for (i, number) in self.notice_numbers().iter().enumerate() {
            f.write_str(if i == 0 { " " } else { ", " })?;
            write!(f, "{number}")?;
        }
        Ok(())
    }
}

impl DecodeInner for NoticeReference {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let organization = fields.get::<DisplayText>()?;
        let notice_numbers = fields.get::<Asn1SequenceOf<Asn1Integer>>()?;
        fields.end()?;
        Ok((
            element.total_len(),
            Self {
                organization,
                notice_numbers,
            },
        ))
    }
}

impl EncodeContent for NoticeReference {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.organization.encoded_len(rules) + self.notice_numbers.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.organization.encode(rules, out)?;
        Ok(at + self.notice_numbers.encode(rules, &mut out[at..])?)
    }
}

impl Decode for NoticeReference {}

impl Tagged for NoticeReference {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for NoticeReference {}

impl Encode for NoticeReference {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::NoticeReference;
    use crate::ext::DisplayText;
    use alloc::{string::ToString, vec};
    use tc_asn1::{Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};

    #[test]
    fn missing_fields_are_rejected() {
        for wire in [&b"\x30\x00"[..], &b"\x30\x03\x0c\x01O"[..]] {
            assert!(matches!(
                NoticeReference::decode(wire, &DecodingOptions::default()),
                Err(tc_asn1::Asn1Error::Truncated)
            ));
        }
    }

    #[test]
    fn extra_fields_are_rejected() {
        let wire = &b"\x30\x07\x0c\x01O\x30\x00\x05\x00"[..];
        assert!(matches!(
            NoticeReference::decode(wire, &DecodingOptions::default()),
            Err(tc_asn1::Asn1Error::TrailingData)
        ));
    }

    #[test]
    fn wrong_tags_are_rejected() {
        for wire in [
            &b"\x31\x00"[..],
            &b"\x30\x05\x13\x01O\x30\x00"[..],
            &b"\x30\x05\x0c\x01O\x31\x00"[..],
        ] {
            assert!(matches!(
                NoticeReference::decode(wire, &DecodingOptions::default()),
                Err(tc_asn1::Asn1Error::UnexpectedTag)
            ));
        }
    }

    #[test]
    fn notice_numbers_may_be_empty_and_preserve_their_order() {
        for numbers in [vec![], vec![Asn1Integer::from(1), Asn1Integer::from(2)]] {
            let value = NoticeReference::new(DisplayText::new("Org").unwrap(), numbers.clone());
            let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                NoticeReference::decode_der(&der, &DecodingOptions::default()).unwrap(),
                (der.len(), value.clone())
            );
            assert_eq!(value.notice_numbers(), numbers);
            assert_eq!(
                value.to_string(),
                if numbers.is_empty() {
                    "Org:"
                } else {
                    "Org: 1, 2"
                }
            );
        }
        let value = NoticeReference::new(DisplayText::new("O").unwrap(), vec![]);
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x30\x05\x0c\x01O\x30\x00"
        );
    }
}
