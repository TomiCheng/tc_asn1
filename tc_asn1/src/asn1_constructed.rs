//! A constructed encoding of any tag holding elements of one type.

use alloc::vec::Vec;

use crate::traits::encode::{default_encode, default_encoded_len};
use crate::universal::cer_common::constructed_tag;
use crate::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions,
};

/// A constructed encoding: an identifier and a series of `T` values.
///
/// This is the one mechanism behind SEQUENCE OF, SET OF and the constructed
/// string forms. The identifier is whatever the value was built or read with
/// (`30` for SEQUENCE OF, `31` for SET OF, `24` for a segmented OCTET STRING,
/// `A0` for `[0] IMPLICIT`, ...); decoding accepts any constructed identifier
/// and keeps it, so checking that it is the expected one is the caller's job.
/// With `T = Asn1Any` the elements are kept as raw TLVs.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Constructed, Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// // `[1] IMPLICIT SEQUENCE OF INTEGER` holding one value.
/// let field = Asn1Constructed::new(&[0xA1], vec![Asn1Integer::from(5)]);
/// let der = field.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0xA1, 0x03, 0x02, 0x01, 0x05]);
///
/// let (_, back) = Asn1Constructed::<Asn1Integer>::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.tag(), [0xA1]);   // kept, not checked
/// assert_eq!(back.items(), [Asn1Integer::from(5)]);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Constructed<T> {
    tag: Vec<u8>,
    items: Vec<T>,
}

impl<T> Asn1Constructed<T> {
    /// `tag` is a complete identifier; its constructed bit is set if missing.
    pub fn new(tag: &[u8], items: Vec<T>) -> Self {
        let mut tag = tag.to_vec();
        if let Some(first) = tag.first_mut() {
            *first |= 0x20;
        }
        Self { tag, items }
    }

    /// The identifier, constructed bit set.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// The elements in the stored order.
    pub fn items(&self) -> &[T] {
        &self.items
    }

    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}

impl<T: DecodeInner> DecodeInner for Asn1Constructed<T> {
    /// Any constructed identifier is accepted and kept; each child is one `T`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if !element.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut children = element.children(context)?;
        let mut items = Vec::new();
        while let Some(child) = children.next() {
            let child = child?;
            let (used, item) = T::decode_inner(child.raw(), children.context())?;
            debug_assert_eq!(used, child.total_len(), "child length disagrees");
            items.push(item);
        }
        Ok((
            element.total_len(),
            Self {
                tag: element.tag().to_vec(),
                items,
            },
        ))
    }
}

impl<T: DecodeInner> Decode for Asn1Constructed<T> {}

impl<T: Encode> EncodeContent for Asn1Constructed<T> {
    /// The elements' TLVs back to back. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.items.iter().map(|item| item.encoded_len(rules)).sum()
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let total = self.content_len(rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        let mut at = 0;
        for item in &self.items {
            at += item.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

/// The default header with the constructed bit forced on: definite length,
/// or `80 ... 00 00` under CER and indefinite BER.
impl<T: Encode> EncodeTagged for Asn1Constructed<T> {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        default_encoded_len(self, &constructed_tag(tag), rules)
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        default_encode(self, &constructed_tag(tag), rules, out)
    }
}

impl<T: Encode> Encode for Asn1Constructed<T> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(&self.tag, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(&self.tag, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::Asn1Constructed;
    use crate::{
        Asn1Any, Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_constructed_bit_is_forced_on_when_building() {
        let value = Asn1Constructed::new(&[0x80], vec![Asn1Integer::from(5)]);
        assert_eq!(value.tag(), [0xA0]);
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0xA0, 0x03, 0x02, 0x01, 0x05]
        );
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::CER).unwrap(),
            [0xA0, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]
        );
        assert_eq!(value.into_items(), vec![Asn1Integer::from(5)]);
    }

    #[test]
    fn any_constructed_identifier_is_accepted_and_a_primitive_one_is_not() {
        for wire in [
            &[0xA1, 0x03, 0x02, 0x01, 0x05][..],
            &[0x30, 0x03, 0x02, 0x01, 0x05],
            &[0x7F, 0x81, 0x00, 0x03, 0x02, 0x01, 0x05], // APPLICATION 128, constructed
        ] {
            let (used, value) = Asn1Constructed::<Asn1Integer>::decode(wire, &options()).unwrap();
            assert_eq!(
                (used, value.items()),
                (wire.len(), &[Asn1Integer::from(5)][..])
            );
            assert_eq!(value.tag(), &wire[..wire.len() - 3 - 2 + 1]);
        }
        assert!(matches!(
            Asn1Constructed::<Asn1Integer>::decode(&[0x81, 0x01, 0x05], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Asn1Constructed::<Asn1Integer>::decode(&[0xA1, 0x02, 0x05, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn with_any_elements_the_children_stay_raw() {
        let wire = [0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00];
        let (_, value) = Asn1Constructed::<Asn1Any>::decode(&wire, &options()).unwrap();
        assert_eq!(value.items().len(), 2);
        assert_eq!(value.items()[0].raw(), [0x02, 0x01, 0x01]);
        assert_eq!(value.items()[1].raw(), [0x05, 0x00]);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
    }
}
