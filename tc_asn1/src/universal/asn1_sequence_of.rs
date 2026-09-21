//! X.690 §8.10 SEQUENCE OF, universal tag 16 (`30`): an
//! [`Asn1Constructed`] whose elements are all one type, written in the
//! stored order under every rule set.
//!
//! A SEQUENCE with fields of different types is not this; such a structure
//! implements the traits itself and reads its fields through
//! [`Children`](crate::Children).

use alloc::vec::Vec;

use super::cer_common::constructed_tag;
use crate::traits::encode::{default_encode, default_encoded_len};
use crate::{
    Asn1Constructed, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// A homogeneous SEQUENCE OF. Order is significant, so every rule set writes
/// the elements as stored.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Integer, Asn1SequenceOf, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let list = Asn1SequenceOf::new(vec![Asn1Integer::from(2), Asn1Integer::from(1)]);
/// let der = list.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]);   // 2 then 1, as given
///
/// let (_, back) = Asn1SequenceOf::<Asn1Integer>::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.elements().len(), 2);
/// assert_eq!(back, list);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1SequenceOf<T> {
    elements: Asn1Constructed<T>,
}

impl<T> Asn1SequenceOf<T> {
    /// The identifier octets, [`tag::SEQUENCE`](crate::tag::SEQUENCE).
    pub const TAG: &'static [u8] = super::tag::SEQUENCE;

    /// From the elements in wire order.
    pub fn new(elements: Vec<T>) -> Self {
        Self {
            elements: Asn1Constructed::new(Self::TAG, elements),
        }
    }

    /// The elements in the stored order, which is the wire order.
    pub fn elements(&self) -> &[T] {
        self.elements.items()
    }

    /// [`elements`](Self::elements), owned.
    pub fn into_elements(self) -> Vec<T> {
        self.elements.into_items()
    }
}

impl<T: DecodeInner> DecodeInner for Asn1SequenceOf<T> {
    /// A SET or a primitive tag is `UnexpectedTag`; so is an element that
    /// is not a `T`. Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, elements) = Asn1Constructed::decode_inner(buff, context)?;
        if elements.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        Ok((used, Self { elements }))
    }
}

impl<T: DecodeInner> Decode for Asn1SequenceOf<T> {}
impl<T> Tagged for Asn1SequenceOf<T> {
    const TAG: &'static [u8] = Self::TAG;
}

impl<T: Encode> EncodeContent for Asn1SequenceOf<T> {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.elements.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.elements.encode_content(rules, out)
    }
}

/// The default header with the constructed bit forced on, as for [`Asn1Constructed`].
impl<T: Encode> EncodeTagged for Asn1SequenceOf<T> {
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

impl<T: Encode> Encode for Asn1SequenceOf<T> {
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
    use alloc::vec::Vec;

    use super::Asn1SequenceOf;
    use crate::{
        Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions, EncodingType,
        LengthForm,
    };

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn integers(values: &[i32]) -> Asn1SequenceOf<Asn1Integer> {
        Asn1SequenceOf::new(values.iter().map(|n| Asn1Integer::from(*n)).collect())
    }

    #[test]
    fn the_elements_are_written_back_to_back_in_the_stored_order() {
        for (list, wire) in [
            (integers(&[]), &[0x30, 0x00][..]),
            (integers(&[1]), &[0x30, 0x03, 0x02, 0x01, 0x01]),
            (
                integers(&[2, 1]),
                &[0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01],
            ),
        ] {
            assert_eq!(list.encode_to_vec(&der()).unwrap(), wire);
            let (used, back) = Asn1SequenceOf::<Asn1Integer>::decode(wire, &options()).unwrap();
            assert_eq!((used, &back), (wire.len(), &list));
            assert_eq!(
                Asn1SequenceOf::<Asn1Integer>::decode_der(wire, &options())
                    .unwrap()
                    .1,
                list
            );
        }
        assert_eq!(
            integers(&[2, 1]).into_elements(),
            vec![Asn1Integer::from(2), Asn1Integer::from(1)]
        );
    }

    #[test]
    fn indefinite_length_is_written_on_request_and_read_under_ber_only() {
        let list = integers(&[1]);
        let indefinite = list
            .encode_to_vec(&EncodingOptions::new(EncodingType::Ber(
                LengthForm::Indefinite,
            )))
            .unwrap();
        assert_eq!(indefinite, [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]);
        let (used, back) = Asn1SequenceOf::<Asn1Integer>::decode(&indefinite, &options()).unwrap();
        assert_eq!((used, back), (7, list));
        assert!(matches!(
            Asn1SequenceOf::<Asn1Integer>::decode_der(&indefinite, &options()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn nesting_works_to_the_depth_limit() {
        let nested = Asn1SequenceOf::new(vec![integers(&[1, 2]), integers(&[])]);
        let wire = nested.encode_to_vec(&der()).unwrap();
        assert_eq!(
            wire,
            [
                0x30, 0x0A, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x30, 0x00
            ]
        );
        let (_, back) =
            Asn1SequenceOf::<Asn1SequenceOf<Asn1Integer>>::decode(&wire, &options()).unwrap();
        assert_eq!(back, nested);
        assert!(matches!(
            Asn1SequenceOf::<Asn1SequenceOf<Asn1Integer>>::decode(
                &wire,
                &DecodingOptions::new(1, 1024, 16)
            ),
            Err(Asn1Error::DepthExceeded)
        ));
    }

    #[test]
    fn the_wrong_container_tag_or_element_type_is_unexpected() {
        for wire in [
            &[0x31, 0x03, 0x02, 0x01, 0x01][..], // SET OF
            &[0x04, 0x03, 0x02, 0x01, 0x01],     // primitive
            &[0x30, 0x03, 0x04, 0x01, 0x01],     // an OCTET STRING among the INTEGERs
        ] {
            assert!(
                matches!(
                    Asn1SequenceOf::<Asn1Integer>::decode(wire, &options()),
                    Err(Asn1Error::UnexpectedTag)
                ),
                "{wire:02X?}"
            );
        }
    }

    #[test]
    fn the_children_limit_applies() {
        let mut wire = Vec::from([0x30, 0x09]);
        wire.extend_from_slice(&[0x02, 0x01, 0x01].repeat(3));
        assert!(
            Asn1SequenceOf::<Asn1Integer>::decode(&wire, &DecodingOptions::new(8, 64, 3)).is_ok()
        );
        assert!(matches!(
            Asn1SequenceOf::<Asn1Integer>::decode(&wire, &DecodingOptions::new(8, 64, 2)),
            Err(Asn1Error::ChildrenExceeded)
        ));
    }
}
