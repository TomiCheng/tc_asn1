//! X.690 §8.12 SET OF, universal tag 17 (`31`): an [`Asn1Constructed`]
//! whose elements are all one type and whose order carries no meaning.
//!
//! CER and DER therefore fix the order (§11.6): the members are written
//! sorted by their encodings compared as octet strings, so a SET OF has one
//! canonical form and two equal sets encode identically, which is what the
//! DN of a certificate relies on. Decoding keeps the wire order and does
//! not check it under DER.

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

use super::cer_common::constructed_tag;
use crate::traits::encode::{default_encode, default_encoded_len};
use crate::{
    Asn1Constructed, Asn1Error, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

/// A homogeneous SET OF. Construction and decoding keep the given order; CER
/// and DER write the members sorted by their encodings (X.690 §11.6), BER
/// writes them as stored.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Integer, Asn1SetOf, Encode, EncodingOptions};
///
/// let set = Asn1SetOf::new(vec![Asn1Integer::from(2), Asn1Integer::from(1)]);
///
/// // DER sorts by encoding; BER writes the members as given.
/// let der = set.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
/// let ber = set.encode_to_vec(&EncodingOptions::BER)?;
/// assert_eq!(ber, [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]);
///
/// // The order is not part of the value.
/// assert_eq!(set, Asn1SetOf::new(vec![Asn1Integer::from(1), Asn1Integer::from(2)]));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Asn1SetOf<T> {
    members: Asn1Constructed<T>,
}

/// Two sets are equal when their DER encodings are, so the stored order does
/// not matter. Should encoding fail, which a valid value never does under DER,
/// the sets compare unequal, even to themselves.
impl<T: Encode> PartialEq for Asn1SetOf<T> {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self.encode_to_vec(&EncodingOptions::DER), other.encode_to_vec(&EncodingOptions::DER)),
            (Ok(a), Ok(b)) if a == b
        )
    }
}

impl<T: Encode> Eq for Asn1SetOf<T> {}

/// Hashes the DER encoding, matching [`PartialEq`].
impl<T: Encode> Hash for Asn1SetOf<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Ok(der) = self.encode_to_vec(&EncodingOptions::DER) {
            der.hash(state);
        }
    }
}

impl<T> Asn1SetOf<T> {
    /// The identifier octets, [`tag::SET`](crate::tag::SET).
    pub const TAG: &'static [u8] = super::tag::SET;

    /// From the members in any order; CER and DER sort them on output.
    pub fn new(members: Vec<T>) -> Self {
        Self {
            members: Asn1Constructed::new(Self::TAG, members),
        }
    }

    /// The members in the stored order: the order given to `new` or the
    /// wire order, not the sorted one.
    pub fn members(&self) -> &[T] {
        self.members.items()
    }

    /// [`members`](Self::members), owned.
    pub fn into_members(self) -> Vec<T> {
        self.members.into_items()
    }
}

impl<T: DecodeInner> DecodeContent for Asn1SetOf<T> {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let elements = Children::from_contents(value, context)?.collect_all()?;
        Ok(Self::new(elements))
    }
}

impl<T: DecodeInner> DecodeInner for Asn1SetOf<T> {
    /// A SEQUENCE or a primitive tag is `UnexpectedTag`; so is a member that
    /// is not a `T`. The order is kept as found and not checked, even under
    /// DER. Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, members) = Asn1Constructed::decode_inner(buff, context)?;
        if members.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        Ok((used, Self { members }))
    }
}

impl<T: DecodeInner> Decode for Asn1SetOf<T> {}
impl<T> Tagged for Asn1SetOf<T> {
    const TAG: &'static [u8] = Self::TAG;
}

impl<T: Encode> EncodeContent for Asn1SetOf<T> {
    /// Sorting does not change the length. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.members.content_len(rules)
    }

    /// BER writes the members as stored. CER and DER encode each member,
    /// sort the encodings as octet strings and write them in that order.
    /// Variable time: the sort compares public encodings.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        if !rules.is_canonical() {
            return self.members.encode_content(rules, out);
        }
        let mut encodings = self
            .members
            .items()
            .iter()
            .map(|member| member.encode_to_vec(rules))
            .collect::<Result<Vec<_>, _>>()?;
        encodings.sort();
        let total = encodings.iter().map(Vec::len).sum();
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        let mut at = 0;
        for encoding in &encodings {
            out[at..at + encoding.len()].copy_from_slice(encoding);
            at += encoding.len();
        }
        Ok(at)
    }
}

/// The default header with the constructed bit forced on, as for [`Asn1Constructed`].
impl<T: Encode> EncodeTagged for Asn1SetOf<T> {
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

impl<T: Encode> Encode for Asn1SetOf<T> {
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
    use core::hash::{Hash, Hasher};

    use super::Asn1SetOf;
    use crate::{
        Asn1Error, Asn1Integer, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
        EncodingType, LengthForm,
    };

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn rules(encoding: EncodingType) -> EncodingOptions {
        EncodingOptions::new(encoding)
    }

    fn integers(values: &[i32]) -> Asn1SetOf<Asn1Integer> {
        Asn1SetOf::new(values.iter().map(|n| Asn1Integer::from(*n)).collect())
    }

    /// FNV-1a, enough to see whether two values hash alike.
    struct Fnv(u64);
    impl Hasher for Fnv {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3);
            }
        }
    }
    fn fnv<T: Hash>(value: &T) -> u64 {
        let mut hasher = Fnv(0xcbf2_9ce4_8422_2325);
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn der_and_cer_sort_by_encoding_and_ber_keeps_the_stored_order() {
        let set = integers(&[2, 1]);
        assert_eq!(
            set.encode_to_vec(&rules(EncodingType::Der)).unwrap(),
            [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
        assert_eq!(
            set.encode_to_vec(&rules(EncodingType::Cer)).unwrap(),
            [0x31, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00]
        );
        for form in [LengthForm::Definite, LengthForm::Indefinite] {
            let ber = set.encode_to_vec(&rules(EncodingType::Ber(form))).unwrap();
            assert_eq!(&ber[2..8], &[0x02, 0x01, 0x02, 0x02, 0x01, 0x01]);
        }
        assert_eq!(set.members()[0], Asn1Integer::from(2)); // still as given
    }

    #[test]
    fn the_sort_compares_encodings_as_octet_strings_not_values() {
        // 256 is `02 02 01 00`, -1 is `02 01 FF`: as octet strings, 2 < 256 < -1.
        let set = integers(&[-1, 256, 2]);
        assert_eq!(
            set.encode_to_vec(&rules(EncodingType::Der)).unwrap(),
            [
                0x31, 0x0A, 0x02, 0x01, 0x02, 0x02, 0x01, 0xFF, 0x02, 0x02, 0x01, 0x00
            ]
        );
        // a shorter encoding that is a prefix of a longer one comes first
        let set = Asn1SetOf::new(vec![
            Asn1OctetString::new(&[0x01, 0x00]),
            Asn1OctetString::new(&[0x01]),
        ]);
        assert_eq!(
            set.encode_to_vec(&rules(EncodingType::Der)).unwrap(),
            [0x31, 0x07, 0x04, 0x01, 0x01, 0x04, 0x02, 0x01, 0x00]
        );
    }

    #[test]
    fn equality_and_hashing_ignore_the_stored_order() {
        let a = integers(&[1, 2, 3]);
        let b = integers(&[3, 1, 2]);
        assert_eq!(a, b);
        assert_eq!(fnv(&a), fnv(&b));
        assert_ne!(a, integers(&[1, 2]));
        assert_ne!(a, integers(&[1, 2, 3, 3])); // a multiset: the duplicate counts
    }

    #[test]
    fn decoding_keeps_the_wire_order_and_re_encodes_sorted() {
        let unsorted = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        let (used, set) = Asn1SetOf::<Asn1Integer>::decode(&unsorted, &options()).unwrap();
        assert_eq!(used, 8);
        assert_eq!(set.members(), [Asn1Integer::from(2), Asn1Integer::from(1)]);
        assert_eq!(
            set.encode_to_vec(&rules(EncodingType::Der)).unwrap(),
            [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
        assert_eq!(set.into_members().len(), 2);
        let (_, empty) = Asn1SetOf::<Asn1Integer>::decode(&[0x31, 0x00], &options()).unwrap();
        assert!(empty.members().is_empty());
    }

    #[test]
    fn the_wrong_container_tag_or_member_type_is_unexpected() {
        for wire in [
            &[0x30, 0x03, 0x02, 0x01, 0x01][..], // SEQUENCE OF
            &[0x11, 0x03, 0x02, 0x01, 0x01],     // primitive
            &[0x31, 0x03, 0x04, 0x01, 0x01],     // an OCTET STRING among the INTEGERs
        ] {
            assert!(
                matches!(
                    Asn1SetOf::<Asn1Integer>::decode(wire, &options()),
                    Err(Asn1Error::UnexpectedTag)
                ),
                "{wire:02X?}"
            );
        }
    }
}
