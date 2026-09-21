//! Encoding wrappers for tagged fields: `[n] EXPLICIT T` and `[n] IMPLICIT T`.
//!
//! Both borrow the value and the identifier octets to write it under, so a
//! structure's `encode_content` can wrap a field without copying it. The
//! decoding side is `Children::get_explicit_opt` and friends.

use crate::{Asn1Error, Encode, EncodeContent, EncodeTagged, EncodingOptions};

/// `[n] EXPLICIT T`: the value's complete TLV wrapped in a constructed
/// element with the given tag, `A0 03 02 01 02` for `[0] EXPLICIT INTEGER 2`.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Integer, Encode, EncodingOptions, Explicit};
///
/// let version = Asn1Integer::from(2);
/// let out = Explicit::new(&[0xA0], &version).encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(out, [0xA0, 0x03, 0x02, 0x01, 0x02]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct Explicit<'a> {
    tag: &'a [u8],
    inner: &'a dyn Encode,
}

impl<'a> Explicit<'a> {
    /// `tag` must have the constructed bit set, since the wrapper holds a TLV.
    pub fn new(tag: &'a [u8], inner: &'a dyn Encode) -> Self {
        debug_assert!(
            tag.first().is_some_and(|b| b & 0x20 != 0),
            "an EXPLICIT tag must be constructed"
        );
        Self { tag, inner }
    }
}

impl EncodeContent for Explicit<'_> {
    /// The inner value's complete TLV. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.inner.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        self.inner.encode(rules, out)
    }
}

impl EncodeTagged for Explicit<'_> {}

impl Encode for Explicit<'_> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag, rules, out)
    }
}

/// `[n] IMPLICIT T`: the value's own identifier replaced by the given tag,
/// contents unchanged, `81 02 05 A0` for `[1] IMPLICIT BIT STRING`.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1BitString, Encode, EncodingOptions, Implicit};
///
/// let id = Asn1BitString::from_bits(&[0xA0], 3);
/// let out = Implicit::new(&[0x81], &id).encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(out, [0x81, 0x02, 0x05, 0xA0]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct Implicit<'a> {
    tag: &'a [u8],
    inner: &'a dyn Encode,
}

impl<'a> Implicit<'a> {
    /// `tag` keeps the inner type's primitive/constructed bit: `81` for a
    /// BIT STRING, `A1` for a SEQUENCE.
    pub fn new(tag: &'a [u8], inner: &'a dyn Encode) -> Self {
        Self { tag, inner }
    }
}

impl EncodeContent for Implicit<'_> {
    /// The inner value's contents as they are. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.inner.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        self.inner.encode_content(rules, out)
    }
}

/// Delegates to the inner value so its own header rules apply, such as a
/// SET OF being sorted or a SEQUENCE going indefinite under CER.
impl EncodeTagged for Implicit<'_> {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        self.inner.encoded_len_tagged(tag, rules)
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        self.inner.encode_tagged(tag, rules, out)
    }
}

impl Encode for Implicit<'_> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{Explicit, Implicit};
    use crate::{
        Asn1Error, Asn1Integer, Asn1OctetString, Asn1SequenceOf, Asn1SetOf, Encode,
        EncodingOptions, EncodingType, LengthForm,
    };

    fn rules(encoding: EncodingType) -> EncodingOptions {
        EncodingOptions::new(encoding)
    }

    #[test]
    fn explicit_wraps_the_whole_tlv_and_follows_the_length_form() {
        let list = Asn1SequenceOf::new(vec![Asn1Integer::from(1)]);
        let wrapped = Explicit::new(&[0xA3], &list);
        assert_eq!(wrapped.encoded_len(&rules(EncodingType::Der)), 7);
        assert_eq!(
            wrapped.encode_to_vec(&rules(EncodingType::Der)).unwrap(),
            [0xA3, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]
        );
        assert_eq!(
            wrapped.encode_to_vec(&rules(EncodingType::Cer)).unwrap(),
            [
                0xA3, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00
            ]
        );
        let mut short = [0u8; 6];
        assert!(matches!(
            wrapped.encode(&rules(EncodingType::Der), &mut short),
            Err(Asn1Error::BufferTooSmall)
        ));
    }

    #[test]
    fn implicit_replaces_the_tag_and_leaves_the_inner_rules_in_force() {
        let set = Asn1SetOf::new(vec![Asn1Integer::from(2), Asn1Integer::from(1)]);
        let retagged = Implicit::new(&[0xA1], &set);
        assert_eq!(
            retagged.encode_to_vec(&rules(EncodingType::Der)).unwrap(),
            [0xA1, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02] // sorted, as a SET OF is
        );
        assert_eq!(
            retagged
                .encode_to_vec(&rules(EncodingType::Ber(LengthForm::Definite)))
                .unwrap(),
            [0xA1, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]
        );
        // a primitive keeps its contents under the new tag
        let octets = Asn1OctetString::new(&[0xAA, 0xBB]);
        assert_eq!(
            Implicit::new(&[0x84], &octets)
                .encode_to_vec(&rules(EncodingType::Der))
                .unwrap(),
            [0x84, 0x02, 0xAA, 0xBB]
        );
        // the constructed bit is forced on for a constructed inner value
        assert_eq!(
            Implicit::new(&[0x81], &set)
                .encode_to_vec(&rules(EncodingType::Der))
                .unwrap()[0],
            0xA1
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "must be constructed")]
    fn an_explicit_tag_without_the_constructed_bit_is_a_programming_error() {
        Explicit::new(&[0x80], &Asn1Integer::from(1));
    }
}
