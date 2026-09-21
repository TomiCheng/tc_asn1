//! X.690 §8.6 BIT STRING, universal tag 3.
//!
//! The contents are one octet giving the number of unused bits in the last
//! data octet (0 to 7, and 0 when there is no data) followed by the bits
//! packed most significant first. DER (§11.2.1) requires the unused bits to
//! be zero; this type always writes them so and rejects set unused bits
//! when the DER rules are on. The further DER rule for a named bit list,
//! dropping trailing zero bits (§11.2.2), is the named type's business,
//! not this one's: a plain BIT STRING keeps its length.
//!
//! This type reads and writes the primitive form only; the constructed form
//! BER allows and CER requires over 1000 octets is
//! [`Asn1Constructed`](crate::Asn1Constructed) with tag `23`.

use alloc::vec::Vec;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// A bit string of any length, kept as packed octets plus the count of
/// unused bits in the last one.
///
/// Whole octets, such as a public key or a signature, come from
/// [`from_bytes`](Self::from_bytes); a bit count that is not a multiple of
/// eight, such as a flag set, from [`from_bits`](Self::from_bits).
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// // Three bits, 101: one data octet with five unused bits.
/// let flags = Asn1BitString::from_bits(&[0b1010_0000], 3);
/// assert_eq!(flags.bit_len(), 3);
/// assert!(flags.bit(0) && !flags.bit(1) && flags.bit(2));
/// assert!(!flags.bit(3));   // past the end is never set
///
/// let der = flags.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x03, 0x02, 0x05, 0xA0]);
/// let (_, back) = Asn1BitString::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, flags);
///
/// // Whole octets have no unused bits.
/// let key = Asn1BitString::from_bytes(&[0x12, 0x34]);
/// assert_eq!((key.unused_bits(), key.bit_len()), (0, 16));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1BitString {
    unused_bits: u8,
    bytes: Vec<u8>,
}

impl Asn1BitString {
    /// The identifier octets, [`tag::BIT_STRING`](crate::tag::BIT_STRING).
    pub const TAG: &'static [u8] = super::tag::BIT_STRING;

    /// Every bit of `bytes`, no unused bits.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            unused_bits: 0,
            bytes: bytes.to_vec(),
        }
    }

    /// The first `bit_len` bits of `bytes`, most significant bit of the
    /// first octet first. Octets past the last needed one are dropped and
    /// the unused bits of the last one are cleared; a `bit_len` beyond
    /// `bytes` is clamped to what is there.
    pub fn from_bits(bytes: &[u8], bit_len: usize) -> Self {
        let byte_len = bit_len.div_ceil(8).min(bytes.len());
        let bit_len = bit_len.min(byte_len * 8);
        let unused_bits = (byte_len * 8 - bit_len) as u8;
        let mut bytes = bytes[..byte_len].to_vec();
        mask_unused(&mut bytes, unused_bits);
        Self { unused_bits, bytes }
    }

    /// The packed bits; the unused bits of the last octet are zero.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 0 to 7, and 0 when there are no octets.
    pub fn unused_bits(&self) -> u8 {
        self.unused_bits
    }

    /// The number of bits, the unused ones excluded.
    pub fn bit_len(&self) -> usize {
        self.bytes.len() * 8 - usize::from(self.unused_bits)
    }

    /// Bit `index` counted from the most significant bit of the first
    /// octet; `false` past [`bit_len`](Self::bit_len).
    pub fn bit(&self, index: usize) -> bool {
        index < self.bit_len() && self.bytes[index / 8] & (0x80 >> (index % 8)) != 0
    }
}

fn mask_unused(bytes: &mut [u8], unused_bits: u8) {
    if let Some(last) = bytes.last_mut() {
        *last &= 0xFF << unused_bits;
    }
}

impl DecodeInner for Asn1BitString {
    /// The primitive form only: the constructed tag `23` is
    /// `UnexpectedTag` here.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1BitString {}
impl Tagged for Asn1BitString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1BitString {
    /// No octets at all, an unused-bit count over 7 or a nonzero count
    /// with no data are `MalformedValue`. Set unused bits are cleared
    /// under BER and `NotDer` under DER. Variable time: branches only on
    /// the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let (unused_bits, data) = value.split_first().ok_or(Asn1Error::MalformedValue)?;
        if *unused_bits > 7 || (data.is_empty() && *unused_bits != 0) {
            return Err(Asn1Error::MalformedValue);
        }
        let mut bytes = data.to_vec();
        mask_unused(&mut bytes, *unused_bits);
        // X.690 §11.2.1: DER requires the unused bits to be zero.
        if context.is_der() && bytes.last() != data.last() {
            return Err(Asn1Error::NotDer);
        }
        Ok(Self {
            unused_bits: *unused_bits,
            bytes,
        })
    }
}

impl EncodeContent for Asn1BitString {
    /// The primitive contents: unused-bit count followed by the data.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        1 + self.bytes.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..1 + self.bytes.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out[0] = self.unused_bits;
        out[1..].copy_from_slice(&self.bytes);
        Ok(out.len())
    }
}

impl EncodeTagged for Asn1BitString {
    /// Always primitive. Under CER contents over 1000 octets (the count
    /// octet included) are [`Asn1Error::PrimitiveTooLong`]. Variable time:
    /// branches only on the encoding structure.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(1 + self.bytes.len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1BitString {
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

    use super::Asn1BitString;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn from_bits_keeps_only_the_named_bits_and_clears_the_rest() {
        let three = Asn1BitString::from_bits(&[0b1011_1111, 0xFF], 3);
        assert_eq!((three.as_bytes(), three.unused_bits()), (&[0xA0][..], 5));
        assert_eq!(three.bit_len(), 3);

        let nine = Asn1BitString::from_bits(&[0xFF, 0xFF, 0xFF], 9);
        assert_eq!(
            (nine.as_bytes(), nine.unused_bits()),
            (&[0xFF, 0x80][..], 7)
        );

        let whole = Asn1BitString::from_bits(&[0x12, 0x34], 16);
        assert_eq!(whole, Asn1BitString::from_bytes(&[0x12, 0x34]));

        let none = Asn1BitString::from_bits(&[0xFF], 0);
        assert_eq!(
            (none.as_bytes(), none.unused_bits(), none.bit_len()),
            (&[][..], 0, 0)
        );
    }

    #[test]
    fn a_bit_length_beyond_the_octets_is_clamped() {
        let value = Asn1BitString::from_bits(&[0xFF], 20);
        assert_eq!((value.bit_len(), value.unused_bits()), (8, 0));
    }

    #[test]
    fn bits_are_numbered_from_the_most_significant_bit_of_the_first_octet() {
        let value = Asn1BitString::from_bits(&[0b1000_0001, 0b0100_0000], 10);
        assert!(value.bit(0));
        assert!(!value.bit(1));
        assert!(value.bit(7));
        assert!(!value.bit(8));
        assert!(value.bit(9));
        assert!(!value.bit(10)); // past bit_len
        assert!(!value.bit(1000));
    }

    #[test]
    fn the_wire_form_is_the_unused_count_then_the_octets() {
        for (value, wire) in [
            (Asn1BitString::from_bytes(&[]), &[0x03, 0x01, 0x00][..]),
            (
                Asn1BitString::from_bytes(&[0x12, 0x34]),
                &[0x03, 0x03, 0x00, 0x12, 0x34],
            ),
            (
                Asn1BitString::from_bits(&[0b1010_0000], 3),
                &[0x03, 0x02, 0x05, 0xA0],
            ),
        ] {
            assert_eq!(value.encode_to_vec(&der()).unwrap(), wire);
            let (used, back) = Asn1BitString::decode(wire, &options()).unwrap();
            assert_eq!((used, &back), (wire.len(), &value));
            assert_eq!(
                Asn1BitString::decode_der(wire, &options()).unwrap().1,
                value
            );
        }
    }

    #[test]
    fn set_unused_bits_are_cleared_under_ber_and_rejected_under_der() {
        let wire = [0x03, 0x02, 0x05, 0xA7];
        let (_, value) = Asn1BitString::decode(&wire, &options()).unwrap();
        assert_eq!(value, Asn1BitString::from_bits(&[0xA0], 3));
        assert_eq!(
            value.encode_to_vec(&der()).unwrap(),
            [0x03, 0x02, 0x05, 0xA0]
        );
        assert!(matches!(
            Asn1BitString::decode_der(&wire, &options()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn missing_count_octet_count_over_7_or_unused_bits_without_data_are_malformed() {
        for wire in [
            &[0x03, 0x00][..],         // no contents at all
            &[0x03, 0x02, 0x08, 0x00], // 8 unused bits
            &[0x03, 0x01, 0x01],       // unused bits but no data octet
        ] {
            assert!(matches!(
                Asn1BitString::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn the_constructed_form_and_other_tags_are_unexpected() {
        assert!(matches!(
            Asn1BitString::decode(&[0x23, 0x03, 0x03, 0x01, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Asn1BitString::decode(&[0x04, 0x01, 0x00], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn cer_counts_the_unused_bit_octet_towards_the_1000_octet_limit() {
        let cer = EncodingOptions::CER;
        assert!(
            Asn1BitString::from_bytes(&vec![0; 999])
                .encode_to_vec(&cer)
                .is_ok()
        );
        assert!(matches!(
            Asn1BitString::from_bytes(&vec![0; 1000]).encode_to_vec(&cer),
            Err(Asn1Error::PrimitiveTooLong)
        ));
        assert!(
            Asn1BitString::from_bytes(&vec![0; 1000])
                .encode_to_vec(&der())
                .is_ok()
        );
    }
}
