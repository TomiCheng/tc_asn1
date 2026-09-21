//! X.690 §8.4 ENUMERATED, universal tag 10.
//!
//! The contents are those of an INTEGER: two's complement in the fewest
//! octets, with the same ban on redundant sign octets. Only the tag tells
//! the two apart, so an INTEGER where an ENUMERATED is expected is
//! `UnexpectedTag`. The schema gives each value a name; this type keeps
//! the number and leaves the names to the type defined on top of it, as
//! with a CRL reason code.

use alloc::vec::Vec;

use super::integer_octets::{minimal_signed, validate_integer_octets};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// An ENUMERATED value, kept as its two's-complement content octets.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Enumerated, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// // CRLReason keyCompromise(1), as an extension would carry it.
/// let reason = Asn1Enumerated::from(1u64);
/// let der = reason.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x0A, 0x01, 0x01]);
///
/// let (_, back) = Asn1Enumerated::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(u64::try_from(&back)?, 1);
///
/// // The same octets under the INTEGER tag are a different type.
/// assert!(matches!(
///     Asn1Enumerated::decode(&[0x02, 0x01, 0x01], &DecodingOptions::default()),
///     Err(Asn1Error::UnexpectedTag)
/// ));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Enumerated {
    value: Vec<u8>,
}

impl Asn1Enumerated {
    /// The identifier octets, [`tag::ENUMERATED`](crate::tag::ENUMERATED).
    pub const TAG: &'static [u8] = super::tag::ENUMERATED;

    /// From content octets: empty or with a redundant sign octet is
    /// `MalformedValue`. Variable time: branches on the first two octets.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_integer_octets(bytes)?;
        Ok(Self {
            value: bytes.to_vec(),
        })
    }

    /// The content octets: two's complement, never empty.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

impl From<u64> for Asn1Enumerated {
    /// The shortest two's complement of a non-negative value, a sign octet
    /// added when the high bit is set. Variable time: scans the redundant
    /// sign octets.
    fn from(value: u64) -> Self {
        let mut bytes = [0; 9];
        bytes[1..].copy_from_slice(&value.to_be_bytes());
        Self {
            value: minimal_signed(&bytes).to_vec(),
        }
    }
}

impl From<i64> for Asn1Enumerated {
    /// The shortest two's complement of a signed value. Variable time:
    /// scans the redundant sign octets.
    fn from(value: i64) -> Self {
        Self {
            value: minimal_signed(&value.to_be_bytes()).to_vec(),
        }
    }
}

impl TryFrom<&Asn1Enumerated> for u64 {
    type Error = Asn1Error;

    /// `MalformedValue` when negative, `LengthOverflow` when too big.
    /// Variable time: branches on the length and sign.
    fn try_from(value: &Asn1Enumerated) -> Result<Self, Self::Error> {
        if value.value[0] & 0x80 != 0 {
            return Err(Asn1Error::MalformedValue);
        }
        // drop the sign octet; zero leaves an empty slice, which folds to zero
        let bytes = value.value.strip_prefix(&[0]).unwrap_or(&value.value);
        if bytes.len() > 8 {
            return Err(Asn1Error::LengthOverflow);
        }
        Ok(bytes
            .iter()
            .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte)))
    }
}

impl TryFrom<&Asn1Enumerated> for i64 {
    type Error = Asn1Error;

    /// `LengthOverflow` when outside the `i64` range. Variable time:
    /// branches on the length and sign.
    fn try_from(value: &Asn1Enumerated) -> Result<Self, Self::Error> {
        if value.value.len() > 8 {
            return Err(Asn1Error::LengthOverflow);
        }
        let sign = if value.value[0] & 0x80 != 0 { 0xFF } else { 0 };
        let mut bytes = [sign; 8];
        bytes[8 - value.value.len()..].copy_from_slice(&value.value);
        Ok(Self::from_be_bytes(bytes))
    }
}

impl DecodeInner for Asn1Enumerated {
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

impl Decode for Asn1Enumerated {}
impl Tagged for Asn1Enumerated {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Enumerated {
    /// The INTEGER contents rules: non-empty, no redundant sign octet.
    /// Variable time: branches on the first two octets.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl EncodeContent for Asn1Enumerated {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.value.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.value.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.value);
        Ok(self.value.len())
    }
}

impl EncodeTagged for Asn1Enumerated {}

impl Encode for Asn1Enumerated {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::Asn1Enumerated;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_contents_are_the_shortest_twos_complement_under_tag_0a() {
        for (value, wire) in [
            (Asn1Enumerated::from(0u64), &[0x0A, 0x01, 0x00][..]),
            (Asn1Enumerated::from(1u64), &[0x0A, 0x01, 0x01]),
            (Asn1Enumerated::from(127u64), &[0x0A, 0x01, 0x7F]),
            (Asn1Enumerated::from(128u64), &[0x0A, 0x02, 0x00, 0x80]),
            (Asn1Enumerated::from(-1i64), &[0x0A, 0x01, 0xFF]),
            (Asn1Enumerated::from(-128i64), &[0x0A, 0x01, 0x80]),
            (Asn1Enumerated::from(-129i64), &[0x0A, 0x02, 0xFF, 0x7F]),
        ] {
            assert_eq!(value.encode_to_vec(&der()).unwrap(), wire);
            let (used, back) = Asn1Enumerated::decode(wire, &options()).unwrap();
            assert_eq!((used, &back), (wire.len(), &value));
            assert_eq!(
                Asn1Enumerated::decode_der(wire, &options()).unwrap().1,
                value
            );
        }
    }

    #[test]
    fn the_extremes_of_u64_and_i64_round_trip() {
        let max = Asn1Enumerated::from(u64::MAX);
        assert_eq!(max.as_bytes(), [&[0x00][..], &[0xFF; 8]].concat());
        assert_eq!(u64::try_from(&max).unwrap(), u64::MAX);
        assert!(matches!(
            i64::try_from(&max),
            Err(Asn1Error::LengthOverflow)
        ));

        let min = Asn1Enumerated::from(i64::MIN);
        assert_eq!(min.as_bytes(), [&[0x80][..], &[0x00; 7]].concat());
        assert_eq!(i64::try_from(&min).unwrap(), i64::MIN);
        assert!(matches!(
            u64::try_from(&min),
            Err(Asn1Error::MalformedValue)
        ));

        let same = Asn1Enumerated::from(i64::MAX);
        assert_eq!(same, Asn1Enumerated::from(i64::MAX as u64));
        assert_eq!(u64::try_from(&same).unwrap(), i64::MAX as u64);
    }

    #[test]
    fn nine_octets_of_magnitude_overflow_both_conversions() {
        let big = Asn1Enumerated::from_der_bytes(&[&[0x01][..], &[0x00; 8]].concat()).unwrap();
        assert!(matches!(
            u64::try_from(&big),
            Err(Asn1Error::LengthOverflow)
        ));
        assert!(matches!(
            i64::try_from(&big),
            Err(Asn1Error::LengthOverflow)
        ));
    }

    #[test]
    fn redundant_sign_octets_and_empty_contents_are_malformed() {
        for contents in [&[][..], &[0x00, 0x01], &[0xFF, 0xFF]] {
            assert!(matches!(
                Asn1Enumerated::from_der_bytes(contents),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            Asn1Enumerated::decode(&[0x0A, 0x02, 0x00, 0x01], &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn an_integer_tag_is_unexpected() {
        assert!(matches!(
            Asn1Enumerated::decode(&[0x02, 0x01, 0x01], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
