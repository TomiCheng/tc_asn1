//! X.690 §8.3 INTEGER, universal tag 2.
//!
//! The contents are the value in two's complement, big-endian, in the
//! fewest octets that hold it: a leading `00` is allowed only before a set
//! high bit and a leading `FF` only before a clear one (§8.3.2). The rule
//! is part of BER, not just DER, so a redundant sign octet is
//! `MalformedValue` whatever the context. There is no size limit; a
//! certificate serial number or an RSA modulus is kept as its octets and
//! converted to a primitive integer only when the caller asks and it fits.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::integer_octets::{minimal_signed, validate_integer_octets};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodingOptions, Tagged,
};

/// An INTEGER of any size, kept as its two's-complement content octets.
///
/// Built from a primitive integer with `From`, from a big-endian magnitude
/// with [`from_unsigned_bytes`](Self::from_unsigned_bytes) or from content
/// octets with [`from_der_bytes`](Self::from_der_bytes); read back with
/// `TryFrom<&Asn1Integer>` for the primitive types,
/// [`as_unsigned_bytes`](Self::as_unsigned_bytes) for a magnitude and the
/// `Display`, `LowerHex` and `UpperHex` formats.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let der = EncodingOptions::DER;
///
/// // Small values take the fewest octets; the sign bit decides how many.
/// assert_eq!(Asn1Integer::from(127).encode_to_vec(&der)?, [0x02, 0x01, 0x7F]);
/// assert_eq!(Asn1Integer::from(128).encode_to_vec(&der)?, [0x02, 0x02, 0x00, 0x80]);
/// assert_eq!(Asn1Integer::from(-128).encode_to_vec(&der)?, [0x02, 0x01, 0x80]);
///
/// // A serial number is built from its magnitude and read back in any base.
/// let serial = Asn1Integer::from_unsigned_bytes(&[0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x15, 0x4b]);
/// assert_eq!(serial.to_string(), "288230376151782731");
/// assert_eq!(format!("{serial:x}"), "40000000001154b");
/// assert_eq!(u64::try_from(&serial)?, 288_230_376_151_782_731);
///
/// // Too big for the asked type is an error, not a truncation.
/// assert!(matches!(u32::try_from(&serial), Err(Asn1Error::LengthOverflow)));
///
/// let (_, back) = Asn1Integer::decode(&serial.encode_to_vec(&der)?, &DecodingOptions::default())?;
/// assert_eq!(back, serial);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Integer {
    value: Vec<u8>,
}

impl Asn1Integer {
    pub const TAG: &'static [u8] = super::tag::INTEGER;

    /// From content octets: empty or with a redundant sign octet is
    /// `MalformedValue`. Variable time: branches on the first two octets.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_integer_octets(bytes)?;
        Ok(Self {
            value: bytes.to_vec(),
        })
    }

    /// A non-negative value from its big-endian magnitude: leading zeros
    /// are dropped and a `00` is put in front when the high bit is set,
    /// so `[]`, `[00]` and `[00 00]` are all zero. Variable time: scans the
    /// leading zeros.
    pub fn from_unsigned_bytes(magnitude: &[u8]) -> Self {
        let start = magnitude
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        let significant = &magnitude[start..];
        let mut value = Vec::with_capacity(significant.len() + 1);
        if significant.first().is_none_or(|b| b & 0x80 != 0) {
            value.push(0x00); // zero is a single 00; a set high bit needs a sign octet
        }
        value.extend_from_slice(significant);
        Self { value }
    }

    fn from_signed_bytes(twos_complement: &[u8]) -> Self {
        Self {
            value: minimal_signed(twos_complement).to_vec(),
        }
    }

    /// The content octets: two's complement, never empty.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    pub fn is_negative(&self) -> bool {
        self.value[0] & 0x80 != 0
    }

    /// The big-endian magnitude without the sign octet, `[00]` for zero;
    /// a negative value is `MalformedValue`. What a modulus or a serial
    /// number is usually wanted as. Variable time: branches on the sign.
    pub fn as_unsigned_bytes(&self) -> Result<&[u8], Asn1Error> {
        if self.is_negative() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(match self.value.as_slice() {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            v => v,
        })
    }

    /// The unsigned reading: `MalformedValue` when negative,
    /// `LengthOverflow` when it does not fit.
    fn to_u128(&self) -> Result<u128, Asn1Error> {
        let bytes = self.as_unsigned_bytes()?;
        if bytes.len() > 16 {
            return Err(Asn1Error::LengthOverflow);
        }
        Ok(bytes
            .iter()
            .fold(0_u128, |acc, b| (acc << 8) | u128::from(*b)))
    }

    /// The absolute value, big-endian without leading zeros; empty for zero.
    fn magnitude(&self) -> Vec<u8> {
        let mut magnitude = self.value.clone();
        if self.is_negative() {
            // two's complement: invert, then add one from the low end
            let mut carry = true;
            for byte in magnitude.iter_mut().rev() {
                *byte = !*byte;
                if carry {
                    let (sum, overflow) = byte.overflowing_add(1);
                    *byte = sum;
                    carry = overflow;
                }
            }
        }
        let start = magnitude
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        magnitude.drain(..start);
        magnitude
    }

    /// The magnitude in decimal, by long division; `"0"` for zero.
    fn decimal_digits(&self) -> String {
        let mut magnitude = self.magnitude();
        let mut digits = Vec::new();
        while !magnitude.is_empty() {
            let mut remainder = 0u16;
            for byte in &mut magnitude {
                let current = (remainder << 8) | u16::from(*byte);
                *byte = (current / 10) as u8;
                remainder = current % 10;
            }
            digits.push(b'0' + remainder as u8);
            if magnitude[0] == 0 {
                magnitude.remove(0);
            }
        }
        if digits.is_empty() {
            digits.push(b'0');
        }
        digits.reverse();
        String::from_utf8(digits).expect("ASCII digits")
    }

    /// The magnitude in hex without a leading zero digit; `"0"` for zero.
    fn hex_digits(&self, upper: bool) -> String {
        let magnitude = self.magnitude();
        let mut digits = String::with_capacity(magnitude.len() * 2);
        for (i, byte) in magnitude.iter().enumerate() {
            let (high, low) = (byte >> 4, byte & 0x0F);
            if i > 0 || high != 0 {
                digits.push(hex_digit(high, upper));
            }
            digits.push(hex_digit(low, upper));
        }
        if digits.is_empty() {
            digits.push('0');
        }
        digits
    }

    /// The signed reading: `LengthOverflow` when it does not fit.
    fn to_i128(&self) -> Result<i128, Asn1Error> {
        if self.value.len() > 16 {
            return Err(Asn1Error::LengthOverflow);
        }
        let sign: i128 = if self.is_negative() { -1 } else { 0 };
        Ok(self
            .value
            .iter()
            .fold(sign, |acc, b| (acc << 8) | i128::from(*b)))
    }
}

fn hex_digit(nibble: u8, upper: bool) -> char {
    let digit = match nibble {
        0..=9 => b'0' + nibble,
        _ if upper => b'A' + nibble - 10,
        _ => b'a' + nibble - 10,
    };
    char::from(digit)
}

/// Decimal, with a leading `-` when negative. Width, fill and `+` are
/// honoured as for the primitive integers.
impl fmt::Display for Asn1Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(!self.is_negative(), "", &self.decimal_digits())
    }
}

/// The magnitude in lowercase hex, `-` first when negative, `0x` with `#`.
impl fmt::LowerHex for Asn1Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(!self.is_negative(), "0x", &self.hex_digits(false))
    }
}

/// The magnitude in uppercase hex, `-` first when negative, `0x` with `#`.
impl fmt::UpperHex for Asn1Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(!self.is_negative(), "0x", &self.hex_digits(true))
    }
}

macro_rules! from_unsigned {
    ($($t:ty),*) => {$(
        impl From<$t> for Asn1Integer {
            fn from(n: $t) -> Self {
                Self::from_unsigned_bytes(&n.to_be_bytes())
            }
        }
    )*};
}
macro_rules! from_signed {
    ($($t:ty),*) => {$(
        impl From<$t> for Asn1Integer {
            fn from(n: $t) -> Self {
                Self::from_signed_bytes(&n.to_be_bytes())
            }
        }
    )*};
}
from_unsigned!(u8, u16, u32, u64, u128);
from_signed!(i8, i16, i32, i64, i128);

macro_rules! try_into_unsigned {
    ($($t:ty),*) => {$(
        impl TryFrom<&Asn1Integer> for $t {
            type Error = Asn1Error;
            /// `MalformedValue` when negative, `LengthOverflow` when too big.
            fn try_from(n: &Asn1Integer) -> Result<Self, Asn1Error> {
                <$t>::try_from(n.to_u128()?).map_err(|_| Asn1Error::LengthOverflow)
            }
        }
    )*};
}
macro_rules! try_into_signed {
    ($($t:ty),*) => {$(
        impl TryFrom<&Asn1Integer> for $t {
            type Error = Asn1Error;
            /// `LengthOverflow` when outside the type's range.
            fn try_from(n: &Asn1Integer) -> Result<Self, Asn1Error> {
                <$t>::try_from(n.to_i128()?).map_err(|_| Asn1Error::LengthOverflow)
            }
        }
    )*};
}
try_into_unsigned!(u8, u16, u32, u64, u128);
try_into_signed!(i8, i16, i32, i64, i128);

impl DecodeInner for Asn1Integer {
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

impl Decode for Asn1Integer {}
impl Tagged for Asn1Integer {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Integer {
    /// [`from_der_bytes`](Self::from_der_bytes) after the length limit; the
    /// shortest-form rule is BER's, so there is nothing more for DER to
    /// check.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl crate::EncodeContent for Asn1Integer {
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

impl crate::EncodeTagged for Asn1Integer {}

impl Encode for Asn1Integer {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    use super::Asn1Integer;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_sign_bit_decides_the_octet_count_at_every_boundary() {
        for (value, wire) in [
            (Asn1Integer::from(0), &[0x02, 0x01, 0x00][..]),
            (Asn1Integer::from(1), &[0x02, 0x01, 0x01]),
            (Asn1Integer::from(127), &[0x02, 0x01, 0x7F]),
            (Asn1Integer::from(128), &[0x02, 0x02, 0x00, 0x80]),
            (Asn1Integer::from(255), &[0x02, 0x02, 0x00, 0xFF]),
            (Asn1Integer::from(256), &[0x02, 0x02, 0x01, 0x00]),
            (Asn1Integer::from(-1), &[0x02, 0x01, 0xFF]),
            (Asn1Integer::from(-128), &[0x02, 0x01, 0x80]),
            (Asn1Integer::from(-129), &[0x02, 0x02, 0xFF, 0x7F]),
            (Asn1Integer::from(-256), &[0x02, 0x02, 0xFF, 0x00]),
        ] {
            assert_eq!(value.encode_to_vec(&der()).unwrap(), wire, "{value}");
            let (used, back) = Asn1Integer::decode(wire, &options()).unwrap();
            assert_eq!((used, &back), (wire.len(), &value));
            assert_eq!(Asn1Integer::decode_der(wire, &options()).unwrap().1, value);
        }
    }

    #[test]
    fn every_primitive_type_encodes_the_same_value_the_same_way() {
        assert_eq!(Asn1Integer::from(200u8), Asn1Integer::from(200i16));
        assert_eq!(Asn1Integer::from(200u64), Asn1Integer::from(200i128));
        assert_eq!(Asn1Integer::from(-5i8), Asn1Integer::from(-5i64));
        assert_eq!(
            Asn1Integer::from(u128::MAX).as_bytes(),
            [&[0x00][..], &[0xFF; 16]].concat()
        );
        assert_eq!(
            Asn1Integer::from(i128::MIN).as_bytes(),
            [&[0x80][..], &[0x00; 15]].concat()
        );
    }

    #[test]
    fn a_magnitude_drops_leading_zeros_and_gains_a_sign_octet_when_needed() {
        for (magnitude, contents) in [
            (&[][..], &[0x00][..]),
            (&[0x00], &[0x00]),
            (&[0x00, 0x00, 0x01], &[0x01]),
            (&[0x7F], &[0x7F]),
            (&[0x80], &[0x00, 0x80]),
            (&[0x00, 0xFF, 0xFF], &[0x00, 0xFF, 0xFF]),
        ] {
            let value = Asn1Integer::from_unsigned_bytes(magnitude);
            assert_eq!(value.as_bytes(), contents);
            assert!(!value.is_negative());
        }
    }

    #[test]
    fn as_unsigned_bytes_strips_the_sign_octet_and_refuses_negatives() {
        assert_eq!(Asn1Integer::from(128).as_unsigned_bytes().unwrap(), [0x80]);
        assert_eq!(Asn1Integer::from(0).as_unsigned_bytes().unwrap(), [0x00]);
        assert_eq!(Asn1Integer::from(1).as_unsigned_bytes().unwrap(), [0x01]);
        assert!(matches!(
            Asn1Integer::from(-1).as_unsigned_bytes(),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(Asn1Integer::from(-1).is_negative());
    }

    #[test]
    fn redundant_sign_octets_are_malformed_even_under_ber() {
        for contents in [&[][..], &[0x00, 0x7F], &[0xFF, 0x80], &[0x00, 0x00]] {
            assert!(matches!(
                Asn1Integer::from_der_bytes(contents),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(Asn1Integer::from_der_bytes(&[0x00, 0x80]).is_ok());
        assert!(Asn1Integer::from_der_bytes(&[0xFF, 0x7F]).is_ok());
        assert!(matches!(
            Asn1Integer::decode(&[0x02, 0x02, 0x00, 0x01], &options()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            Asn1Integer::decode(&[0x02, 0x00], &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn conversions_fail_on_range_not_on_representation() {
        assert_eq!(u8::try_from(&Asn1Integer::from(255)).unwrap(), 255);
        assert!(matches!(
            u8::try_from(&Asn1Integer::from(256)),
            Err(Asn1Error::LengthOverflow)
        ));
        assert!(matches!(
            u8::try_from(&Asn1Integer::from(-1)),
            Err(Asn1Error::MalformedValue)
        ));
        assert_eq!(i8::try_from(&Asn1Integer::from(-128)).unwrap(), -128);
        assert!(matches!(
            i8::try_from(&Asn1Integer::from(128)),
            Err(Asn1Error::LengthOverflow)
        ));
        assert_eq!(
            u128::try_from(&Asn1Integer::from(u128::MAX)).unwrap(),
            u128::MAX
        );
        assert_eq!(
            i128::try_from(&Asn1Integer::from(i128::MIN)).unwrap(),
            i128::MIN
        );
        // 2^128 has a 17-octet magnitude
        let too_big = Asn1Integer::from_unsigned_bytes(&[&[0x01][..], &[0x00; 16]].concat());
        assert!(matches!(
            u128::try_from(&too_big),
            Err(Asn1Error::LengthOverflow)
        ));
        assert!(matches!(
            i128::try_from(&too_big),
            Err(Asn1Error::LengthOverflow)
        ));
    }

    #[test]
    fn display_and_hex_follow_the_primitive_integer_formats() {
        let two_to_64 = Asn1Integer::from_unsigned_bytes(&[&[0x01][..], &[0x00; 8]].concat());
        assert_eq!(two_to_64.to_string(), "18446744073709551616");
        assert_eq!(format!("{two_to_64:x}"), "10000000000000000");
        assert_eq!(Asn1Integer::from(-255).to_string(), "-255");
        assert_eq!(format!("{:#x}", Asn1Integer::from(-255)), "-0xff");
        assert_eq!(format!("{:X}", Asn1Integer::from(48879)), "BEEF");
        assert_eq!(format!("{:+}", Asn1Integer::from(42)), "+42");
        assert_eq!(format!("{:08}", Asn1Integer::from(-42)), "-0000042");
        assert_eq!(format!("{:>5}|", Asn1Integer::from(0)), "    0|");
        assert_eq!(
            format!("{:x}", Asn1Integer::from(i128::MIN)),
            "-80000000000000000000000000000000"
        );
    }

    #[test]
    fn a_long_value_round_trips_through_the_long_length_form() {
        let modulus = Asn1Integer::from_unsigned_bytes(&vec![0xC3; 256]);
        let wire = modulus.encode_to_vec(&der()).unwrap();
        assert_eq!(wire[..5], [0x02, 0x82, 0x01, 0x01, 0x00]); // 257 contents octets
        let (used, back) = Asn1Integer::decode(&wire, &options()).unwrap();
        assert_eq!(
            (used, back.as_unsigned_bytes().unwrap()),
            (wire.len(), &[0xC3; 256][..])
        );
    }

    #[test]
    fn another_tag_is_unexpected() {
        assert!(matches!(
            Asn1Integer::decode(&[0x0A, 0x01, 0x01], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
