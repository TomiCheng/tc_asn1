//! X.680 §46 `GeneralizedTime`, universal tag 24: a time string with a
//! four-digit year, `YYYYMMDDhhmmssZ`.
//!
//! Only `YYYYMMDDhhmmssZ` is accepted. X.690 §11.7 lets DER carry non-zero
//! fractional seconds, but RFC 5280 §4.1.2.5.2 forbids them in certificates, so
//! fractions are rejected too. UTC offsets and omitted seconds are rejected for
//! the same reason as in [`Asn1UtcTime`](super::Asn1UtcTime).

use core::fmt;

use super::date_time::{DateTime, digits, two_digits};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Length of `YYYYMMDDhhmmssZ`.
const LEN: usize = 15;

/// A UTC instant to the second, year 0-9999.
///
/// RFC 5280 requires this type from 2050 on and
/// [`Asn1UtcTime`](super::Asn1UtcTime) before; a certificate's `notAfter`
/// of `99991231235959Z` means no expiry. Ordering is chronological.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1GeneralizedTime, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let not_after = Asn1GeneralizedTime::new(2050, 1, 1, 0, 0, 0)?;
/// let der = not_after.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, b"\x18\x0F20500101000000Z");
/// let (_, back) = Asn1GeneralizedTime::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.to_string(), "2050-01-01T00:00:00Z");
///
/// // Fractional seconds are DER but not PKIX, and are refused.
/// assert!(matches!(
///     Asn1GeneralizedTime::decode(b"\x18\x1120500101000000.5Z", &DecodingOptions::default()),
///     Err(Asn1Error::MalformedValue)
/// ));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1GeneralizedTime(DateTime);

impl Asn1GeneralizedTime {
    pub const TAG: &'static [u8] = super::tag::GENERALIZED_TIME;

    /// Year 0-9999; the other fields follow `DateTime::checked`.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        if year > 9999 {
            return Err(Asn1Error::MalformedValue);
        }
        DateTime::checked(year, month, day, hour, minute, second).map(Self)
    }

    pub fn year(&self) -> u16 {
        self.0.year
    }
    pub fn month(&self) -> u8 {
        self.0.month
    }
    pub fn day(&self) -> u8 {
        self.0.day
    }
    pub fn hour(&self) -> u8 {
        self.0.hour
    }
    pub fn minute(&self) -> u8 {
        self.0.minute
    }
    pub fn second(&self) -> u8 {
        self.0.second
    }
}

/// ISO 8601, `2050-01-01T00:00:00Z`.
impl fmt::Display for Asn1GeneralizedTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl DecodeInner for Asn1GeneralizedTime {
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

impl Decode for Asn1GeneralizedTime {}
impl Tagged for Asn1GeneralizedTime {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1GeneralizedTime {
    /// Accepts `YYYYMMDDhhmmssZ` only. Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let [body @ .., b'Z'] = value else {
            return Err(Asn1Error::MalformedValue);
        };
        if body.len() != LEN - 1 {
            return Err(Asn1Error::MalformedValue);
        }
        let (year, fields) = body.split_at(4);
        let [hi, lo] = year.as_chunks::<2>().0 else {
            return Err(Asn1Error::MalformedValue);
        };
        let year = u16::from(two_digits(hi)?) * 100 + u16::from(two_digits(lo)?);
        DateTime::from_fields(year, fields).map(Self)
    }
}

impl EncodeContent for Asn1GeneralizedTime {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        LEN
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out: &mut [u8; LEN] = out
            .get_mut(..LEN)
            .and_then(|out| out.try_into().ok())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out[0..2].copy_from_slice(&digits((self.0.year / 100) as u8));
        out[2..4].copy_from_slice(&digits((self.0.year % 100) as u8));
        self.0
            .write_fields((&mut out[4..14]).try_into().expect("ten octets"));
        out[14] = b'Z';
        Ok(LEN)
    }
}

impl EncodeTagged for Asn1GeneralizedTime {}

impl Encode for Asn1GeneralizedTime {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::Asn1GeneralizedTime;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_four_digit_year_covers_0_to_9999() {
        let der = EncodingOptions::DER;
        for (fields, wire, text) in [
            (
                (0, 1, 1, 0, 0, 0),
                &b"\x18\x0F00000101000000Z"[..],
                "0000-01-01T00:00:00Z",
            ),
            (
                (2040, 12, 31, 23, 59, 59),
                b"\x18\x0F20401231235959Z",
                "2040-12-31T23:59:59Z",
            ),
            (
                (9999, 12, 31, 23, 59, 59),
                b"\x18\x0F99991231235959Z",
                "9999-12-31T23:59:59Z",
            ),
        ] {
            let (y, mo, d, h, mi, s) = fields;
            let value = Asn1GeneralizedTime::new(y, mo, d, h, mi, s).unwrap();
            assert_eq!(value.encode_to_vec(&der).unwrap(), wire, "{text}");
            let (used, back) = Asn1GeneralizedTime::decode(wire, &options()).unwrap();
            assert_eq!((used, back), (wire.len(), value));
            assert_eq!(back.to_string(), text);
            assert_eq!(
                Asn1GeneralizedTime::decode_der(wire, &options()).unwrap().1,
                value
            );
            assert_eq!(
                (
                    back.year(),
                    back.month(),
                    back.day(),
                    back.hour(),
                    back.minute(),
                    back.second()
                ),
                fields
            );
        }
        assert!(matches!(
            Asn1GeneralizedTime::new(10000, 1, 1, 0, 0, 0),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn fractions_offsets_and_short_forms_are_rejected() {
        for wire in [
            &b"\x18\x1120401231235959.5Z"[..], // fractional seconds
            b"\x18\x1320401231235959+0800",    // an offset
            b"\x18\x0E20401231235959",         // no Z
            b"\x18\x0D204012312359Z",          // no seconds
            b"\x18\x0D401231235959Z",          // a two-digit year
            b"\x18\x0F20230229000000Z",        // not a leap year
        ] {
            assert!(
                matches!(
                    Asn1GeneralizedTime::decode(wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{wire:02X?}"
            );
        }
        assert!(Asn1GeneralizedTime::decode(b"\x18\x0F20240229000000Z", &options()).is_ok());
    }

    #[test]
    fn ordering_is_chronological_and_the_utctime_tag_is_unexpected() {
        let earlier = Asn1GeneralizedTime::new(2049, 12, 31, 23, 59, 59).unwrap();
        let later = Asn1GeneralizedTime::new(2050, 1, 1, 0, 0, 0).unwrap();
        assert!(earlier < later);
        assert!(matches!(
            Asn1GeneralizedTime::decode(b"\x17\x0D160801121924Z", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
