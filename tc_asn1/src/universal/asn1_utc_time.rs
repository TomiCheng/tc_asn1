//! X.680 §47 `UTCTime`, universal tag 23: a time string with a two-digit
//! year, `YYMMDDhhmmssZ`.
//!
//! Only the DER form `YYMMDDhhmmssZ` is accepted (X.690 §11.8: seconds present,
//! `Z` only). The BER options of omitting the seconds or using a UTC offset are
//! **deliberately rejected**: RFC 5280 mandates the DER form, certificates never
//! carry anything else, and accepting offsets would mean time-zone arithmetic
//! for a case that does not occur. This is the one exception to lenient BER
//! decoding, for that reason.

use core::fmt;

use super::date_time::{DateTime, digits, two_digits};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Length of the DER form `YYMMDDhhmmssZ`.
const LEN: usize = 13;

/// A UTC instant to the second, year 1950-2049.
///
/// The year is expanded per RFC 5280 §4.1.2.5.1: `YY >= 50` is 19YY, otherwise
/// 20YY, so the representable range is 1950-2049. Later dates need
/// [`Asn1GeneralizedTime`](super::Asn1GeneralizedTime). Ordering is
/// chronological.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1UtcTime, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let not_before = Asn1UtcTime::new(2016, 8, 1, 12, 19, 24)?;
/// let der = not_before.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, b"\x17\x0D160801121924Z");
/// let (_, back) = Asn1UtcTime::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.to_string(), "2016-08-01T12:19:24Z");
///
/// // 2050 does not fit two digits under the RFC 5280 rule.
/// assert!(matches!(Asn1UtcTime::new(2050, 1, 1, 0, 0, 0), Err(Asn1Error::MalformedValue)));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1UtcTime(DateTime);

impl Asn1UtcTime {
    pub const TAG: &'static [u8] = super::tag::UTC_TIME;

    /// Year 1950-2049; the other fields follow `DateTime::checked`.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        if !(1950..=2049).contains(&year) {
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

/// ISO 8601, `2016-08-01T12:19:24Z`.
impl fmt::Display for Asn1UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl DecodeInner for Asn1UtcTime {
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

impl Decode for Asn1UtcTime {}
impl Tagged for Asn1UtcTime {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1UtcTime {
    /// Accepts `YYMMDDhhmmssZ` only. Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let [yy @ .., b'Z'] = value else {
            return Err(Asn1Error::MalformedValue);
        };
        if yy.len() != LEN - 1 {
            return Err(Asn1Error::MalformedValue);
        }
        let (year, fields) = yy.split_at(2);
        let yy = two_digits(year)?;
        let year = if yy >= 50 { 1900 } else { 2000 } + u16::from(yy);
        let inner = DateTime::from_fields(year, fields)?;
        Self::new(
            inner.year,
            inner.month,
            inner.day,
            inner.hour,
            inner.minute,
            inner.second,
        )
    }
}

impl EncodeContent for Asn1UtcTime {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        LEN
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out: &mut [u8; LEN] = out
            .get_mut(..LEN)
            .and_then(|out| out.try_into().ok())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out[0..2].copy_from_slice(&digits((self.0.year % 100) as u8));
        self.0
            .write_fields((&mut out[2..12]).try_into().expect("ten octets"));
        out[12] = b'Z';
        Ok(LEN)
    }
}

impl EncodeTagged for Asn1UtcTime {}

impl Encode for Asn1UtcTime {
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

    use super::Asn1UtcTime;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_two_digit_year_pivots_at_50() {
        let der = EncodingOptions::DER;
        for (fields, wire, text) in [
            (
                (1950, 1, 1, 0, 0, 0),
                &b"\x17\x0D500101000000Z"[..],
                "1950-01-01T00:00:00Z",
            ),
            (
                (1999, 12, 31, 23, 59, 59),
                b"\x17\x0D991231235959Z",
                "1999-12-31T23:59:59Z",
            ),
            (
                (2000, 2, 29, 12, 0, 0),
                b"\x17\x0D000229120000Z",
                "2000-02-29T12:00:00Z",
            ),
            (
                (2049, 12, 31, 23, 59, 59),
                b"\x17\x0D491231235959Z",
                "2049-12-31T23:59:59Z",
            ),
        ] {
            let (y, mo, d, h, mi, s) = fields;
            let value = Asn1UtcTime::new(y, mo, d, h, mi, s).unwrap();
            assert_eq!(value.encode_to_vec(&der).unwrap(), wire, "{text}");
            let (used, back) = Asn1UtcTime::decode(wire, &options()).unwrap();
            assert_eq!((used, back), (wire.len(), value));
            assert_eq!(back.to_string(), text);
            assert_eq!(Asn1UtcTime::decode_der(wire, &options()).unwrap().1, value);
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
        for year in [1949, 2050] {
            assert!(matches!(
                Asn1UtcTime::new(year, 1, 1, 0, 0, 0),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn only_the_der_form_with_seconds_and_z_is_accepted() {
        for wire in [
            &b"\x17\x0B1608011219Z"[..],  // no seconds
            b"\x17\x11160801121924+0800", // an offset instead of Z
            b"\x17\x0C160801121924",      // no Z
            b"\x17\x0D160801121924z",     // lowercase z
            b"\x17\x0D16O801121924Z",     // a letter among the digits
            b"\x17\x0F20160801121924Z",   // a four-digit year
        ] {
            assert!(
                matches!(
                    Asn1UtcTime::decode(wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{wire:02X?}"
            );
        }
    }

    #[test]
    fn the_calendar_is_checked_when_built_and_decoded() {
        assert!(Asn1UtcTime::new(2024, 2, 29, 0, 0, 0).is_ok());
        for (y, mo, d, h, mi, s) in [
            (2023, 2, 29, 0, 0, 0),
            (2024, 13, 1, 0, 0, 0),
            (2024, 4, 31, 0, 0, 0),
            (2024, 1, 1, 24, 0, 0),
            (2024, 1, 1, 0, 60, 0),
            (2024, 1, 1, 0, 0, 60),
        ] {
            assert!(matches!(
                Asn1UtcTime::new(y, mo, d, h, mi, s),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            Asn1UtcTime::decode(b"\x17\x0D230229000000Z", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn ordering_is_chronological_and_another_tag_is_unexpected() {
        let earlier = Asn1UtcTime::new(1999, 12, 31, 23, 59, 59).unwrap();
        let later = Asn1UtcTime::new(2000, 1, 1, 0, 0, 0).unwrap();
        assert!(earlier < later);
        assert!(matches!(
            Asn1UtcTime::decode(b"\x18\x0F20160801121924Z", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
