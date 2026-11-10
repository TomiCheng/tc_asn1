//! X.680 §46 `GeneralizedTime`, universal tag 24: a time string with a
//! four-digit year, `YYYYMMDDhhmmss[.f]Z`.
//!
//! Fractional seconds are accepted to the nanosecond, nine digits, as X.690
//! §11.7 lets DER carry them and RFC 3161 timestamps use them. Under DER the
//! fraction is written with a full stop and without trailing zeros, and a
//! zero fraction is left out; BER also accepts a comma and trailing zeros.
//! RFC 5280 §4.1.2.5.2 forbids fractions in certificates, which is for the
//! crates that read certificates to enforce. UTC offsets and omitted seconds
//! are rejected for the same reason as in [`Asn1UtcTime`](super::Asn1UtcTime).

use core::fmt;

use super::date_time::{DateTime, digits, two_digits};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Length of `YYYYMMDDhhmmssZ`.
const LEN: usize = 15;

/// Nanoseconds in a second, the bound of the fraction.
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// The fraction's nine digits and how many of them are written after the
/// full stop, trailing zeros removed: none for a whole second.
fn fraction_digits(nanosecond: u32) -> ([u8; 9], usize) {
    let mut out = [b'0'; 9];
    let mut value = nanosecond;
    for slot in out.iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let len = out
        .iter()
        .rposition(|&digit| digit != b'0')
        .map_or(0, |at| at + 1);
    (out, len)
}

/// Reads `.f` or `,f`, one to nine digits, as nanoseconds; nothing is 0.
/// Under DER only a full stop and no trailing zero are allowed.
fn read_fraction(fraction: &[u8], context: &DecodingContext) -> Result<u32, Asn1Error> {
    let [separator, digits @ ..] = fraction else {
        return Ok(0);
    };
    if !matches!(separator, b'.' | b',') || digits.is_empty() || digits.len() > 9 {
        return Err(Asn1Error::MalformedValue);
    }
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(Asn1Error::MalformedValue);
    }
    if context.is_der() && (*separator == b',' || digits.last() == Some(&b'0')) {
        return Err(Asn1Error::NotDer);
    }
    let value = digits
        .iter()
        .fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'));
    Ok(value * 10u32.pow(9 - digits.len() as u32))
}
/// A UTC instant to the nanosecond, year 0-9999.
///
/// RFC 5280 requires this type from 2050 on and
/// [`Asn1UtcTime`](super::Asn1UtcTime) before; a certificate's `notAfter`
/// of `99991231235959Z` means no expiry, and a certificate's times carry no
/// fractional seconds. Ordering is chronological.
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
/// // A timestamp's fractional seconds, written without trailing zeros.
/// let stamp = Asn1GeneralizedTime::new(2026, 11, 10, 8, 30, 0)?.with_nanosecond(120_000_000)?;
/// assert_eq!(stamp.encode_to_vec(&EncodingOptions::DER)?, b"\x18\x1220261110083000.12Z");
/// assert_eq!(stamp.to_string(), "2026-11-10T08:30:00.12Z");
/// # Ok::<(), Asn1Error>(())
/// ```
// Field order is chronological order, so the derived `Ord` compares instants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1GeneralizedTime {
    date_time: DateTime,
    nanosecond: u32,
}

impl Asn1GeneralizedTime {
    /// The identifier octets, [`tag::GENERALIZED_TIME`](crate::tag::GENERALIZED_TIME).
    pub const TAG: &'static [u8] = super::tag::GENERALIZED_TIME;

    /// Year 0-9999; the other fields follow `DateTime::checked`. No
    /// fractional seconds; add them with
    /// [`with_nanosecond`](Self::with_nanosecond). Variable time: branches
    /// only on the fields.
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
        DateTime::checked(year, month, day, hour, minute, second).map(|date_time| Self {
            date_time,
            nanosecond: 0,
        })
    }

    /// The same instant with `nanosecond` fractional seconds, 0-999 999 999;
    /// any other is `MalformedValue`. Constant time.
    pub fn with_nanosecond(self, nanosecond: u32) -> Result<Self, Asn1Error> {
        if nanosecond >= NANOS_PER_SECOND {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { nanosecond, ..self })
    }

    /// The same instant with `microsecond` fractional seconds, 0-999 999;
    /// any other is `MalformedValue`. Constant time.
    pub fn with_microsecond(self, microsecond: u32) -> Result<Self, Asn1Error> {
        if microsecond >= 1_000_000 {
            return Err(Asn1Error::MalformedValue);
        }
        self.with_nanosecond(microsecond * 1_000)
    }

    /// The same instant with `millisecond` fractional seconds, 0-999; any
    /// other is `MalformedValue`. Constant time.
    pub fn with_millisecond(self, millisecond: u16) -> Result<Self, Asn1Error> {
        if millisecond >= 1_000 {
            return Err(Asn1Error::MalformedValue);
        }
        self.with_nanosecond(u32::from(millisecond) * 1_000_000)
    }

    /// The year, 0-9999.
    pub fn year(&self) -> u16 {
        self.date_time.year
    }
    /// The month, 1-12.
    pub fn month(&self) -> u8 {
        self.date_time.month
    }
    /// The day of the month, 1-31.
    pub fn day(&self) -> u8 {
        self.date_time.day
    }
    /// The hour, 0-23.
    pub fn hour(&self) -> u8 {
        self.date_time.hour
    }
    /// The minute, 0-59.
    pub fn minute(&self) -> u8 {
        self.date_time.minute
    }
    /// The second, 0-59; leap seconds are not represented.
    pub fn second(&self) -> u8 {
        self.date_time.second
    }
    /// The fractional seconds in nanoseconds, 0-999 999 999; 0 for a whole
    /// second. Constant time.
    pub fn nanosecond(&self) -> u32 {
        self.nanosecond
    }
    /// The fractional seconds in whole microseconds, 0-999 999, rounding
    /// down: `.1234567` is 123 456. Constant time.
    pub fn microsecond(&self) -> u32 {
        self.nanosecond / 1_000
    }
    /// The fractional seconds in whole milliseconds, 0-999, rounding down:
    /// `.1239` is 123. Constant time.
    pub fn millisecond(&self) -> u16 {
        (self.nanosecond / 1_000_000) as u16
    }
}

/// ISO 8601, `2050-01-01T00:00:00Z`, with the fractional seconds before the
/// `Z` when there are any, `2050-01-01T00:00:00.5Z`.
impl fmt::Display for Asn1GeneralizedTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (digits, len) = fraction_digits(self.nanosecond);
        if len == 0 {
            return self.date_time.fmt(f);
        }
        let d = &self.date_time;
        let fraction = core::str::from_utf8(&digits[..len]).expect("ASCII digits");
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{fraction}Z",
            d.year, d.month, d.day, d.hour, d.minute, d.second
        )
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
    /// Accepts `YYYYMMDDhhmmssZ` with an optional fraction of one to nine
    /// digits before the `Z`. Under DER the fraction takes a full stop and no
    /// trailing zero, else `NotDer`. Variable time: branches only on the
    /// encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let [body @ .., b'Z'] = value else {
            return Err(Asn1Error::MalformedValue);
        };
        if body.len() < LEN - 1 {
            return Err(Asn1Error::MalformedValue);
        }
        let (whole, fraction) = body.split_at(LEN - 1);
        let (year, fields) = whole.split_at(4);
        let (hi, lo) = year.split_at(2);
        let year = u16::from(two_digits(hi)?) * 100 + u16::from(two_digits(lo)?);
        let date_time = DateTime::from_fields(year, fields)?;
        let nanosecond = read_fraction(fraction, context)?;
        Ok(Self {
            date_time,
            nanosecond,
        })
    }
}

impl EncodeContent for Asn1GeneralizedTime {
    /// `YYYYMMDDhhmmss`, then `.` and the fraction without trailing zeros
    /// when there is one, then `Z`. Constant time.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        match fraction_digits(self.nanosecond).1 {
            0 => LEN,
            len => LEN + 1 + len,
        }
    }

    /// The DER form for any rules. Variable time: branches only on the
    /// length of the fraction.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let total = self.content_len(rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        out[0..2].copy_from_slice(&digits((self.date_time.year / 100) as u8));
        out[2..4].copy_from_slice(&digits((self.date_time.year % 100) as u8));
        self.date_time
            .write_fields((&mut out[4..14]).try_into().expect("ten octets"));
        let (fraction, len) = fraction_digits(self.nanosecond);
        if len > 0 {
            out[14] = b'.';
            out[15..15 + len].copy_from_slice(&fraction[..len]);
        }
        out[total - 1] = b'Z';
        Ok(total)
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

#[cfg(feature = "zeroize")]
impl tc_zeroize::Zeroize for Asn1GeneralizedTime {
    /// Wipes the fields and leaves 0000-01-01 00:00:00 UTC, the earliest
    /// GeneralizedTime. Constant time.
    fn zeroize(&mut self) {
        self.date_time.wipe(0);
        self.nanosecond.zeroize();
    }
}

#[cfg(feature = "chrono")]
impl From<Asn1GeneralizedTime> for chrono::DateTime<chrono::Utc> {
    /// The same instant, fractional seconds included. Variable time:
    /// branches on the fields, which are public.
    fn from(value: Asn1GeneralizedTime) -> Self {
        use chrono::Timelike;
        value
            .date_time
            .to_chrono()
            .with_nanosecond(value.nanosecond)
            .expect("a nanosecond below one second")
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<chrono::DateTime<chrono::Utc>> for Asn1GeneralizedTime {
    type Error = Asn1Error;

    /// Truncates to the second, as it did before the type carried fractional
    /// seconds; [`with_nanosecond`](Asn1GeneralizedTime::with_nanosecond)
    /// adds them back. A leap second becomes `:59`. A year outside 0-9999 is `MalformedValue`.
    /// Variable time: branches on the fields, which are public.
    ///
    /// ```
    /// use chrono::{DateTime, TimeZone, Utc};
    /// use tc_asn1::{Asn1Error, Asn1GeneralizedTime};
    ///
    /// let instant = Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap();
    /// let time = Asn1GeneralizedTime::try_from(instant)?;
    /// assert_eq!(DateTime::<Utc>::from(time), instant);
    ///
    /// let outside = Utc.with_ymd_and_hms(10000, 1, 1, 0, 0, 0).unwrap();
    /// assert_eq!(Asn1GeneralizedTime::try_from(outside), Err(Asn1Error::MalformedValue));
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn try_from(value: chrono::DateTime<chrono::Utc>) -> Result<Self, Asn1Error> {
        let (year, month, day, hour, minute, second) = DateTime::fields_of(&value)?;
        Self::new(year, month, day, hour, minute, second)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::Asn1GeneralizedTime;
    use crate::{Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};

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
    fn offsets_and_short_forms_are_rejected() {
        for wire in [
            &b"\x18\x1320401231235959+0800"[..], // an offset
            b"\x18\x0E20401231235959",           // no Z
            b"\x18\x0D204012312359Z",            // no seconds
            b"\x18\x0D401231235959Z",            // a two-digit year
            b"\x18\x0F20230229000000Z",          // not a leap year
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

    fn decode(wire: &[u8], der: bool) -> Result<Asn1GeneralizedTime, Asn1Error> {
        use crate::DecodeInner;
        let mut context = if der {
            DecodingContext::new_der(options())
        } else {
            DecodingContext::new(options())
        };
        Asn1GeneralizedTime::decode_inner(wire, &mut context).map(|(_, value)| value)
    }

    #[test]
    fn a_der_fraction_is_read_to_the_nanosecond_and_written_back_the_same() {
        for (wire, nanosecond, text) in [
            (
                &b"\x18\x1120401231235959.5Z"[..],
                500_000_000,
                "2040-12-31T23:59:59.5Z",
            ),
            (
                b"\x18\x1320401231235959.123Z",
                123_000_000,
                "2040-12-31T23:59:59.123Z",
            ),
            (
                b"\x18\x1920401231235959.000000001Z",
                1,
                "2040-12-31T23:59:59.000000001Z",
            ),
            (
                b"\x18\x1920401231235959.999999999Z",
                999_999_999,
                "2040-12-31T23:59:59.999999999Z",
            ),
        ] {
            for der in [false, true] {
                let value = decode(wire, der).unwrap();
                assert_eq!(value.nanosecond(), nanosecond, "{text}");
                assert_eq!(value.second(), 59);
                assert_eq!(value.to_string(), text);
                assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            }
        }
    }

    #[test]
    fn ber_also_takes_a_comma_and_trailing_zeros_which_der_refuses() {
        for (wire, nanosecond) in [
            (&b"\x18\x1120401231235959,5Z"[..], 500_000_000),
            (b"\x18\x1220401231235959.50Z", 500_000_000),
            (b"\x18\x1120401231235959.0Z", 0),
        ] {
            assert_eq!(decode(wire, false).unwrap().nanosecond(), nanosecond);
            assert!(
                matches!(decode(wire, true), Err(Asn1Error::NotDer)),
                "{wire:02X?}"
            );
        }
        // Written back in the DER form
        let value = decode(b"\x18\x1220401231235959,50Z", false).unwrap();
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x18\x1120401231235959.5Z"
        );
        let whole = decode(b"\x18\x1120401231235959.0Z", false).unwrap();
        assert_eq!(
            whole.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x18\x0F20401231235959Z"
        );
    }

    #[test]
    fn a_fraction_without_digits_or_beyond_nanoseconds_is_malformed() {
        for wire in [
            &b"\x18\x1020401231235959.Z"[..],      // no digit
            b"\x18\x1A20401231235959.0000000001Z", // ten digits
            b"\x18\x1120401231235959.aZ",          // not a digit
            b"\x18\x1120401231235959:5Z",          // not a separator
        ] {
            for der in [false, true] {
                assert!(
                    matches!(decode(wire, der), Err(Asn1Error::MalformedValue)),
                    "{wire:02X?}"
                );
            }
        }
    }

    #[test]
    fn with_nanosecond_takes_less_than_a_second() {
        let whole = Asn1GeneralizedTime::new(2040, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(whole.nanosecond(), 0);
        assert_eq!(
            whole.with_nanosecond(999_999_999).unwrap().nanosecond(),
            999_999_999
        );
        assert!(matches!(
            whole.with_nanosecond(1_000_000_000),
            Err(Asn1Error::MalformedValue)
        ));
        assert_eq!(whole.with_nanosecond(0).unwrap(), whole);
    }

    #[test]
    fn milliseconds_and_microseconds_set_and_read_the_same_fraction() {
        let whole = Asn1GeneralizedTime::new(2040, 12, 31, 23, 59, 59).unwrap();
        let milli = whole.with_millisecond(123).unwrap();
        assert_eq!(milli.nanosecond(), 123_000_000);
        assert_eq!(
            milli.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x18\x1320401231235959.123Z"
        );
        let micro = whole.with_microsecond(123_456).unwrap();
        assert_eq!(micro.nanosecond(), 123_456_000);
        assert_eq!(micro.millisecond(), 123);

        // Reading rounds down
        let nano = whole.with_nanosecond(123_456_789).unwrap();
        assert_eq!((nano.millisecond(), nano.microsecond()), (123, 123_456));
        let top = whole.with_nanosecond(999_999_999).unwrap();
        assert_eq!((top.millisecond(), top.microsecond()), (999, 999_999));

        for result in [
            whole.with_millisecond(1_000),
            whole.with_microsecond(1_000_000),
        ] {
            assert!(matches!(result, Err(Asn1Error::MalformedValue)));
        }
        assert_eq!(whole.with_millisecond(999).unwrap().millisecond(), 999);
        assert_eq!(
            whole.with_microsecond(999_999).unwrap().microsecond(),
            999_999
        );
    }

    #[test]
    fn ordering_is_chronological_and_the_utctime_tag_is_unexpected() {
        let earlier = Asn1GeneralizedTime::new(2049, 12, 31, 23, 59, 59).unwrap();
        let fraction = earlier.with_nanosecond(999_999_999).unwrap();
        let later = Asn1GeneralizedTime::new(2050, 1, 1, 0, 0, 0).unwrap();
        assert!(earlier < fraction && fraction < later);
        assert!(matches!(
            Asn1GeneralizedTime::decode(b"\x17\x0D160801121924Z", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
