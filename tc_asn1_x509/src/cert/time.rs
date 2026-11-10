//! RFC 5280 §4.1.2.5 `Time`.
//!
//! ```text
//! Time ::= CHOICE {
//!     utcTime        UTCTime,
//!     generalTime    GeneralizedTime
//! }
//! ```
//!
//! Dates through 2049 MUST use UTCTime and dates from 2050 on MUST use
//! GeneralizedTime; [`Time::new`] picks the alternative by year. Both are to
//! the second: RFC 5280 §4.1.2.5.2 forbids fractional seconds, so decoding
//! refuses them and encoding leaves them out.

use core::{cmp::Ordering, fmt};

#[cfg(feature = "chrono")]
use chrono::{DateTime, Datelike, NaiveDate, Timelike, Utc};
use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Asn1UtcTime, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions,
};

/// A CHOICE between the two time types, so it has no single identifier.
/// Ordering is chronological whichever alternative carries the instant.
///
/// A PKIX time has no fractional seconds. [`Time::new`] and the `From`
/// conversions never give it any; a `GeneralizedTime` built with some and
/// wrapped directly is written and displayed to the second.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Time {
    /// A UTCTime, which RFC 5280 requires through 2049.
    UtcTime(Asn1UtcTime),
    /// A GeneralizedTime, which RFC 5280 requires from 2050.
    GeneralizedTime(Asn1GeneralizedTime),
}

impl Time {
    /// Picks the alternative RFC 5280 requires for the year: UTCTime through
    /// 2049, GeneralizedTime from 2050. Fields are validated like the two types.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        if year <= 2049 {
            Asn1UtcTime::new(year, month, day, hour, minute, second).map(Self::UtcTime)
        } else {
            Asn1GeneralizedTime::new(year, month, day, hour, minute, second)
                .map(Self::GeneralizedTime)
        }
    }

    /// The year, 1950-2049 for UTCTime and 0-9999 for GeneralizedTime.
    pub fn year(&self) -> u16 {
        match self {
            Self::UtcTime(t) => t.year(),
            Self::GeneralizedTime(t) => t.year(),
        }
    }
    /// The month, 1-12.
    pub fn month(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.month(),
            Self::GeneralizedTime(t) => t.month(),
        }
    }
    /// The day of the month, 1-31.
    pub fn day(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.day(),
            Self::GeneralizedTime(t) => t.day(),
        }
    }
    /// The hour, 0-23.
    pub fn hour(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.hour(),
            Self::GeneralizedTime(t) => t.hour(),
        }
    }
    /// The minute, 0-59.
    pub fn minute(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.minute(),
            Self::GeneralizedTime(t) => t.minute(),
        }
    }
    /// The second, 0-59.
    pub fn second(&self) -> u8 {
        match self {
            Self::UtcTime(t) => t.second(),
            Self::GeneralizedTime(t) => t.second(),
        }
    }

    // The GeneralizedTime alternative to the second, as it is written
    fn whole(time: &Asn1GeneralizedTime) -> Asn1GeneralizedTime {
        time.with_nanosecond(0).expect("zero is below one second")
    }

    fn sort_key(&self) -> (u16, u8, u8, u8, u8, u8, u8) {
        let alternative = match self {
            Self::UtcTime(_) => 0,
            Self::GeneralizedTime(_) => 1,
        };
        (
            self.year(),
            self.month(),
            self.day(),
            self.hour(),
            self.minute(),
            self.second(),
            alternative,
        )
    }
}

impl Ord for Time {
    /// Compares the instants, so a GeneralizedTime before 2050 still sorts
    /// before a later UTCTime. The same instant in the two alternatives puts
    /// UTCTime first, keeping the order consistent with `Eq`. Variable time:
    /// branches on the fields, which are public.
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<Asn1UtcTime> for Time {
    fn from(value: Asn1UtcTime) -> Self {
        Self::UtcTime(value)
    }
}

impl From<Asn1GeneralizedTime> for Time {
    /// The same instant to the second. A PKIX time carries no fractional
    /// seconds, RFC 5280 §4.1.2.5.2, so any are dropped, rounding down, as
    /// `TryFrom<DateTime<Utc>>` does. Constant time.
    fn from(value: Asn1GeneralizedTime) -> Self {
        Self::GeneralizedTime(Self::whole(&value))
    }
}

#[cfg(feature = "chrono")]
impl From<Time> for DateTime<Utc> {
    /// The same instant. Variable time: branches on the fields, which are public.
    fn from(value: Time) -> Self {
        NaiveDate::from_ymd_opt(
            i32::from(value.year()),
            u32::from(value.month()),
            u32::from(value.day()),
        )
        .and_then(|date| {
            date.and_hms_opt(
                u32::from(value.hour()),
                u32::from(value.minute()),
                u32::from(value.second()),
            )
        })
        .expect("Time holds a valid Gregorian date and time")
        .and_utc()
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<DateTime<Utc>> for Time {
    type Error = Asn1Error;

    /// Truncates to the second, the precision `Time` carries, and picks the
    /// alternative as [`Time::new`] does. A leap second becomes `:59`. Years
    /// outside 1950-9999 return `MalformedValue`. Variable time: branches on
    /// the fields, which are public.
    ///
    /// ```
    /// use chrono::{DateTime, TimeZone, Utc};
    /// use tc_asn1_x509::cert::{Time, Validity};
    ///
    /// let not_before = Time::new(2026, 1, 1, 0, 0, 0)?;
    /// let not_after = Time::new(2027, 1, 1, 0, 0, 0)?;
    /// let validity = Validity::new(not_before, not_after)?;
    ///
    /// let now = Time::try_from(Utc.with_ymd_and_hms(2026, 10, 21, 8, 0, 0).unwrap())?;
    /// assert!(validity.not_before() <= now && now <= validity.not_after());
    ///
    /// let expiry: DateTime<Utc> = validity.not_after().into();
    /// assert_eq!(expiry, Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap());
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn try_from(value: DateTime<Utc>) -> Result<Self, Asn1Error> {
        let year = u16::try_from(value.year()).map_err(|_| Asn1Error::MalformedValue)?;
        Self::new(
            year,
            value.month() as u8,
            value.day() as u8,
            value.hour() as u8,
            value.minute() as u8,
            value.second() as u8,
        )
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UtcTime(t) => t.fmt(f),
            Self::GeneralizedTime(t) => Self::whole(t).fmt(f),
        }
    }
}

impl DecodeInner for Time {
    /// The identifier selects the alternative. A GeneralizedTime with
    /// fractional seconds is `MalformedValue`, as RFC 5280 §4.1.2.5.2 forbids
    /// them. Variable time: branches only on the tag and the fraction.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if element.tag() == Asn1UtcTime::TAG {
            let (used, value) = Asn1UtcTime::decode_inner(buff, context)?;
            Ok((used, Self::UtcTime(value)))
        } else if element.tag() == Asn1GeneralizedTime::TAG {
            let (used, value) = Asn1GeneralizedTime::decode_inner(buff, context)?;
            if value.nanosecond() != 0 {
                return Err(Asn1Error::MalformedValue);
            }
            Ok((used, Self::GeneralizedTime(value)))
        } else {
            Err(Asn1Error::UnexpectedTag)
        }
    }
}

impl Decode for Time {}

impl EncodeContent for Time {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::UtcTime(t) => t.content_len(rules),
            Self::GeneralizedTime(t) => Self::whole(t).content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::UtcTime(t) => t.encode_content(rules, out),
            Self::GeneralizedTime(t) => Self::whole(t).encode_content(rules, out),
        }
    }
}

impl EncodeTagged for Time {}

/// Each alternative writes its own identifier.
impl Encode for Time {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::UtcTime(t) => t.encoded_len(rules),
            Self::GeneralizedTime(t) => Self::whole(t).encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::UtcTime(t) => t.encode(rules, out),
            Self::GeneralizedTime(t) => Self::whole(t).encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use core::cmp::Ordering;

    #[test]
    fn a_generalizedtime_with_fractional_seconds_is_not_a_pkix_time() {
        use super::Time;
        use tc_asn1::{
            Asn1Error, Asn1GeneralizedTime, Decode, DecodingOptions, Encode, EncodingOptions,
        };

        let options = DecodingOptions::default();
        let fraction = b"\x18\x1120501231235959.5Z";
        assert!(Asn1GeneralizedTime::decode(fraction, &options).is_ok());
        assert!(matches!(
            Time::decode(fraction, &options),
            Err(Asn1Error::MalformedValue)
        ));

        let stamp = Asn1GeneralizedTime::new(2050, 12, 31, 23, 59, 59)
            .unwrap()
            .with_millisecond(500)
            .unwrap();
        let whole = Time::new(2050, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(Time::from(stamp), whole);

        let wrapped = Time::GeneralizedTime(stamp);
        assert_eq!(
            wrapped.encode_to_vec(&EncodingOptions::DER).unwrap(),
            whole.encode_to_vec(&EncodingOptions::DER).unwrap()
        );
        assert_eq!(wrapped.to_string(), "2050-12-31T23:59:59Z");
    }

    use tc_asn1::{
        Asn1Error, Asn1GeneralizedTime, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::Time;

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    #[test]
    fn the_year_selects_utctime_through_2049_and_generalizedtime_from_2050() {
        let t = Time::new(2049, 12, 31, 23, 59, 59).unwrap();
        assert!(matches!(t, Time::UtcTime(_)));
        assert_eq!(t.encode_to_vec(&der()).unwrap(), b"\x17\x0d491231235959Z");
        let t = Time::new(2050, 1, 1, 0, 0, 0).unwrap();
        assert!(matches!(t, Time::GeneralizedTime(_)));
        assert_eq!(t.encode_to_vec(&der()).unwrap(), b"\x18\x0f20500101000000Z");
    }

    #[test]
    fn decoding_follows_the_identifier_and_rejects_other_tags() {
        let (used, t) =
            Time::decode(b"\x17\x0d260918123456Z", &DecodingOptions::default()).unwrap();
        assert_eq!((used, t.to_string().as_str()), (15, "2026-09-18T12:34:56Z"));
        let (_, t) = Time::decode(b"\x18\x0f20600101000000Z", &DecodingOptions::default()).unwrap();
        assert_eq!(t.year(), 2060);
        assert!(matches!(
            Time::decode(b"\x13\x0d260918123456Z", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn times_order_across_the_two_alternatives() {
        assert!(
            Time::new(2049, 12, 31, 23, 59, 59).unwrap() < Time::new(2050, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn a_generalizedtime_before_2050_orders_by_its_instant_not_its_alternative() {
        let early = Time::GeneralizedTime(Asn1GeneralizedTime::new(2020, 1, 1, 0, 0, 0).unwrap());
        let late = Time::new(2030, 1, 1, 0, 0, 0).unwrap();
        assert!(early < late);
        assert!(late > early);
    }

    #[test]
    fn the_same_instant_in_both_alternatives_differs_and_puts_utctime_first() {
        let utc = Time::new(2026, 1, 1, 0, 0, 0).unwrap();
        let general = Time::GeneralizedTime(Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap());
        assert_ne!(utc, general);
        assert_eq!(utc.cmp(&general), Ordering::Less);
    }

    #[cfg(feature = "chrono")]
    mod chrono_conversion {
        use chrono::{DateTime, NaiveDate, TimeZone, Utc};
        use tc_asn1::{Asn1Error, Asn1GeneralizedTime};

        use crate::cert::Time;

        fn utc(
            year: i32,
            month: u32,
            day: u32,
            hour: u32,
            minute: u32,
            second: u32,
        ) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
                .unwrap()
        }

        #[test]
        fn instants_round_trip_and_pick_the_alternative_at_2050() {
            for instant in [utc(1950, 1, 1, 0, 0, 0), utc(2049, 12, 31, 23, 59, 59)] {
                let time = Time::try_from(instant).unwrap();
                assert!(matches!(time, Time::UtcTime(_)));
                assert_eq!(DateTime::<Utc>::from(time), instant);
            }
            for instant in [utc(2050, 1, 1, 0, 0, 0), utc(9999, 12, 31, 23, 59, 59)] {
                let time = Time::try_from(instant).unwrap();
                assert!(matches!(time, Time::GeneralizedTime(_)));
                assert_eq!(DateTime::<Utc>::from(time), instant);
            }
        }

        #[test]
        fn a_generalizedtime_before_2050_converts_to_its_own_instant() {
            let time =
                Time::GeneralizedTime(Asn1GeneralizedTime::new(1949, 6, 1, 12, 0, 0).unwrap());
            assert_eq!(DateTime::<Utc>::from(time), utc(1949, 6, 1, 12, 0, 0));
        }

        #[test]
        fn fractions_are_truncated_and_a_leap_second_becomes_59() {
            let fraction = NaiveDate::from_ymd_opt(2026, 10, 21)
                .unwrap()
                .and_hms_milli_opt(8, 0, 0, 999)
                .unwrap()
                .and_utc();
            assert_eq!(
                Time::try_from(fraction).unwrap(),
                Time::new(2026, 10, 21, 8, 0, 0).unwrap()
            );
            let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
                .unwrap()
                .and_hms_milli_opt(23, 59, 59, 1_500)
                .unwrap()
                .and_utc();
            assert_eq!(
                Time::try_from(leap).unwrap(),
                Time::new(2016, 12, 31, 23, 59, 59).unwrap()
            );
        }

        #[test]
        fn years_outside_1950_to_9999_are_rejected() {
            for instant in [
                utc(1949, 12, 31, 23, 59, 59),
                utc(10000, 1, 1, 0, 0, 0),
                utc(-1, 1, 1, 0, 0, 0),
            ] {
                assert_eq!(Time::try_from(instant), Err(Asn1Error::MalformedValue));
            }
        }
    }
}
