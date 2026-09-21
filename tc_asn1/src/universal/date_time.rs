//! Shared by `UTCTime` and `GeneralizedTime`: the split fields, range checks,
//! reading and writing `MMDDhhmmss`, and the ISO 8601 display. The year's digit
//! count and range are handled by each type.

use core::fmt;

use crate::error::Asn1Error;

/// Gregorian leap year: every fourth year, except centuries, except every fourth century.
pub(crate) fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Days in the month; the caller has checked that `month` is 1-12.
pub(crate) fn days_in_month(leap: bool, month: u8) -> u8 {
    match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Field order is chronological order, so the derived `Ord` compares instants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct DateTime {
    pub(crate) year: u16,
    pub(crate) month: u8,
    pub(crate) day: u8,
    pub(crate) hour: u8,
    pub(crate) minute: u8,
    pub(crate) second: u8,
}

impl DateTime {
    /// Validates a Gregorian date: month 1-12, hour 0-23, minute and second 0-59.
    /// The caller has already checked the year's range. Leap seconds are not
    /// handled, so seconds stay 0-59. Variable time: branches only on the fields.
    pub(crate) fn checked(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        let in_range = (1..=12).contains(&month)
            && (1..=days_in_month(is_leap_year(year), month)).contains(&day)
            && hour <= 23
            && minute <= 59
            && second <= 59;
        if !in_range {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    /// Builds from the year and the ten `MMDDhhmmss` octets.
    pub(crate) fn from_fields(year: u16, fields: &[u8]) -> Result<Self, Asn1Error> {
        let [m, d, h, mi, s] = fields.as_chunks::<2>().0 else {
            return Err(Asn1Error::MalformedValue);
        };
        Self::checked(
            year,
            two_digits(m)?,
            two_digits(d)?,
            two_digits(h)?,
            two_digits(mi)?,
            two_digits(s)?,
        )
    }

    /// Writes `MMDDhhmmss` into ten octets.
    pub(crate) fn write_fields(&self, out: &mut [u8; 10]) {
        for (slot, n) in out.as_chunks_mut::<2>().0.iter_mut().zip([
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        ]) {
            *slot = digits(n);
        }
    }
}

/// Two ASCII digits to a number.
pub(crate) fn two_digits(pair: &[u8; 2]) -> Result<u8, Asn1Error> {
    match pair {
        [a, b] if a.is_ascii_digit() && b.is_ascii_digit() => Ok((a - b'0') * 10 + (b - b'0')),
        _ => Err(Asn1Error::MalformedValue),
    }
}

/// A number to two ASCII digits; the caller guarantees `n < 100`.
pub(crate) fn digits(n: u8) -> [u8; 2] {
    [b'0' + n / 10, b'0' + n % 10]
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}
