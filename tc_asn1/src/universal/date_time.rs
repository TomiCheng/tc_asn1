//! Shared by `UTCTime` and `GeneralizedTime`: the split fields, range checks,
//! reading and writing `MMDDhhmmss`, and the ISO 8601 display. The year's digit
//! count and range are handled by each type.

use core::fmt;

use crate::error::Asn1Error;

/// Gregorian leap year: every fourth year, except centuries, except every fourth century.
pub(crate) fn is_leap_year(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
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
        if fields.len() != 10 {
            return Err(Asn1Error::MalformedValue);
        }
        let [m, d, h, mi, s] = [0, 2, 4, 6, 8].map(|at| &fields[at..at + 2]);
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
        for (slot, n) in
            out.chunks_exact_mut(2)
                .zip([self.month, self.day, self.hour, self.minute, self.second])
        {
            slot.copy_from_slice(&digits(n));
        }
    }
}

/// Two ASCII digits to a number; any other length is malformed.
pub(crate) fn two_digits(pair: &[u8]) -> Result<u8, Asn1Error> {
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

#[cfg(feature = "zeroize")]
impl DateTime {
    /// Wipes every field, then leaves midnight on January 1 of `year`, the
    /// first instant the owning type allows. Constant time.
    pub(crate) fn wipe(&mut self, year: u16) {
        use tc_zeroize::Zeroize;
        self.year.zeroize();
        self.month.zeroize();
        self.day.zeroize();
        self.hour.zeroize();
        self.minute.zeroize();
        self.second.zeroize();
        self.year = year;
        self.month = 1;
        self.day = 1;
    }
}

#[cfg(feature = "chrono")]
impl DateTime {
    /// The same instant in chrono. Variable time: branches on the fields,
    /// which are public.
    pub(crate) fn to_chrono(self) -> chrono::DateTime<chrono::Utc> {
        chrono::NaiveDate::from_ymd_opt(
            i32::from(self.year),
            u32::from(self.month),
            u32::from(self.day),
        )
        .and_then(|date| {
            date.and_hms_opt(
                u32::from(self.hour),
                u32::from(self.minute),
                u32::from(self.second),
            )
        })
        .expect("a checked DateTime is a valid chrono date and time")
        .and_utc()
    }

    /// The fields of a chrono instant, truncated to the second, for the
    /// owning type's `new` to check: chrono keeps a leap second as second 59
    /// with an extra nanosecond count, so it becomes `:59`. A year chrono can
    /// hold but `u16` cannot is `MalformedValue`. Variable time: branches on
    /// the fields, which are public.
    pub(crate) fn fields_of(
        value: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(u16, u8, u8, u8, u8, u8), Asn1Error> {
        use chrono::{Datelike, Timelike};
        let year = u16::try_from(value.year()).map_err(|_| Asn1Error::MalformedValue)?;
        // chrono keeps the remaining fields within 1-12, 1-31, 0-23 and 0-59.
        Ok((
            year,
            value.month() as u8,
            value.day() as u8,
            value.hour() as u8,
            value.minute() as u8,
            value.second() as u8,
        ))
    }
}
