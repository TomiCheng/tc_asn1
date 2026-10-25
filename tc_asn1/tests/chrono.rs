//! The conversions behind the `chrono` feature between UTCTime,
//! GeneralizedTime and `chrono::DateTime<Utc>`.

#![cfg(feature = "chrono")]

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use tc_asn1::{Asn1Error, Asn1GeneralizedTime, Asn1UtcTime};

fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .unwrap()
}

#[test]
fn utctime_round_trips_through_chrono_at_both_ends_of_its_range() {
    for instant in [
        utc(1950, 1, 1, 0, 0, 0),
        utc(2000, 2, 29, 12, 30, 45),
        utc(2049, 12, 31, 23, 59, 59),
    ] {
        let time = Asn1UtcTime::try_from(instant).unwrap();
        assert_eq!(DateTime::<Utc>::from(time), instant);
    }
}

#[test]
fn generalizedtime_round_trips_through_chrono_at_both_ends_of_its_range() {
    for instant in [
        utc(0, 1, 1, 0, 0, 0),
        utc(1949, 6, 1, 12, 0, 0),
        utc(9999, 12, 31, 23, 59, 59),
    ] {
        let time = Asn1GeneralizedTime::try_from(instant).unwrap();
        assert_eq!(DateTime::<Utc>::from(time), instant);
    }
}

#[test]
fn fractions_are_truncated_and_a_leap_second_becomes_59() {
    let fraction = NaiveDate::from_ymd_opt(2026, 10, 21)
        .unwrap()
        .and_hms_milli_opt(8, 0, 0, 999)
        .unwrap()
        .and_utc();
    assert_eq!(
        Asn1UtcTime::try_from(fraction).unwrap(),
        Asn1UtcTime::new(2026, 10, 21, 8, 0, 0).unwrap()
    );
    assert_eq!(
        Asn1GeneralizedTime::try_from(fraction).unwrap(),
        Asn1GeneralizedTime::new(2026, 10, 21, 8, 0, 0).unwrap()
    );
    let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
        .unwrap()
        .and_hms_milli_opt(23, 59, 59, 1_500)
        .unwrap()
        .and_utc();
    assert_eq!(
        Asn1UtcTime::try_from(leap).unwrap(),
        Asn1UtcTime::new(2016, 12, 31, 23, 59, 59).unwrap()
    );
    assert_eq!(
        Asn1GeneralizedTime::try_from(leap).unwrap(),
        Asn1GeneralizedTime::new(2016, 12, 31, 23, 59, 59).unwrap()
    );
}

#[test]
fn years_outside_each_types_range_are_rejected() {
    for instant in [utc(1949, 12, 31, 23, 59, 59), utc(2050, 1, 1, 0, 0, 0)] {
        assert_eq!(
            Asn1UtcTime::try_from(instant),
            Err(Asn1Error::MalformedValue)
        );
    }
    for instant in [utc(-1, 12, 31, 23, 59, 59), utc(10000, 1, 1, 0, 0, 0)] {
        assert_eq!(
            Asn1GeneralizedTime::try_from(instant),
            Err(Asn1Error::MalformedValue)
        );
    }
}
