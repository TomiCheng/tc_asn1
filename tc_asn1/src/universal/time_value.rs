//! Validation of the TIME value notation and X.690 §11.9 normalization; no
//! time-zone database and no date arithmetic.
use super::date_time::days_in_month;
use crate::Asn1Error;
use alloc::{format, string::String, vec::Vec};
type Result<T> = core::result::Result<T, Asn1Error>;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Asn1Error::MalformedValue)
    }
}
fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}
fn small(s: &str, width: usize) -> Result<u32> {
    require(s.len() == width && digits(s))?;
    Ok(s.bytes().fold(0, |n, b| n * 10 + u32::from(b - b'0')))
}
fn fraction(s: &str) -> Result<(&str, usize)> {
    if let Some((whole, frac)) = s.split_once(['.', ',']) {
        require(digits(whole) && digits(frac))?;
        Ok((whole, frac.len()))
    } else {
        require(digits(s))?;
        Ok((s, 0))
    }
}

// Date forms: C, Y, YM, YMD, YD, YW, YWD. The year class and precision are also
// used to check that interval endpoints agree.
fn date(s: &str) -> Result<(u8, usize)> {
    require(s.is_ascii())?;
    let negative = s.starts_with('-');
    let signed = negative || s.starts_with('+');
    let rest = if signed { &s[1..] } else { s };
    let year_end = rest.find(['-', 'C']).unwrap_or(rest.len());
    let year = &rest[..year_end];
    require(digits(year))?;
    let suffix = &rest[year_end..];
    let century = suffix == "C";
    let width = if century { 2 } else { 4 };
    require(if signed {
        (negative && year.len() == width) || (year.len() > width && !year.starts_with('0'))
    } else {
        year.len() == width
    })?;
    require(!negative || year.bytes().any(|b| b != b'0'))?;
    let n = year
        .bytes()
        .fold(0u32, |n, b| (n * 10 + u32::from(b - b'0')) % 10000);
    let class = if year.len() > width {
        year.len() + if century { 2 } else { 0 }
    } else if negative {
        2
    } else if n < if century { 15 } else { 1582 } {
        0
    } else {
        1
    };
    if century {
        return Ok((0, class));
    }
    let y = if negative {
        (400 - n % 400) % 400
    } else {
        n % 400
    };
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y == 0);
    if suffix.is_empty() {
        return Ok((1, class));
    }
    let suffix = suffix.strip_prefix('-').ok_or(Asn1Error::MalformedValue)?;
    if let Some(week) = suffix.strip_prefix('W') {
        let (week, day) = week
            .split_once('-')
            .map_or((week, None), |(w, d)| (w, Some(d)));
        let week = small(week, 2)?;
        let prev = (y + 399) % 400;
        let jan1 = (365 * prev + prev / 4 - prev / 100 + 1) % 7;
        let max = if jan1 == 4 || (jan1 == 3 && leap) {
            53
        } else {
            52
        };
        require((1..=max).contains(&week))?;
        if let Some(day) = day {
            require((1..=7).contains(&small(day, 1)?))?;
        }
        return Ok((if day.is_some() { 6 } else { 5 }, class));
    }
    if suffix.len() == 3 {
        require((1..=if leap { 366 } else { 365 }).contains(&small(suffix, 3)?))?;
        return Ok((4, class));
    }
    let (month, day) = suffix
        .split_once('-')
        .map_or((suffix, None), |(m, d)| (m, Some(d)));
    let month = small(month, 2)?;
    require((1..=12).contains(&month))?;
    if let Some(day) = day {
        let max = u32::from(days_in_month(leap, month as u8));
        require((1..=max).contains(&small(day, 2)?))?;
    }
    Ok((if day.is_some() { 3 } else { 2 }, class))
}

struct Point {
    canonical: String,
    date: Option<(u8, usize)>,
    time: Option<(usize, usize)>,
    zone: u8,
    zone_at: usize,
    midnight: Option<bool>,
}
fn clock(s: &str) -> Result<Point> {
    let zone_at = s.find(['Z', '+', '-']).unwrap_or(s.len());
    let (value, zone) = s.split_at(zone_at);
    let mut suffix = String::new();
    let zone_kind = if zone.is_empty() {
        0
    } else if zone == "Z" {
        suffix.push('Z');
        1
    } else {
        require(zone.starts_with(['+', '-']))?;
        let (hours, minutes) = zone[1..]
            .split_once(':')
            .map_or((&zone[1..], None), |(h, m)| (h, Some(m)));
        let hours = small(hours, 2)?;
        let minutes = minutes.map(|m| small(m, 2)).transpose()?.unwrap_or(0);
        require(hours <= 15 && minutes < 60 && (hours < 15 || minutes == 0))?;
        require(!zone.starts_with('-') || hours != 0 || minutes != 0)?;
        suffix.push_str(&zone[..3]);
        if minutes != 0 {
            suffix.push_str(&zone[3..]);
        }
        2
    };
    let fields: Vec<_> = value.split(':').collect();
    require((1..=3).contains(&fields.len()))?;
    let (last, precision) = fraction(fields[fields.len() - 1])?;
    let mut numbers = [0; 3];
    for (i, field) in fields.iter().enumerate() {
        numbers[i] = small(if i + 1 == fields.len() { last } else { field }, 2)?;
    }
    require(numbers[0] <= 24 && numbers[1] <= 59 && numbers[2] <= 60)?;
    if numbers[0] == 24 {
        require(
            numbers[1] == 0
                && numbers[2] == 0
                && value
                    .bytes()
                    .filter(|b| b.is_ascii_digit())
                    .skip(2)
                    .all(|b| b == b'0'),
        )?;
    }
    let mut canonical = value.replace(',', ".");
    let zone_at = canonical.len();
    canonical.push_str(&suffix);
    Ok(Point {
        canonical,
        date: None,
        time: Some((fields.len(), precision)),
        zone: zone_kind,
        zone_at,
        midnight: if numbers[0] == 24 {
            Some(true)
        } else if numbers == [0; 3]
            && value
                .bytes()
                .filter(|b| b.is_ascii_digit())
                .all(|b| b == b'0')
        {
            Some(false)
        } else {
            None
        },
    })
}
fn point(s: &str) -> Result<Point> {
    if let Some((d, t)) = s.split_once('T') {
        let properties = date(d)?;
        require(matches!(properties.0, 3 | 4 | 6))?;
        let mut p = clock(t)?;
        p.canonical = format!("{d}T{}", p.canonical);
        p.zone_at += d.len() + 1;
        p.date = Some(properties);
        return Ok(p);
    }
    if let Ok(properties) = date(s) {
        return Ok(Point {
            canonical: String::from(s),
            date: Some(properties),
            time: None,
            zone: 0,
            zone_at: s.len(),
            midnight: None,
        });
    }
    clock(s)
}

pub(super) fn duration(s: &str) -> Result<String> {
    let s = s.strip_prefix('P').ok_or(Asn1Error::MalformedValue)?;
    let mut rest = s;
    let mut time = false;
    let mut components = Vec::new();
    let mut last_rank = None;
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix('T') {
            require(!time && !tail.is_empty())?;
            time = true;
            rest = tail;
        }
        let end = rest
            .find(|c: char| c.is_ascii_alphabetic())
            .ok_or(Asn1Error::MalformedValue)?;
        let number = &rest[..end];
        let unit = rest.as_bytes()[end];
        let rank = match (time, unit) {
            (false, b'Y') => 0,
            (false, b'M') => 1,
            (false, b'W') => 2,
            (false, b'D') => 3,
            (true, b'H') => 4,
            (true, b'M') => 5,
            (true, b'S') => 6,
            _ => return Err(Asn1Error::MalformedValue),
        };
        require(last_rank.is_none_or(|r| rank > r))?;
        let (integer, fractional) = fraction(number)?;
        require(integer.len() == 1 || !integer.starts_with('0'))?;
        rest = &rest[end + 1..];
        require(fractional == 0 || rest.is_empty())?;
        components.push((rank, number, unit));
        last_rank = Some(rank);
    }
    require(!components.is_empty())?;
    require(components.len() == 1 || components.iter().all(|(rank, _, _)| *rank != 2))?;
    let mut result = String::from("P");
    let mut emitted_time = false;
    for (i, (rank, number, unit)) in components.iter().enumerate() {
        let zero = number.bytes().all(|b| matches!(b, b'0' | b'.' | b','));
        if zero && i + 1 != components.len() {
            continue;
        }
        if *rank >= 4 && !emitted_time {
            result.push('T');
            emitted_time = true;
        }
        result.push_str(&number.replace(',', "."));
        result.push(char::from(*unit));
    }
    Ok(result)
}

pub(super) fn time(s: &str) -> Result<String> {
    require(s.is_ascii())?;
    let (recurrence, interval) = if let Some(rest) = s.strip_prefix('R') {
        let (n, interval) = rest.split_once('/').ok_or(Asn1Error::MalformedValue)?;
        require(n.is_empty() || (digits(n) && (n.len() == 1 || !n.starts_with('0'))))?;
        (Some(n), interval)
    } else {
        (None, s)
    };
    let result = if let Some((start, end)) = interval.split_once('/') {
        require(!end.contains('/'))?;
        match (start.starts_with('P'), end.starts_with('P')) {
            (true, true) => return Err(Asn1Error::MalformedValue),
            (true, false) => format!("{}/{}", duration(start)?, point(end)?.canonical),
            (false, true) => format!("{}/{}", point(start)?.canonical, duration(end)?),
            (false, false) => {
                let a = point(start)?;
                let mut b = point(end)?;
                require(a.date == b.date && a.time == b.time)?;
                require(a.midnight.is_none() || b.midnight.is_none() || a.midnight == b.midnight)?;
                require(a.zone == b.zone || (a.zone == 2 && b.zone == 0))?;
                if a.zone == 2
                    && b.zone == 2
                    && a.canonical[a.zone_at..] == b.canonical[b.zone_at..]
                {
                    b.canonical.truncate(b.zone_at);
                }
                format!("{}/{}", a.canonical, b.canonical)
            }
        }
    } else if interval.starts_with('P') {
        duration(interval)?
    } else {
        require(recurrence.is_none())?;
        point(interval)?.canonical
    };
    Ok(if let Some(n) = recurrence {
        format!("R{n}/{result}")
    } else {
        result
    })
}

pub(super) fn useful_date(s: &str) -> Result<String> {
    require(date(s)? == (3, 1))?;
    Ok(String::from(s))
}
pub(super) fn useful_clock(s: &str) -> Result<String> {
    require(s.is_ascii())?;
    let p = clock(s)?;
    require(p.time == Some((3, 0)) && p.zone == 0)?;
    Ok(p.canonical)
}
pub(super) fn useful_date_time(s: &str) -> Result<String> {
    let (d, t) = s.split_once('T').ok_or(Asn1Error::MalformedValue)?;
    useful_date(d)?;
    useful_clock(t)?;
    Ok(String::from(s))
}
