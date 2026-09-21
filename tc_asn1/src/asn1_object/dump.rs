//! Tree dump of an [`Asn1Object`] through `Display`, one element per line,
//! two spaces of indent per level.

use core::fmt;

use super::Asn1Object;
use crate::{Asn1Class, Asn1Integer};

impl fmt::Display for Asn1Object {
    /// Writes the whole tree; public data only.
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dump(self, 0, f)
    }
}

fn indent(level: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for _ in 0..level {
        f.write_str("  ")?;
    }
    Ok(())
}

fn hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

fn octets(bytes: &[u8], count: usize, unit: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, " ({count} {unit})")?;
    if !bytes.is_empty() {
        f.write_str(" ")?;
        hex(bytes, f)?;
    }
    Ok(())
}

fn bytes_line(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    octets(bytes, bytes.len(), "bytes", f)?;
    f.write_str("\n")
}

fn integer(value: &Asn1Integer, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Ok(number) = i128::try_from(value) {
        write!(f, " {number}")
    } else {
        octets(value.as_bytes(), value.as_bytes().len(), "bytes", f)
    }
}

/// The tag number, or `None` when it does not fit in `u64`.
fn tag_number(tag: &[u8]) -> Option<u64> {
    let first = *tag.first()?;
    if first & 0x1F != 0x1F {
        return Some(u64::from(first & 0x1F));
    }
    let mut number: u64 = 0;
    for byte in &tag[1..] {
        number = number.checked_shl(7)?.checked_add(u64::from(byte & 0x7F))?;
        if number >> 57 != 0 && byte & 0x80 != 0 {
            return None; // the next group would overflow
        }
    }
    Some(number)
}

/// `SEQUENCE`, `SET`, or `[CLASS number]` for everything else; an oversized
/// number is shown as `tag=` plus the identifier octets.
fn identifier(tag: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match tag {
        [0x30] => return f.write_str("SEQUENCE"),
        [0x31] => return f.write_str("SET"),
        _ => {}
    }
    let class = match Asn1Class::of(tag[0]) {
        Asn1Class::Universal => "UNIVERSAL",
        Asn1Class::Application => "APPLICATION",
        Asn1Class::ContextSpecific => "CONTEXT",
        Asn1Class::Private => "PRIVATE",
    };
    match tag_number(tag) {
        Some(number) => write!(f, "[{class} {number}]"),
        None => {
            write!(f, "[{class} tag=")?;
            hex(tag, f)?;
            f.write_str("]")
        }
    }
}

fn dump(obj: &Asn1Object, level: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    use Asn1Object::*;
    indent(level, f)?;
    match obj {
        Boolean(value) => writeln!(f, "BOOLEAN {value}"),
        Integer(value) => {
            f.write_str("INTEGER")?;
            integer(value, f)?;
            f.write_str("\n")
        }
        Enumerated(value) => {
            f.write_str("ENUMERATED")?;
            if let Ok(number) = i64::try_from(value) {
                writeln!(f, " {number}")
            } else {
                bytes_line(value.as_bytes(), f)
            }
        }
        Real(value) => {
            f.write_str("REAL")?;
            if let Ok(number) = f64::try_from(value) {
                writeln!(f, " {number}")
            } else {
                bytes_line(value.as_bytes(), f)
            }
        }
        BitString(value) => {
            f.write_str("BIT STRING")?;
            octets(value.as_bytes(), value.bit_len(), "bits", f)?;
            f.write_str("\n")
        }
        OctetString(value) => {
            f.write_str("OCTET STRING")?;
            bytes_line(value.as_bytes(), f)
        }
        Null(_) => f.write_str("NULL\n"),
        Oid(value) => writeln!(f, "OBJECT IDENTIFIER {value}"),
        RelativeOid(value) => writeln!(f, "RELATIVE-OID {value}"),
        Utf8String(value) => writeln!(f, "UTF8String {:?}", value.as_str()),
        PrintableString(value) => writeln!(f, "PrintableString {:?}", value.as_str()),
        Ia5String(value) => writeln!(f, "IA5String {:?}", value.as_str()),
        NumericString(value) => writeln!(f, "NumericString {:?}", value.as_str()),
        VisibleString(value) => writeln!(f, "VisibleString {:?}", value.as_str()),
        BmpString(value) => writeln!(f, "BMPString {:?}", value.as_str()),
        UniversalString(value) => writeln!(f, "UniversalString {:?}", value.as_str()),
        UtcTime(value) => writeln!(f, "UTCTime {value}"),
        GeneralizedTime(value) => writeln!(f, "GeneralizedTime {value}"),
        Time(value) => writeln!(f, "TIME {}", value.as_str()),
        Date(value) => writeln!(f, "DATE {}", value.as_str()),
        TimeOfDay(value) => writeln!(f, "TIME-OF-DAY {}", value.as_str()),
        DateTime(value) => writeln!(f, "DATE-TIME {}", value.as_str()),
        Duration(value) => writeln!(f, "DURATION {}", value.as_str()),
        OidIri(value) => writeln!(f, "OID-IRI {}", value.as_str()),
        RelativeOidIri(value) => writeln!(f, "RELATIVE-OID-IRI {}", value.as_str()),
        SequenceOf(value) => {
            f.write_str(
                "SEQUENCE
",
            )?;
            for child in value.elements() {
                dump(child, level + 1, f)?;
            }
            Ok(())
        }
        SetOf(value) => {
            f.write_str(
                "SET
",
            )?;
            for child in value.members() {
                dump(child, level + 1, f)?;
            }
            Ok(())
        }
        Constructed(value) => {
            identifier(value.tag(), f)?;
            f.write_str("\n")?;
            for child in value.items() {
                dump(child, level + 1, f)?;
            }
            Ok(())
        }
        Unknown(value) => {
            let element = value.as_ref();
            identifier(element.tag(), f)?;
            if element.is_constructed() {
                f.write_str(" constructed")?;
            }
            bytes_line(element.value(), f)
        }
    }
}
