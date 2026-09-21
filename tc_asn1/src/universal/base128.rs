//! Base-128 subidentifiers shared by OBJECT IDENTIFIER and RELATIVE-OID (X.690 §8.19).

use alloc::vec::Vec;

use crate::Asn1Error;

/// [`validate_base128`] without the error detail, usable in `const`
/// contexts so a table of OID constants is checked when it is compiled.
/// Variable time: branches only on the encoding structure.
pub(crate) const fn is_base128(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let mut at_start = true;
    let mut value: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if at_start && byte == 0x80 {
            return false;
        }
        value = match value.checked_mul(128) {
            Some(v) => match v.checked_add((byte & 0x7F) as u64) {
                Some(v) => v,
                None => return false,
            },
            None => return false,
        };
        at_start = byte & 0x80 == 0;
        if at_start {
            value = 0;
        }
        i += 1;
    }
    at_start
}

/// Checks that the contents are a non-empty run of complete, shortest-form
/// subidentifiers that each fit in `u64`.
/// Variable time: branches only on the encoding structure.
pub(crate) fn validate_base128(bytes: &[u8]) -> Result<(), Asn1Error> {
    if bytes.is_empty() {
        return Err(Asn1Error::MalformedValue);
    }
    let mut at_start = true;
    let mut value: u64 = 0;
    for byte in bytes {
        // §8.19.2: the leading octet of a subidentifier shall not be 0x80.
        if at_start && *byte == 0x80 {
            return Err(Asn1Error::MalformedValue);
        }
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add(u64::from(byte & 0x7F)))
            .ok_or(Asn1Error::LengthOverflow)?;
        at_start = byte & 0x80 == 0;
        if at_start {
            value = 0;
        }
    }
    if !at_start {
        return Err(Asn1Error::MalformedValue);
    }
    Ok(())
}

/// Appends one subidentifier: seven bits per octet, high bit set on all but the
/// last, shortest form.
/// Variable time: branches only on the value's bit length.
pub(crate) fn push_base128(out: &mut Vec<u8>, value: u64) {
    let bits = 64 - value.leading_zeros();
    let count = bits.div_ceil(7).max(1) as usize;
    for index in 0..count {
        let shift = 7 * (count - 1 - index);
        let more = if index + 1 < count { 0x80 } else { 0 };
        out.push(((value >> shift) & 0x7F) as u8 | more);
    }
}
