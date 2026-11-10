//! Validation of IPv4 and IPv6 address text, after Bouncy Castle's
//! `Utilities.Net.IPAddress`, which `GeneralName` calls before it turns the
//! text into octets.
//!
//! One difference from Bouncy Castle: its `GetDigitHexadecimal` also takes
//! `g`, `G`, `:` to `?` and some control characters as hexadecimal digits;
//! this takes only `0-9a-fA-F`.

/// An IPv4 or IPv6 address.
/// Variable time: branches on the characters; for public values only.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn is_valid(address: &str) -> bool {
    is_valid_ipv4(address) || is_valid_ipv6(address)
}

/// An IPv4 or IPv6 address with a netmask, such as `10.0.0.0/8`.
/// Variable time: branches on the characters; for public values only.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn is_valid_with_netmask(address: &str) -> bool {
    is_valid_ipv4_with_netmask(address) || is_valid_ipv6_with_netmask(address)
}

/// An IPv4 address of four decimal parts from 0 to 255, leading zeros allowed.
/// Variable time: branches on the characters; for public values only.
pub(crate) fn is_valid_ipv4(address: &str) -> bool {
    ipv4(address.as_bytes())
}

/// An IPv4 address, a `/`, and a mask as an IPv4 address or a prefix length
/// from 0 to 32.
/// Variable time: branches on the characters; for public values only.
pub(crate) fn is_valid_ipv4_with_netmask(address: &str) -> bool {
    let Some((before, after)) = split_netmask(address.as_bytes()) else {
        return false;
    };
    ipv4(before) && (ipv4(after) || parseable_decimal(after, 2, false, 0, 32))
}

/// An IPv6 address, with one `::` allowed and the last two groups allowed as
/// an IPv4 address.
/// Variable time: branches on the characters; for public values only.
pub(crate) fn is_valid_ipv6(address: &str) -> bool {
    ipv6(address.as_bytes())
}

/// An IPv6 address, a `/`, and a mask as an IPv6 address or a prefix length
/// from 1 to 128.
/// Variable time: branches on the characters; for public values only.
pub(crate) fn is_valid_ipv6_with_netmask(address: &str) -> bool {
    let Some((before, after)) = split_netmask(address.as_bytes()) else {
        return false;
    };
    ipv6(before) && (ipv6(after) || parseable_decimal(after, 3, false, 1, 128))
}

// Splits at the first `/`, which cannot be the first character
fn split_netmask(address: &[u8]) -> Option<(&[u8], &[u8])> {
    let index = index_of(address, b'/', 0)?;
    (index >= 1).then(|| (&address[..index], &address[index + 1..]))
}

fn index_of(s: &[u8], c: u8, from: usize) -> Option<usize> {
    s[from..].iter().position(|&b| b == c).map(|i| from + i)
}

fn ipv4(address: &[u8]) -> bool {
    if !(7..=15).contains(&address.len()) {
        return false;
    }
    let mut pos = 0;
    for _ in 0..3 {
        let Some(end) = index_of(address, b'.', pos) else {
            return false;
        };
        if !parseable_decimal(&address[pos..end], 3, true, 0, 255) {
            return false;
        }
        pos = end + 1;
    }
    parseable_decimal(&address[pos..], 3, true, 0, 255)
}

fn ipv6(address: &[u8]) -> bool {
    let Some(&first) = address.first() else {
        return false;
    };
    if first != b':' && digit_hexadecimal(first).is_none() {
        return false;
    }

    // BC appends a `:` to the address before splitting; `len` stands for it here
    let len = address.len();
    let mut segment_count = 0;
    let mut double_colon_found = false;

    let mut pos = 0;
    while pos <= len {
        let end = index_of(address, b':', pos).unwrap_or(len);
        if segment_count == 8 {
            return false;
        }

        if pos != end {
            let value = &address[pos..end];
            if end == len && index_of(value, b'.', 0).is_some_and(|i| i > 0) {
                // A trailing IPv4 address takes two groups
                segment_count += 1;
                if segment_count == 8 {
                    return false;
                }
                if !ipv4(value) {
                    return false;
                }
            } else if !parseable_hexadecimal(value, 4) {
                return false;
            }
        } else {
            if end != 1 && end != len && double_colon_found {
                return false;
            }
            double_colon_found = true;
        }

        pos = end + 1;
        segment_count += 1;
    }

    segment_count == 8 || double_colon_found
}

fn parseable_decimal(
    s: &[u8],
    max_length: usize,
    allow_leading_zero: bool,
    min_value: u32,
    max_value: u32,
) -> bool {
    if s.is_empty() || s.len() > max_length {
        return false;
    }
    if s.len() > 1 && !allow_leading_zero && s[0] == b'0' {
        return false;
    }
    let mut value = 0;
    for &c in s {
        let Some(d) = digit_decimal(c) else {
            return false;
        };
        value = value * 10 + d;
    }
    (min_value..=max_value).contains(&value)
}

// A group of IPv6: one to four hexadecimal digits, leading zeros allowed
fn parseable_hexadecimal(s: &[u8], max_length: usize) -> bool {
    !s.is_empty() && s.len() <= max_length && s.iter().all(|&c| digit_hexadecimal(c).is_some())
}

fn digit_decimal(c: u8) -> Option<u32> {
    c.is_ascii_digit().then(|| u32::from(c - b'0'))
}

fn digit_hexadecimal(c: u8) -> Option<u32> {
    char::from(c).to_digit(16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from bc-csharp's `Utilities.Net.Tests.IPTest`
    #[test]
    fn bc_ip_test_accepts_and_rejects_the_same_addresses() {
        for valid in [
            "0.0.0.0",
            "255.255.255.255",
            "192.168.0.0",
            "0:0:0:0:0:0:0:0",
            "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
            "0:1:2:3:FFFF:5:FFFF:1",
        ] {
            assert!(is_valid(valid), "{valid}");
        }
        for invalid in [
            "0.0.0.0.1",
            "256.255.255.255",
            "1",
            "A.B.C",
            "1:.4.6.5",
            "0.0.0.0:1",
            "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFFF",
        ] {
            assert!(!is_valid(invalid), "{invalid}");
        }
    }

    #[test]
    fn ipv4_octets_are_decimal_up_to_255_and_may_have_leading_zeros() {
        for valid in ["1.2.3.4", "01.02.003.4", "255.0.0.255"] {
            assert!(is_valid_ipv4(valid), "{valid}");
        }
        for invalid in [
            "",
            "1.2.3",
            "1.2.3.4.",
            ".1.2.3.4",
            "1..2.3",
            "1.2.3.256",
            "1.2.3.0004",
            "1.2.3.-1",
            "1.2.3.4 ",
            "١.٢.٣.٤",
        ] {
            assert!(!is_valid_ipv4(invalid), "{invalid}");
        }
    }

    #[test]
    fn ipv6_allows_one_double_colon_and_a_trailing_ipv4() {
        for valid in [
            "::",
            "::1",
            "1::",
            "2001:db8::ff00:42:8329",
            "fe80::1:2:3:4:5:6",
            "::ffff:192.168.0.1",
            "0:0:0:0:0:ffff:192.168.0.1",
        ] {
            assert!(is_valid_ipv6(valid), "{valid}");
        }
        for invalid in [
            "",
            "1::2::3",
            "1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:8:9",
            "1:2:3:4:5:6:7:192.168.0.1",
            "::192.168.0.256",
            "12345::",
            "::1.2.3.4:5",
        ] {
            assert!(!is_valid_ipv6(invalid), "{invalid}");
        }
    }

    #[test]
    fn only_real_hexadecimal_digits_are_accepted_unlike_bc() {
        // BC's GetDigitHexadecimal takes these as digits
        for invalid in ["g::1", "G::1", "::;", "::1:?", "0:0:0:0:0:0:0:\u{10}"] {
            assert!(!is_valid_ipv6(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn netmasks_are_an_address_or_a_prefix_length_without_leading_zeros() {
        for valid in [
            "10.0.0.0/8",
            "10.0.0.0/0",
            "10.0.0.0/32",
            "10.0.0.0/255.0.0.0",
            "2001:db8::/32",
            "2001:db8::/128",
            "2001:db8::/1",
            "2001:db8::/ffff:ffff::",
        ] {
            assert!(is_valid_with_netmask(valid), "{valid}");
        }
        for invalid in [
            "10.0.0.0",
            "/8",
            "10.0.0.0/",
            "10.0.0.0/33",
            "10.0.0.0/08",
            "2001:db8::/0",
            "2001:db8::/129",
            "2001:db8::/032",
        ] {
            assert!(!is_valid_with_netmask(invalid), "{invalid}");
        }
        assert!(!is_valid_ipv4_with_netmask("2001:db8::/32"));
        assert!(!is_valid_ipv6_with_netmask("10.0.0.0/8"));
    }
}
