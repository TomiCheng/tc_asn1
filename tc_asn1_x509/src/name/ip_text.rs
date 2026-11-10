//! The octets of an iPAddress written as text, after `GeneralName`'s
//! `ToGeneralNameEncoding` in Bouncy Castle.
//!
//! The text is validated by `ip_address` first, as Bouncy Castle validates it
//! with `IPAddress`, so the parsers below only see well-formed input; they
//! still return `None` rather than panic.

use alloc::vec::Vec;

use super::ip_address::{
    is_valid_ipv4, is_valid_ipv4_with_netmask, is_valid_ipv6, is_valid_ipv6_with_netmask,
};

/// 4 or 16 octets for an address, 8 or 32 for an address and mask; `None`
/// when the text is not an IPv4 or IPv6 address, with or without a mask.
pub(super) fn to_octets(ip: &str) -> Option<Vec<u8>> {
    if is_valid_ipv6_with_netmask(ip) || is_valid_ipv6(ip) {
        let mut octets = Vec::with_capacity(32);
        match ip.split_once('/') {
            None => push_groups(&mut octets, &parse_ipv6(ip)?),
            Some((address, mask)) => {
                push_groups(&mut octets, &parse_ipv6(address)?);
                // BC tests for a ':' after the first character, so a mask of
                // "::" falls through to the prefix parser and throws.
                let mask = if mask.contains(':') {
                    parse_ipv6(mask)?
                } else {
                    parse_ipv6_mask(mask)?
                };
                push_groups(&mut octets, &mask);
            }
        }
        Some(octets)
    } else if is_valid_ipv4_with_netmask(ip) || is_valid_ipv4(ip) {
        let mut octets = Vec::with_capacity(8);
        match ip.split_once('/') {
            None => octets.extend(parse_ipv4(ip)?),
            Some((address, mask)) => {
                octets.extend(parse_ipv4(address)?);
                let mask = if mask.contains('.') {
                    parse_ipv4(mask)?
                } else {
                    parse_ipv4_mask(mask)?
                };
                octets.extend(mask);
            }
        }
        Some(octets)
    } else {
        None
    }
}

fn push_groups(octets: &mut Vec<u8>, groups: &[u16; 8]) {
    for group in groups {
        octets.extend(group.to_be_bytes());
    }
}

fn parse_ipv4(ip: &str) -> Option<[u8; 4]> {
    let mut octets = [0; 4];
    let mut parts = ip.split('.');
    for octet in &mut octets {
        *octet = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(octets)
}

fn parse_ipv4_mask(mask: &str) -> Option<[u8; 4]> {
    let mut bits: u32 = mask.parse().ok()?;
    let mut octets = [0; 4];
    for octet in &mut octets {
        if bits >= 8 {
            *octet = 0xff;
            bits -= 8;
        } else {
            *octet = (0xff00_u32 >> bits) as u8;
            bits = 0;
        }
    }
    Some(octets)
}

fn parse_ipv6(ip: &str) -> Option<[u16; 8]> {
    let ip = if ip.starts_with("::") {
        &ip[1..]
    } else if ip.ends_with("::") {
        &ip[..ip.len() - 1]
    } else {
        ip
    };

    let mut groups = [0u16; 8];
    let mut index = 0;
    let mut double_colon = None;
    for part in ip.split(':') {
        if part.is_empty() {
            double_colon = Some(index);
            *groups.get_mut(index)? = 0;
            index += 1;
        } else if !part.contains('.') {
            *groups.get_mut(index)? = u16::from_str_radix(part, 16).ok()?;
            index += 1;
        } else {
            let [a, b, c, d] = parse_ipv4(part)?;
            *groups.get_mut(index)? = u16::from_be_bytes([a, b]);
            *groups.get_mut(index + 1)? = u16::from_be_bytes([c, d]);
            index += 2;
        }
    }

    if index != groups.len() {
        // The groups after `::` move to the end; the gap is zero.
        let start = double_colon?;
        let to = groups.len() - (index - start);
        groups.copy_within(start..index, to);
        groups[start..to].fill(0);
    }
    Some(groups)
}

fn parse_ipv6_mask(mask: &str) -> Option<[u16; 8]> {
    let mut bits: u32 = mask.parse().ok()?;
    let mut groups = [0u16; 8];
    for group in &mut groups {
        if bits >= 16 {
            *group = 0xffff;
            bits -= 16;
        } else {
            *group = !(0xffff_u16 >> bits);
            bits = 0;
        }
    }
    Some(groups)
}
