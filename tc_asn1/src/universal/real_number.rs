//! The minimal integer operations REAL normalization needs; no public arithmetic API.

use crate::Asn1Error;
use alloc::{string::String, vec, vec::Vec};
use core::cmp::Ordering;

/// Little-endian base-256 magnitude; zero is the empty vector.
#[derive(Clone, Debug, Default)]
pub(super) struct Magnitude(pub(super) Vec<u8>);
impl Magnitude {
    pub(super) fn from_be(bytes: &[u8]) -> Self {
        let mut n = Self(bytes.iter().rev().copied().collect());
        n.trim();
        n
    }
    fn trim(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }
    pub(super) fn decimal(digits: &[u8]) -> Result<Self, Asn1Error> {
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(Asn1Error::MalformedValue);
        }
        let mut n = Self::default();
        for digit in digits {
            n.mul(10);
            n.add(&Self(vec![digit - b'0']));
        }
        Ok(n)
    }
    pub(super) fn mul(&mut self, factor: u16) {
        let mut carry = 0_u32;
        for digit in &mut self.0 {
            carry += u32::from(*digit) * u32::from(factor);
            *digit = carry as u8;
            carry >>= 8;
        }
        while carry != 0 {
            self.0.push(carry as u8);
            carry >>= 8;
        }
        self.trim();
    }
    fn add(&mut self, other: &Self) {
        let count = self.0.len().max(other.0.len());
        self.0.resize(count, 0);
        let mut carry = 0_u16;
        for (i, digit) in self.0.iter_mut().enumerate() {
            carry += u16::from(*digit) + u16::from(other.0.get(i).copied().unwrap_or(0));
            *digit = carry as u8;
            carry >>= 8;
        }
        if carry != 0 {
            self.0.push(carry as u8);
        }
        self.trim();
    }
    fn compare(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }
    fn subtract(&mut self, other: &Self) {
        let mut borrow = 0_i16;
        for (i, digit) in self.0.iter_mut().enumerate() {
            let next = i16::from(*digit) - i16::from(other.0.get(i).copied().unwrap_or(0)) - borrow;
            *digit = next as u8;
            borrow = i16::from(next < 0);
        }
        debug_assert_eq!(borrow, 0);
        self.trim();
    }
    pub(super) fn divide(&mut self, divisor: u16) -> u16 {
        let mut rem = 0_u16;
        for digit in self.0.iter_mut().rev() {
            let next = (rem << 8) | u16::from(*digit);
            *digit = (next / divisor) as u8;
            rem = next % divisor;
        }
        self.trim();
        rem
    }
    pub(super) fn to_be(&self) -> Vec<u8> {
        self.0.iter().rev().copied().collect()
    }
    fn decimal_text(&self) -> String {
        if self.0.is_empty() {
            return String::from("0");
        }
        let mut n = self.clone();
        let mut digits = Vec::new();
        while !n.0.is_empty() {
            digits.push(b'0' + n.divide(10) as u8);
        }
        digits.reverse();
        String::from_utf8(digits).expect("decimal digits are ASCII")
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Exponent {
    negative: bool,
    magnitude: Magnitude,
}
impl Exponent {
    pub(super) fn binary(bytes: &[u8]) -> Result<Self, Asn1Error> {
        let first = bytes.first().ok_or(Asn1Error::MalformedValue)?;
        let negative = first & 0x80 != 0;
        let magnitude = if negative {
            let mut n = Magnitude(bytes.iter().rev().map(|b| !b).collect());
            n.add(&Magnitude(vec![1]));
            n
        } else {
            Magnitude::from_be(bytes)
        };
        Ok(Self {
            negative: negative && !magnitude.0.is_empty(),
            magnitude,
        })
    }
    pub(super) fn decimal(text: &str) -> Result<Self, Asn1Error> {
        let (negative, digits) = if let Some(rest) = text.strip_prefix('-') {
            (true, rest)
        } else {
            (false, text.strip_prefix('+').unwrap_or(text))
        };
        let magnitude = Magnitude::decimal(digits.as_bytes())?;
        Ok(Self {
            negative: negative && !magnitude.0.is_empty(),
            magnitude,
        })
    }
    pub(super) fn mul(&mut self, factor: u16) {
        self.magnitude.mul(factor);
    }
    pub(super) fn adjust(&mut self, negative: bool, amount: usize) {
        let other = Magnitude::from_be(&amount.to_be_bytes());
        if self.negative == negative {
            self.magnitude.add(&other);
        } else if self.magnitude.compare(&other) != Ordering::Less {
            self.magnitude.subtract(&other);
        } else {
            let mut larger = other;
            larger.subtract(&self.magnitude);
            self.magnitude = larger;
            self.negative = negative;
        }
        if self.magnitude.0.is_empty() {
            self.negative = false;
        }
    }
    pub(super) fn binary_bytes(&self) -> Vec<u8> {
        let mut bytes = self.magnitude.to_be();
        if bytes.is_empty() {
            return vec![0];
        }
        if self.negative {
            for byte in &mut bytes {
                *byte = !*byte;
            }
            let mut carry = 1_u16;
            for byte in bytes.iter_mut().rev() {
                carry += u16::from(*byte);
                *byte = carry as u8;
                carry >>= 8;
            }
            if bytes[0] & 0x80 == 0 {
                bytes.insert(0, 0xFF);
            }
        } else if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        bytes
    }
    pub(super) fn decimal_text(&self) -> String {
        let mut text = self.magnitude.decimal_text();
        if self.negative {
            text.insert(0, '-');
        }
        text
    }
    pub(super) fn to_i64(&self) -> Result<i64, Asn1Error> {
        let bytes = self.binary_bytes();
        if bytes.len() > 8 {
            return Err(Asn1Error::InexactValue);
        }
        let mut out = [if self.negative { 0xFF } else { 0 }; 8];
        out[8 - bytes.len()..].copy_from_slice(&bytes);
        Ok(i64::from_be_bytes(out))
    }
}
