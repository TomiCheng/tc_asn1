//! RFC 5280 §4.2.1.3 `KeyUsage`, the value of extension 2.5.29.15.
//!
//! ```text
//! KeyUsage ::= BIT STRING {
//!     digitalSignature  (0),  nonRepudiation   (1),  keyEncipherment (2),
//!     dataEncipherment  (3),  keyAgreement     (4),  keyCertSign     (5),
//!     cRLSign           (6),  encipherOnly     (7),  decipherOnly    (8) }
//! ```
//!
//! A named-bit BIT STRING: bit 0 is the most significant bit of the first
//! octet. Nine bits are defined, at least one must be set, and DER drops the
//! trailing zero bits (X.690 §11.2.2), so `keyCertSign | cRLSign` is
//! `03 02 01 06` rather than `03 02 00 06`.

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

use tc_asn1::{
    Asn1BitString, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// The set of purposes a key may be used for. Combine flags with `|`.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::KeyUsage;
///
/// // A CA key: signs certificates and CRLs.
/// let usage = KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN;
/// assert!(usage.contains(KeyUsage::CRL_SIGN));
/// assert!(!usage.contains(KeyUsage::DIGITAL_SIGNATURE));
/// println!("{usage}");   // keyCertSign, cRLSign
///
/// let der = usage.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = KeyUsage::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, usage);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KeyUsage {
    bits: u32,
}

impl KeyUsage {
    // Bit i of the BIT STRING is 1 << (31 - i), so the u32 is the first four
    // content octets big-endian.
    /// Verifying signatures other than on certificates and CRLs.
    pub const DIGITAL_SIGNATURE: Self = Self { bits: 1 << 31 };
    /// Called contentCommitment in recent editions of X.509.
    pub const NON_REPUDIATION: Self = Self { bits: 1 << 30 };
    /// Encrypting keys, as RSA key transport does.
    pub const KEY_ENCIPHERMENT: Self = Self { bits: 1 << 29 };
    /// Encrypting user data directly, rarely used.
    pub const DATA_ENCIPHERMENT: Self = Self { bits: 1 << 28 };
    /// Key agreement, as Diffie-Hellman does.
    pub const KEY_AGREEMENT: Self = Self { bits: 1 << 27 };
    /// Verifying signatures on certificates, for a CA.
    pub const KEY_CERT_SIGN: Self = Self { bits: 1 << 26 };
    /// Verifying signatures on CRLs.
    pub const CRL_SIGN: Self = Self { bits: 1 << 25 };
    /// Meaningful only with `KEY_AGREEMENT`.
    pub const ENCIPHER_ONLY: Self = Self { bits: 1 << 24 };
    /// Meaningful only with `KEY_AGREEMENT`.
    pub const DECIPHER_ONLY: Self = Self { bits: 1 << 23 };

    const NAMES: [(Self, &'static str); 9] = [
        (Self::DIGITAL_SIGNATURE, "digitalSignature"),
        (Self::NON_REPUDIATION, "nonRepudiation"),
        (Self::KEY_ENCIPHERMENT, "keyEncipherment"),
        (Self::DATA_ENCIPHERMENT, "dataEncipherment"),
        (Self::KEY_AGREEMENT, "keyAgreement"),
        (Self::KEY_CERT_SIGN, "keyCertSign"),
        (Self::CRL_SIGN, "cRLSign"),
        (Self::ENCIPHER_ONLY, "encipherOnly"),
        (Self::DECIPHER_ONLY, "decipherOnly"),
    ];
    const DEFINED: u32 = 0xFF80_0000;

    /// From the raw bits, `1 << (31 - i)` for bit `i`. No bit set or an
    /// undefined bit set is `MalformedValue`.
    pub fn from_bits(bits: u32) -> Result<Self, Asn1Error> {
        if bits == 0 || bits & !Self::DEFINED != 0 {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { bits })
    }

    /// The raw bits, `1 << (31 - i)` for bit `i`.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Whether every flag in `other` is set in `self`.
    pub fn contains(self, other: Self) -> bool {
        self.bits & other.bits == other.bits
    }

    /// The shortest BIT STRING for the flags, as DER wants it.
    fn bit_string(self) -> Asn1BitString {
        let bit_len = 32 - self.bits.trailing_zeros() as usize;
        Asn1BitString::from_bits(&self.bits.to_be_bytes(), bit_len)
    }
}

impl BitOr for KeyUsage {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

impl BitOrAssign for KeyUsage {
    fn bitor_assign(&mut self, rhs: Self) {
        self.bits |= rhs.bits;
    }
}

/// The set flags by their ASN.1 names, comma separated, in bit order.
impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (flag, name) in Self::NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

impl DecodeInner for KeyUsage {
    /// Bits past the ninth must be zero; no bit set is `MalformedValue`.
    /// Under DER a trailing zero bit is `NotDer`, since X.690 §11.2.2 wants
    /// it dropped. Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, bit_string) = Asn1BitString::decode_inner(buff, context)?;
        let bytes = bit_string.as_bytes();
        let (head, rest) = bytes.split_at(bytes.len().min(4));
        if rest.iter().any(|byte| *byte != 0) {
            return Err(Asn1Error::MalformedValue);
        }
        let mut octets = [0; 4];
        octets[..head.len()].copy_from_slice(head);
        let bits = u32::from_be_bytes(octets);
        let usage = Self::from_bits(bits)?;
        if context.is_der() && bit_string.bit_len() != usage.bit_string().bit_len() {
            return Err(Asn1Error::NotDer);
        }
        Ok((used, usage))
    }
}

impl Decode for KeyUsage {}

impl Tagged for KeyUsage {
    const TAG: &'static [u8] = Asn1BitString::TAG;
}

impl EncodeContent for KeyUsage {
    /// Always the shortest form, under every rule set.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.bit_string().content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.bit_string().encode_content(rules, out)
    }
}

impl EncodeTagged for KeyUsage {}

impl Encode for KeyUsage {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};

    use super::KeyUsage;
    use crate::ext::{Extension, ExtensionId};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn flags_encode_to_the_shortest_bit_string_and_decode_back() {
        let cases: [(KeyUsage, &[u8], &str); 4] = [
            (
                KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_ENCIPHERMENT,
                b"\x03\x02\x05\xa0",
                "digitalSignature, keyEncipherment",
            ),
            (
                KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
                b"\x03\x02\x01\x06",
                "keyCertSign, cRLSign",
            ),
            (
                KeyUsage::DIGITAL_SIGNATURE,
                b"\x03\x02\x07\x80",
                "digitalSignature",
            ),
            (
                KeyUsage::KEY_AGREEMENT | KeyUsage::DECIPHER_ONLY,
                b"\x03\x03\x07\x08\x80",
                "keyAgreement, decipherOnly",
            ),
        ];
        for (usage, wire, text) in cases {
            assert_eq!(usage.encode_to_vec(&der()).unwrap(), wire, "{text}");
            let (used, decoded) = KeyUsage::decode(wire, &options()).unwrap();
            assert_eq!((used, decoded), (wire.len(), usage));
            assert_eq!(decoded.to_string(), text);
            assert_eq!(KeyUsage::decode_der(wire, &options()).unwrap().1, usage);
        }
    }

    #[test]
    fn trailing_zero_bits_are_accepted_under_ber_and_rejected_under_der() {
        for wire in [
            &b"\x03\x02\x00\xa0"[..],
            b"\x03\x03\x07\xa0\x00",
            b"\x03\x04\x00\xa0\x00\x00",
        ] {
            let (_, decoded) = KeyUsage::decode(wire, &options()).unwrap();
            assert_eq!(
                decoded,
                KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_ENCIPHERMENT
            );
            assert!(matches!(
                KeyUsage::decode_der(wire, &options()),
                Err(Asn1Error::NotDer)
            ));
        }
    }

    #[test]
    fn no_bit_and_undefined_bits_are_rejected() {
        for wire in [
            &b"\x03\x01\x00"[..],        // empty
            b"\x03\x02\x07\x00",         // one zero bit
            b"\x03\x03\x06\x00\x40",     // bit 9
            b"\x03\x04\x00\xa0\x00\x01", // a set bit far out
        ] {
            assert!(matches!(
                KeyUsage::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            KeyUsage::from_bits(0),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            KeyUsage::from_bits(1 << 6),
            Err(Asn1Error::MalformedValue)
        ));
        assert_eq!(
            KeyUsage::from_bits(0x8000_0000).unwrap(),
            KeyUsage::DIGITAL_SIGNATURE
        );
    }

    #[test]
    fn flags_combine_and_contain() {
        let mut usage = KeyUsage::DIGITAL_SIGNATURE;
        usage |= KeyUsage::KEY_AGREEMENT;
        assert!(usage.contains(KeyUsage::DIGITAL_SIGNATURE));
        assert!(usage.contains(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_AGREEMENT));
        assert!(!usage.contains(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::CRL_SIGN));
        assert_eq!(usage.bits(), 0x8800_0000);
    }

    #[test]
    fn it_travels_inside_a_critical_extension() {
        let usage = KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN;
        let extension = Extension::new(
            ExtensionId::KEY_USAGE,
            true,
            &usage.encode_to_vec(&der()).unwrap(),
        );
        assert_eq!(extension.extn_id().to_string(), "2.5.29.15");
        let wire = extension.encode_to_vec(&der()).unwrap();
        assert_eq!(
            wire,
            b"\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x06"
        );
        let (_, back) = Extension::decode(&wire, &options()).unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(back.extn_value_as::<KeyUsage>(&mut context).unwrap(), usage);
    }
}
