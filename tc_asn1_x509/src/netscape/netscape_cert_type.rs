//! The Netscape certificate type, the value of extension
//! 2.16.840.1.113730.1.1.
//!
//! ```text
//! NetscapeCertType ::= BIT STRING {
//!     SSLClient (0), SSLServer (1), S/MIME (2), Object Signing (3),
//!     Reserved (4), SSL CA (5), S/MIME CA (6), Object Signing CA (7) }
//! ```
//!
//! A named-bit BIT STRING: bit 0 is the most significant bit of the octet, and
//! DER drops the trailing zero bits (X.690 §11.2.2).

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

use tc_asn1::{
    Asn1BitString, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// What a certificate may be used for, in Netscape's terms. Combine flags with `|`.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::netscape::NetscapeCertType;
///
/// let cert_type = NetscapeCertType::SSL_CLIENT | NetscapeCertType::SMIME;
/// assert_eq!(cert_type.to_string(), "sslClient, smime");
/// assert_eq!(cert_type.encode_to_vec(&EncodingOptions::DER)?, [3, 2, 5, 0xa0]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct NetscapeCertType {
    bits: u8,
}

impl NetscapeCertType {
    // Bit i of the BIT STRING is 1 << (7 - i), the content octet itself.
    /// A TLS client.
    pub const SSL_CLIENT: Self = Self { bits: 1 << 7 };
    /// A TLS server.
    pub const SSL_SERVER: Self = Self { bits: 1 << 6 };
    /// S/MIME email.
    pub const SMIME: Self = Self { bits: 1 << 5 };
    /// Signing objects, such as code.
    pub const OBJECT_SIGNING: Self = Self { bits: 1 << 4 };
    /// Reserved; unused.
    pub const RESERVED: Self = Self { bits: 1 << 3 };
    /// A CA for TLS.
    pub const SSL_CA: Self = Self { bits: 1 << 2 };
    /// A CA for S/MIME.
    pub const SMIME_CA: Self = Self { bits: 1 << 1 };
    /// A CA for object signing.
    pub const OBJECT_SIGNING_CA: Self = Self { bits: 1 };

    const NAMES: [(Self, &'static str); 8] = [
        (Self::SSL_CLIENT, "sslClient"),
        (Self::SSL_SERVER, "sslServer"),
        (Self::SMIME, "smime"),
        (Self::OBJECT_SIGNING, "objectSigning"),
        (Self::RESERVED, "reserved"),
        (Self::SSL_CA, "sslCA"),
        (Self::SMIME_CA, "smimeCA"),
        (Self::OBJECT_SIGNING_CA, "objectSigningCA"),
    ];

    /// From the raw octet, `1 << (7 - i)` for bit `i`.
    /// Variable time: branches only on the encoding structure.
    pub fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    /// Returns the raw octet, `1 << (7 - i)` for bit `i`.
    /// Variable time: branches only on the encoding structure.
    pub fn bits(self) -> u8 {
        self.bits
    }

    /// Whether every flag in `other` is set in `self`.
    /// Variable time: branches only on the encoding structure.
    pub fn contains(self, other: Self) -> bool {
        self.bits & other.bits == other.bits
    }

    /// The shortest BIT STRING for the flags, as DER wants it.
    fn bit_string(self) -> Asn1BitString {
        let bit_len = 8 - self.bits.trailing_zeros().min(8) as usize;
        Asn1BitString::from_bits(&[self.bits], bit_len)
    }
}

impl BitOr for NetscapeCertType {
    type Output = Self;

    /// Variable time: branches only on the encoding structure.
    fn bitor(self, rhs: Self) -> Self {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

impl BitOrAssign for NetscapeCertType {
    /// Variable time: branches only on the encoding structure.
    fn bitor_assign(&mut self, rhs: Self) {
        self.bits |= rhs.bits;
    }
}

/// The set flags by name, comma separated, in bit order.
impl fmt::Display for NetscapeCertType {
    /// Variable time: branches only on the encoding structure.
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

impl DecodeInner for NetscapeCertType {
    /// Bits past the eighth must be zero. Under DER a trailing zero bit is
    /// `NotDer`, since X.690 §11.2.2 wants it dropped.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, bit_string) = Asn1BitString::decode_inner(buff, context)?;
        let bytes = bit_string.as_bytes();
        if bytes.iter().skip(1).any(|byte| *byte != 0) {
            return Err(Asn1Error::MalformedValue);
        }
        let cert_type = Self::from_bits(bytes.first().copied().unwrap_or(0));
        if context.is_der() && bit_string.bit_len() != cert_type.bit_string().bit_len() {
            return Err(Asn1Error::NotDer);
        }
        Ok((used, cert_type))
    }
}

impl Decode for NetscapeCertType {}

impl Tagged for NetscapeCertType {
    const TAG: &'static [u8] = Asn1BitString::TAG;
}

impl EncodeContent for NetscapeCertType {
    /// Always the shortest form, under every rule set.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.bit_string().content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.bit_string().encode_content(rules, out)
    }
}

impl EncodeTagged for NetscapeCertType {}

impl Encode for NetscapeCertType {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::NetscapeCertType;

    #[test]
    fn bc_flags_sit_at_their_named_bit_positions() {
        let flags = [
            NetscapeCertType::SSL_CLIENT,
            NetscapeCertType::SSL_SERVER,
            NetscapeCertType::SMIME,
            NetscapeCertType::OBJECT_SIGNING,
            NetscapeCertType::RESERVED,
            NetscapeCertType::SSL_CA,
            NetscapeCertType::SMIME_CA,
            NetscapeCertType::OBJECT_SIGNING_CA,
        ];
        for (index, flag) in flags.into_iter().enumerate() {
            let der = flag.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(der, [3, 2, 7 - index as u8, 0x80 >> index]);
            assert_eq!(
                NetscapeCertType::decode_der(&der, &DecodingOptions::default())
                    .unwrap()
                    .1,
                flag
            );
        }
    }

    #[test]
    fn bc_misc_test_encodes_smime_as_one_bit_after_two() {
        let der = NetscapeCertType::SMIME
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        assert_eq!(der, [3, 2, 5, 0x20]);
    }

    #[test]
    fn no_flags_is_an_empty_bit_string_and_padding_is_not_der() {
        let none = NetscapeCertType::default();
        assert_eq!(
            none.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [3, 1, 0]
        );
        let options = DecodingOptions::default();
        assert_eq!(
            NetscapeCertType::decode_der(&[3, 2, 0, 0x80], &options),
            Err(Asn1Error::NotDer)
        );
        assert_eq!(
            NetscapeCertType::decode(&[3, 3, 0, 0x80, 1], &options),
            Err(Asn1Error::MalformedValue)
        );
    }
}
