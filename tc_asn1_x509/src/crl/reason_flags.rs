//! Revocation reasons covered by a CRL distribution point or an issuing
//! distribution point (RFC 5280 §4.2.1.13 and §5.2.5).
//!
//! ```text
//! ReasonFlags ::= BIT STRING {
//!     unused                (0),
//!     keyCompromise         (1),
//!     cACompromise          (2),
//!     affiliationChanged    (3),
//!     superseded            (4),
//!     cessationOfOperation  (5),
//!     certificateHold       (6),
//!     privilegeWithdrawn    (7),
//!     aACompromise          (8) }
//! ```
//!
//! Combine reasons with `|` and test membership with [`ReasonFlags::contains`].
//! Encoding uses the shortest named-bit BIT STRING; decoding accepts trailing
//! zero bits under BER and rejects them under DER. IMPLICIT fields can be read
//! through [`DecodeContent`], using the surrounding field's tag.

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

use tc_asn1::{
    Asn1BitString, Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

/// A non-empty set of revocation reasons. Combine flags with `|` or `|=`.
///
/// Formatting lists the selected ASN.1 names in bit order, separated by commas.
/// This type describes reason coverage, not an individual CRL entry's reason code.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::crl::ReasonFlags;
///
/// let reasons = ReasonFlags::KEY_COMPROMISE | ReasonFlags::CA_COMPROMISE;
/// assert!(reasons.contains(ReasonFlags::KEY_COMPROMISE));
/// assert_eq!(reasons.to_string(), "keyCompromise, cACompromise");
///
/// let der = reasons.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = ReasonFlags::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, reasons);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReasonFlags {
    bits: u32,
}

impl ReasonFlags {
    // Bit i maps to 1 << (31 - i): the first four data octets in big-endian order.
    /// The ASN.1 `unused` bit (0).
    pub const UNUSED: Self = Self { bits: 1 << 31 };
    /// Key compromise (bit 1).
    pub const KEY_COMPROMISE: Self = Self { bits: 1 << 30 };
    /// Certification authority compromise (bit 2).
    pub const CA_COMPROMISE: Self = Self { bits: 1 << 29 };
    /// A change in affiliation (bit 3).
    pub const AFFILIATION_CHANGED: Self = Self { bits: 1 << 28 };
    /// The certificate has been superseded (bit 4).
    pub const SUPERSEDED: Self = Self { bits: 1 << 27 };
    /// Cessation of operation (bit 5).
    pub const CESSATION_OF_OPERATION: Self = Self { bits: 1 << 26 };
    /// The certificate is on hold (bit 6).
    pub const CERTIFICATE_HOLD: Self = Self { bits: 1 << 25 };
    /// Privileges have been withdrawn (bit 7).
    pub const PRIVILEGE_WITHDRAWN: Self = Self { bits: 1 << 24 };
    /// Attribute authority compromise (bit 8).
    pub const AA_COMPROMISE: Self = Self { bits: 1 << 23 };

    const NAMES: [(Self, &'static str); 9] = [
        (Self::UNUSED, "unused"),
        (Self::KEY_COMPROMISE, "keyCompromise"),
        (Self::CA_COMPROMISE, "cACompromise"),
        (Self::AFFILIATION_CHANGED, "affiliationChanged"),
        (Self::SUPERSEDED, "superseded"),
        (Self::CESSATION_OF_OPERATION, "cessationOfOperation"),
        (Self::CERTIFICATE_HOLD, "certificateHold"),
        (Self::PRIVILEGE_WITHDRAWN, "privilegeWithdrawn"),
        (Self::AA_COMPROMISE, "aACompromise"),
    ];
    const DEFINED: u32 = 0xFF80_0000;

    /// Creates a reason set from the raw mask returned by [`bits`](Self::bits).
    /// ASN.1 bit `i` is represented by `1 << (31 - i)`.
    ///
    /// Returns [`Asn1Error::MalformedValue`] if the mask is zero or contains
    /// any bit outside the nine defined flags.
    pub fn from_bits(bits: u32) -> Result<Self, Asn1Error> {
        if bits == 0 || bits & !Self::DEFINED != 0 {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { bits })
    }

    /// Returns the raw mask, with ASN.1 bit `i` represented by `1 << (31 - i)`.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Returns whether this set contains every reason in `other`.
    pub fn contains(self, other: Self) -> bool {
        self.bits & other.bits == other.bits
    }

    // Drops trailing zero bits as required for a DER named-bit list.
    fn bit_string(self) -> Asn1BitString {
        let bit_len = 32 - self.bits.trailing_zeros() as usize;
        Asn1BitString::from_bits(&self.bits.to_be_bytes(), bit_len)
    }

    fn from_bit_string(
        bit_string: Asn1BitString,
        context: &DecodingContext,
    ) -> Result<Self, Asn1Error> {
        let bytes = bit_string.as_bytes();
        let (head, rest) = bytes.split_at(bytes.len().min(4));
        if rest.iter().any(|byte| *byte != 0) {
            return Err(Asn1Error::MalformedValue);
        }
        let mut octets = [0; 4];
        octets[..head.len()].copy_from_slice(head);
        let flags = Self::from_bits(u32::from_be_bytes(octets))?;
        if context.is_der() && bit_string.bit_len() != flags.bit_string().bit_len() {
            return Err(Asn1Error::NotDer);
        }
        Ok(flags)
    }
}

impl BitOr for ReasonFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

impl BitOrAssign for ReasonFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.bits |= rhs.bits;
    }
}

/// Lists the selected ASN.1 names in bit order, separated by `, `.
impl fmt::Display for ReasonFlags {
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

impl DecodeContent for ReasonFlags {
    /// Reads BIT STRING contents: an unused-bit count followed by the data octets.
    /// Use this for IMPLICIT fields after consuming their tag and length.
    /// The same value and DER checks apply as for a complete BIT STRING.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Self::from_bit_string(Asn1BitString::decode_content(value, context)?, context)
    }
}

impl DecodeInner for ReasonFlags {
    /// Reads a primitive BIT STRING containing at least one defined flag.
    /// Empty sets and set bits beyond bit 8 return [`Asn1Error::MalformedValue`].
    /// Under DER, trailing zero bits return [`Asn1Error::NotDer`].
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, bit_string) = Asn1BitString::decode_inner(buff, context)?;
        Ok((used, Self::from_bit_string(bit_string, context)?))
    }
}

impl Decode for ReasonFlags {}

impl Tagged for ReasonFlags {
    const TAG: &'static [u8] = Asn1BitString::TAG;
}

impl EncodeContent for ReasonFlags {
    /// Returns the content length of the shortest named-bit encoding.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.bit_string().content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.bit_string().encode_content(rules, out)
    }
}

impl EncodeTagged for ReasonFlags {}

impl Encode for ReasonFlags {
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

    use tc_asn1::{
        Asn1Error, Asn1Ref, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions,
    };

    use super::ReasonFlags;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn flags_encode_to_the_shortest_bit_string_and_decode_back() {
        let cases: [(ReasonFlags, &[u8], &str); 4] = [
            (ReasonFlags::UNUSED, b"\x03\x02\x07\x80", "unused"),
            (
                ReasonFlags::KEY_COMPROMISE | ReasonFlags::CA_COMPROMISE,
                b"\x03\x02\x05\x60",
                "keyCompromise, cACompromise",
            ),
            (
                ReasonFlags::CERTIFICATE_HOLD | ReasonFlags::PRIVILEGE_WITHDRAWN,
                b"\x03\x02\x00\x03",
                "certificateHold, privilegeWithdrawn",
            ),
            (
                ReasonFlags::AFFILIATION_CHANGED | ReasonFlags::AA_COMPROMISE,
                b"\x03\x03\x07\x10\x80",
                "affiliationChanged, aACompromise",
            ),
        ];
        for (flags, wire, text) in cases {
            assert_eq!(flags.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            let (used, decoded) = ReasonFlags::decode(wire, &options()).unwrap();
            assert_eq!((used, decoded), (wire.len(), flags));
            assert_eq!(decoded.to_string(), text);
            assert_eq!(ReasonFlags::decode_der(wire, &options()).unwrap().1, flags);
        }
    }

    #[test]
    fn implicit_context_specific_one_decodes_through_decode_content() {
        let wire = b"\x30\x04\x81\x02\x06\x40";
        let mut context = DecodingContext::new(options());
        let sequence = Asn1Ref::parse(wire, &mut context).unwrap();
        let mut fields = sequence.children(&mut context).unwrap();
        assert_eq!(
            fields.get_implicit::<ReasonFlags>([0x81]).unwrap(),
            ReasonFlags::KEY_COMPROMISE
        );
        fields.end().unwrap();
    }

    #[test]
    fn trailing_zero_bits_are_accepted_under_ber_and_rejected_under_der() {
        for wire in [
            &b"\x03\x02\x00\x60"[..],
            b"\x03\x03\x07\x60\x00",
            b"\x03\x04\x00\x60\x00\x00",
        ] {
            let (_, decoded) = ReasonFlags::decode(wire, &options()).unwrap();
            assert_eq!(
                decoded,
                ReasonFlags::KEY_COMPROMISE | ReasonFlags::CA_COMPROMISE
            );
            assert!(matches!(
                ReasonFlags::decode_der(wire, &options()),
                Err(Asn1Error::NotDer)
            ));
        }
    }

    #[test]
    fn no_bit_and_undefined_bits_are_rejected() {
        for wire in [
            &b"\x03\x01\x00"[..],
            b"\x03\x02\x07\x00",
            b"\x03\x03\x06\x00\x40",
            b"\x03\x04\x00\x60\x00\x01",
        ] {
            assert!(matches!(
                ReasonFlags::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            ReasonFlags::from_bits(0),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            ReasonFlags::from_bits(1 << 6),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn flags_combine_and_contain() {
        let mut flags = ReasonFlags::KEY_COMPROMISE;
        flags |= ReasonFlags::CESSATION_OF_OPERATION;
        assert!(flags.contains(ReasonFlags::KEY_COMPROMISE));
        assert!(flags.contains(ReasonFlags::KEY_COMPROMISE | ReasonFlags::CESSATION_OF_OPERATION));
        assert!(!flags.contains(ReasonFlags::CERTIFICATE_HOLD));
        assert_eq!(flags.bits(), 0x4400_0000);
    }
}
