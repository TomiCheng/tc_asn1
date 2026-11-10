//! RFC 5280 §5.3.1 revocation reason codes.
//!
//! ```text
//! CRLReason ::= ENUMERATED {
//!     unspecified(0), keyCompromise(1), cACompromise(2),
//!     affiliationChanged(3), superseded(4), cessationOfOperation(5),
//!     certificateHold(6), removeFromCRL(8), privilegeWithdrawn(9),
//!     aACompromise(10) }
//! ```
//!
//! These are enumeration values, not the bit positions in `ReasonFlags`.

use core::fmt;

use tc_asn1::{
    Asn1Enumerated, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The reason for a CRL entry, including removal from a delta CRL.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::crl::CrlReason;
///
/// assert_eq!(CrlReason::RemoveFromCrl.encode_to_vec(&EncodingOptions::DER)?, [10, 1, 8]);
/// assert_eq!(CrlReason::KeyCompromise.to_string(), "keyCompromise");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CrlReason {
    /// The `unspecified (0)` reason.
    Unspecified = 0,
    /// The `keyCompromise (1)` reason.
    KeyCompromise = 1,
    /// The `cACompromise (2)` reason.
    CaCompromise = 2,
    /// The `affiliationChanged (3)` reason.
    AffiliationChanged = 3,
    /// The `superseded (4)` reason.
    Superseded = 4,
    /// The `cessationOfOperation (5)` reason.
    CessationOfOperation = 5,
    /// The `certificateHold (6)` reason.
    CertificateHold = 6,
    /// The `removeFromCRL (8)` reason.
    RemoveFromCrl = 8,
    /// The `privilegeWithdrawn (9)` reason.
    PrivilegeWithdrawn = 9,
    /// The `aACompromise (10)` reason.
    AaCompromise = 10,
}

impl CrlReason {
    /// Returns the ASN.1 enumeration value.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Returns the named reason, rejecting unassigned values with `MalformedValue`.
    pub fn from_number(number: u8) -> Result<Self, Asn1Error> {
        match number {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::KeyCompromise),
            2 => Ok(Self::CaCompromise),
            3 => Ok(Self::AffiliationChanged),
            4 => Ok(Self::Superseded),
            5 => Ok(Self::CessationOfOperation),
            6 => Ok(Self::CertificateHold),
            8 => Ok(Self::RemoveFromCrl),
            9 => Ok(Self::PrivilegeWithdrawn),
            10 => Ok(Self::AaCompromise),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl fmt::Display for CrlReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "cACompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::RemoveFromCrl => "removeFromCRL",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AaCompromise => "aACompromise",
        })
    }
}

impl DecodeInner for CrlReason {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, value) = Asn1Enumerated::decode_inner(buff, context)?;
        let number = u64::try_from(&value).map_err(|_| Asn1Error::MalformedValue)?;
        let number = u8::try_from(number).map_err(|_| Asn1Error::MalformedValue)?;
        Ok((used, Self::from_number(number)?))
    }
}

impl EncodeContent for CrlReason {
    fn content_len(&self, _rules: &EncodingOptions) -> usize {
        1
    }

    fn encode_content(&self, _rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        *out.first_mut().ok_or(Asn1Error::BufferTooSmall)? = self.number();
        Ok(1)
    }
}

impl Decode for CrlReason {}

impl Tagged for CrlReason {
    const TAG: &'static [u8] = tag::ENUMERATED;
}

impl EncodeTagged for CrlReason {}

impl Encode for CrlReason {
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

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::CrlReason;

    #[test]
    fn assigned_reasons_use_enumerated_values_not_reason_flag_positions() {
        for (number, name) in [
            (0, "unspecified"),
            (1, "keyCompromise"),
            (2, "cACompromise"),
            (3, "affiliationChanged"),
            (4, "superseded"),
            (5, "cessationOfOperation"),
            (6, "certificateHold"),
            (8, "removeFromCRL"),
            (9, "privilegeWithdrawn"),
            (10, "aACompromise"),
        ] {
            let value = CrlReason::from_number(number).unwrap();
            let wire = [0x0a, 1, number];
            assert_eq!(value.to_string(), name);
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                CrlReason::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn unassigned_and_negative_reasons_are_rejected_without_truncation() {
        for wire in [
            &b"\x0a\x01\x07"[..],
            &b"\x0a\x01\x0b"[..],
            &b"\x0a\x01\xff"[..],
            &b"\x0a\x02\x01\x00"[..],
        ] {
            assert_eq!(
                CrlReason::decode_der(wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn an_integer_is_not_accepted_in_place_of_an_enumerated_reason() {
        assert_eq!(
            CrlReason::decode_der(b"\x02\x01\x01", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
