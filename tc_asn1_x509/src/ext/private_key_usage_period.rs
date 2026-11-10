//! Private key usage bounds (RFC 5280 Appendix A.1).
//!
//! ```text
//! PrivateKeyUsagePeriod ::= SEQUENCE {
//!     notBefore [0] GeneralizedTime OPTIONAL,
//!     notAfter  [1] GeneralizedTime OPTIONAL }
//! ```
//!
//! At least one bound is required. Both fields use IMPLICIT tagging.
//! The bounds do not replace the certificate validity period.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};

/// A private key's permitted usage period, with one or both bounds.
///
/// # Examples
///
/// ```
/// use tc_asn1::Asn1GeneralizedTime;
/// use tc_asn1_x509::ext::PrivateKeyUsagePeriod;
///
/// let end = Asn1GeneralizedTime::new(2030, 1, 1, 0, 0, 0)?;
/// let period = PrivateKeyUsagePeriod::new(None, Some(end))?;
/// assert_eq!(period.not_after(), Some(&end));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PrivateKeyUsagePeriod {
    not_before: Option<Asn1GeneralizedTime>,
    not_after: Option<Asn1GeneralizedTime>,
}

impl PrivateKeyUsagePeriod {
    /// Rejects absent bounds or a start after the end with `MalformedValue`.
    pub fn new(
        not_before: Option<Asn1GeneralizedTime>,
        not_after: Option<Asn1GeneralizedTime>,
    ) -> Result<Self, Asn1Error> {
        if (not_before.is_none() && not_after.is_none())
            || matches!((&not_before, &not_after), (Some(a), Some(b)) if a > b)
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    /// Returns the inclusive start bound.
    pub fn not_before(&self) -> Option<&Asn1GeneralizedTime> {
        self.not_before.as_ref()
    }

    /// Returns the inclusive end bound.
    pub fn not_after(&self) -> Option<&Asn1GeneralizedTime> {
        self.not_after.as_ref()
    }
}

impl fmt::Display for PrivateKeyUsagePeriod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(v) = &self.not_before {
            write!(f, "notBefore: {v}")?;
        }
        if let Some(v) = &self.not_after {
            if self.not_before.is_some() {
                f.write_str(", ")?;
            }
            write!(f, "notAfter: {v}")?;
        }
        Ok(())
    }
}

impl DecodeInner for PrivateKeyUsagePeriod {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let start = fields.get_implicit_opt::<Asn1GeneralizedTime>([0x80])?;
        let end = fields.get_implicit_opt::<Asn1GeneralizedTime>([0x81])?;
        fields.end()?;
        Ok((element.total_len(), Self::new(start, end)?))
    }
}

impl EncodeContent for PrivateKeyUsagePeriod {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.not_before
            .as_ref()
            .map_or(0, |v| Implicit::new(&[0x80], v).encoded_len(rules))
            + self
                .not_after
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x81], v).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.not_before {
            at += Implicit::new(&[0x80], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.not_after {
            at += Implicit::new(&[0x81], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PrivateKeyUsagePeriod {}

impl Tagged for PrivateKeyUsagePeriod {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PrivateKeyUsagePeriod {}

impl Encode for PrivateKeyUsagePeriod {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{
        Asn1Error, Asn1GeneralizedTime, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::PrivateKeyUsagePeriod;

    #[test]
    fn either_or_both_implicit_time_bounds_round_trip() {
        for wire in [
            &b"\x30\x11\x80\x0f20300101000000Z"[..],
            &b"\x30\x11\x81\x0f20310101000000Z"[..],
            &b"\x30\x22\x80\x0f20300101000000Z\x81\x0f20310101000000Z"[..],
        ] {
            let (used, value) =
                PrivateKeyUsagePeriod::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                PrivateKeyUsagePeriod::decode(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn empty_reversed_out_of_order_and_invalid_time_bounds_are_rejected() {
        assert!(matches!(
            PrivateKeyUsagePeriod::decode(b"\x30\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PrivateKeyUsagePeriod::decode(
                b"\x30\x22\x80\x0f20310101000000Z\x81\x0f20300101000000Z",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PrivateKeyUsagePeriod::decode(
                b"\x30\x22\x81\x0f20310101000000Z\x80\x0f20300101000000Z",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::TrailingData)
        ));
        assert!(matches!(
            PrivateKeyUsagePeriod::decode(
                b"\x30\x11\x80\x0f20301301000000Z",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn usage_bounds_must_exist_and_be_ordered_but_may_be_equal() {
        let a = Asn1GeneralizedTime::new(2030, 1, 1, 0, 0, 0).unwrap();
        let b = Asn1GeneralizedTime::new(2031, 1, 1, 0, 0, 0).unwrap();
        assert!(matches!(
            PrivateKeyUsagePeriod::new(None, None),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PrivateKeyUsagePeriod::new(Some(b), Some(a)),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(PrivateKeyUsagePeriod::new(Some(a), Some(a)).is_ok());
    }
}
