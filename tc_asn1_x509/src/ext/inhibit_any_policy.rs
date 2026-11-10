//! RFC 5280 §4.2.1.14 anyPolicy processing limit.
//!
//! ```text
//! InhibitAnyPolicy ::= SkipCerts
//! SkipCerts ::= INTEGER (0..MAX)
//! ```
//!
//! Criticality and certification path processing belong to the validator.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

/// Number of additional certificates before anyPolicy is inhibited.
/// Arbitrarily large non-negative integers are preserved.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::ext::InhibitAnyPolicy;
///
/// let limit = InhibitAnyPolicy::new(0)?;
/// assert_eq!(limit.to_string(), "0");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct InhibitAnyPolicy {
    skip_certs: Asn1Integer,
}

impl InhibitAnyPolicy {
    /// Creates a non-negative skip count. Negative values are `MalformedValue`.
    pub fn new(skip_certs: impl Into<Asn1Integer>) -> Result<Self, Asn1Error> {
        let skip_certs = skip_certs.into();
        if skip_certs.is_negative() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { skip_certs })
    }

    /// Returns the skip count without narrowing it to a machine integer.
    pub fn skip_certs(&self) -> &Asn1Integer {
        &self.skip_certs
    }
}

impl fmt::Display for InhibitAnyPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.skip_certs.fmt(f)
    }
}

impl DecodeContent for InhibitAnyPolicy {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Self::new(Asn1Integer::decode_content(value, context)?)
    }
}

impl DecodeInner for InhibitAnyPolicy {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, n) = Asn1Integer::decode_inner(buff, context)?;
        Ok((used, Self::new(n)?))
    }
}

impl EncodeContent for InhibitAnyPolicy {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.skip_certs.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.skip_certs.encode_content(rules, out)
    }
}

impl Decode for InhibitAnyPolicy {}

impl Tagged for InhibitAnyPolicy {
    const TAG: &'static [u8] = Asn1Integer::TAG;
}

impl EncodeTagged for InhibitAnyPolicy {}

impl Encode for InhibitAnyPolicy {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::InhibitAnyPolicy;

    #[test]
    fn zero_and_counts_above_u32_round_trip_without_narrowing() {
        for wire in [&b"\x02\x01\x00"[..], &b"\x02\x05\x01\x00\x00\x00\x00"[..]] {
            let (used, value) =
                InhibitAnyPolicy::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                InhibitAnyPolicy::decode(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn negative_counts_and_non_integer_tags_are_rejected() {
        assert!(matches!(
            InhibitAnyPolicy::decode(b"\x02\x01\xff", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            InhibitAnyPolicy::decode(b"\x05\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn zero_is_a_valid_skip_count_but_negative_counts_are_not() {
        assert!(matches!(
            InhibitAnyPolicy::new(-1),
            Err(Asn1Error::MalformedValue)
        ));
        assert_eq!(InhibitAnyPolicy::new(0).unwrap().skip_certs(), &0.into());
    }
}
