//! RFC 5280 §5.2.3 CRL number, also the value of the delta CRL indicator.
//!
//! ```text
//! CRLNumber ::= INTEGER (0..MAX)
//! BaseCRLNumber ::= CRLNumber
//! ```
//!
//! Comparing numbers across CRLs from the same issuer belongs to the validator.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

/// A monotonically increasing CRL sequence number.
/// Arbitrarily large non-negative integers are preserved; RFC 5280 allows up to 20 octets.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::crl::CrlNumber;
///
/// let number = CrlNumber::new(42)?;
/// assert_eq!(number.to_string(), "42");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlNumber {
    number: Asn1Integer,
}

impl CrlNumber {
    /// Creates a non-negative CRL number. Negative values are `MalformedValue`.
    pub fn new(number: impl Into<Asn1Integer>) -> Result<Self, Asn1Error> {
        let number = number.into();
        if number.is_negative() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { number })
    }

    /// Returns the number without narrowing it to a machine integer.
    pub fn number(&self) -> &Asn1Integer {
        &self.number
    }
}

impl fmt::Display for CrlNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.number.fmt(f)
    }
}

impl DecodeContent for CrlNumber {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Self::new(Asn1Integer::decode_content(value, context)?)
    }
}

impl DecodeInner for CrlNumber {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, number) = Asn1Integer::decode_inner(buff, context)?;
        Ok((used, Self::new(number)?))
    }
}

impl EncodeContent for CrlNumber {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.number.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.number.encode_content(rules, out)
    }
}

impl Decode for CrlNumber {}

impl Tagged for CrlNumber {
    const TAG: &'static [u8] = Asn1Integer::TAG;
}

impl EncodeTagged for CrlNumber {}

impl Encode for CrlNumber {
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

    use super::CrlNumber;

    #[test]
    fn zero_and_a_twenty_octet_number_round_trip_without_narrowing() {
        let mut long = [0x02, 20, 0x7f].to_vec();
        long.extend([0xff; 19]);
        for wire in [&b"\x02\x01\x00"[..], &long[..]] {
            let (used, value) = CrlNumber::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        }
    }

    #[test]
    fn negative_numbers_and_non_integer_tags_are_rejected() {
        assert_eq!(CrlNumber::new(-1), Err(Asn1Error::MalformedValue));
        assert!(matches!(
            CrlNumber::decode(b"\x02\x01\xff", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            CrlNumber::decode(b"\x04\x01\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
