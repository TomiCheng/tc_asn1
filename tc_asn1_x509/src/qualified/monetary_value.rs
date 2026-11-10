//! RFC 3739 §3.2.6 monetary value, the info of the `QcLimitValue` statement.
//!
//! ```text
//! MonetaryValue ::= SEQUENCE {
//!     currency Iso4217CurrencyCode,
//!     amount   INTEGER,
//!     exponent INTEGER }
//! -- value = amount * 10^exponent
//! ```
//!
//! Neither integer is constrained, so negative values are kept.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::qualified::Iso4217CurrencyCode;

/// `amount` times ten to the `exponent`, in `currency`.
///
/// ```
/// use tc_asn1_x509::qualified::{Iso4217CurrencyCode, MonetaryValue};
///
/// // 25 000 euro
/// let limit = MonetaryValue::new(Iso4217CurrencyCode::alphabetic("EUR")?, 25, 3);
/// assert_eq!(limit.currency().as_alphabetic(), Some("EUR"));
/// assert_eq!(i64::try_from(limit.exponent()), Ok(3));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MonetaryValue {
    currency: Iso4217CurrencyCode,
    amount: Asn1Integer,
    exponent: Asn1Integer,
}

impl MonetaryValue {
    /// Stores the three fields as given.
    pub fn new(
        currency: Iso4217CurrencyCode,
        amount: impl Into<Asn1Integer>,
        exponent: impl Into<Asn1Integer>,
    ) -> Self {
        Self {
            currency,
            amount: amount.into(),
            exponent: exponent.into(),
        }
    }

    /// Returns `currency`.
    pub fn currency(&self) -> &Iso4217CurrencyCode {
        &self.currency
    }

    /// Returns `amount`.
    pub fn amount(&self) -> &Asn1Integer {
        &self.amount
    }

    /// Returns `exponent`.
    pub fn exponent(&self) -> &Asn1Integer {
        &self.exponent
    }
}

impl DecodeContent for MonetaryValue {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let currency = fields.get()?;
        let amount = fields.get::<Asn1Integer>()?;
        let exponent = fields.get::<Asn1Integer>()?;
        fields.end()?;
        Ok(Self::new(currency, amount, exponent))
    }
}

impl DecodeInner for MonetaryValue {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        Ok((
            element.total_len(),
            Self::decode_content(element.value(), context)?,
        ))
    }
}

impl EncodeContent for MonetaryValue {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.currency.encoded_len(rules)
            + self.amount.encoded_len(rules)
            + self.exponent.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.currency.encode(rules, out)?;
        at += self.amount.encode(rules, &mut out[at..])?;
        at += self.exponent.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for MonetaryValue {}

impl Tagged for MonetaryValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for MonetaryValue {}

impl Encode for MonetaryValue {
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

    use super::MonetaryValue;
    use crate::qualified::Iso4217CurrencyCode;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_three_fields_round_trip_in_order() {
        let value = MonetaryValue::new(Iso4217CurrencyCode::alphabetic("EUR").unwrap(), 25, 3);
        let wire = b"\x30\x0b\x13\x03EUR\x02\x01\x19\x02\x01\x03";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            MonetaryValue::decode_der(wire, &options()).unwrap().1,
            value
        );
    }

    #[test]
    fn a_negative_exponent_and_a_numeric_currency_are_kept() {
        let wire = b"\x30\x0a\x02\x02\x03\xd2\x02\x01\x05\x02\x01\xfe";
        let value = MonetaryValue::decode_der(wire, &options()).unwrap().1;
        assert_eq!(value.currency().as_numeric(), Some(978));
        assert_eq!(i64::try_from(value.exponent()), Ok(-2));
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
    }

    #[test]
    fn a_missing_field_or_a_bad_currency_is_rejected() {
        assert!(MonetaryValue::decode_der(b"\x30\x08\x13\x03EUR\x02\x01\x19", &options()).is_err());
        assert_eq!(
            MonetaryValue::decode_der(b"\x30\x0a\x13\x02EU\x02\x01\x19\x02\x01\x03", &options()),
            Err(Asn1Error::MalformedValue)
        );
    }
}
