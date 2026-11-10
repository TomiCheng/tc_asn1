//! RFC 3739 §3.2.6 ISO 4217 currency code, the currency of a [`MonetaryValue`](crate::qualified::MonetaryValue).
//!
//! ```text
//! Iso4217CurrencyCode ::= CHOICE {
//!     alphabetic PrintableString (SIZE (3)), -- recommended
//!     numeric    INTEGER (1..999) }
//! ```
//!
//! Both constraints are checked when building and when decoding. Bouncy
//! Castle accepts alphabetic codes shorter than three characters; this type
//! follows the module and does not.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1PrintableString, Asn1Ref, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions,
};

const NUMERIC_MIN: u16 = 1;
const NUMERIC_MAX: u16 = 999;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum Code {
    Alphabetic(Asn1PrintableString),
    Numeric(Asn1Integer),
}

/// An alphabetic code such as `EUR`, or a numeric one such as `978`.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::qualified::Iso4217CurrencyCode;
///
/// let euro = Iso4217CurrencyCode::alphabetic("EUR")?;
/// assert_eq!(euro.as_alphabetic(), Some("EUR"));
/// assert_eq!(euro.encode_to_vec(&EncodingOptions::DER)?, b"\x13\x03EUR");
/// assert!(Iso4217CurrencyCode::numeric(1000).is_err());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Iso4217CurrencyCode(Code);

impl Iso4217CurrencyCode {
    /// An alphabetic code; anything but three PrintableString characters is
    /// `MalformedValue`.
    pub fn alphabetic(code: &str) -> Result<Self, Asn1Error> {
        Self::from_alphabetic(Asn1PrintableString::new(code)?)
    }

    /// A numeric code; outside 1..=999 is `MalformedValue`.
    pub fn numeric(code: u16) -> Result<Self, Asn1Error> {
        if !(NUMERIC_MIN..=NUMERIC_MAX).contains(&code) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self(Code::Numeric(code.into())))
    }

    fn from_alphabetic(code: Asn1PrintableString) -> Result<Self, Asn1Error> {
        if code.as_str().len() != 3 {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self(Code::Alphabetic(code)))
    }

    fn from_numeric(code: &Asn1Integer) -> Result<Self, Asn1Error> {
        let code = u16::try_from(code).map_err(|_| Asn1Error::MalformedValue)?;
        Self::numeric(code)
    }

    /// The alphabetic code, or `None` for a numeric one.
    pub fn as_alphabetic(&self) -> Option<&str> {
        match &self.0 {
            Code::Alphabetic(code) => Some(code.as_str()),
            Code::Numeric(_) => None,
        }
    }

    /// The numeric code, or `None` for an alphabetic one.
    pub fn as_numeric(&self) -> Option<u16> {
        match &self.0 {
            Code::Alphabetic(_) => None,
            // in range by construction
            Code::Numeric(code) => u16::try_from(code).ok(),
        }
    }
}

impl DecodeInner for Iso4217CurrencyCode {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let tag = Asn1Ref::parse(buff, context)?.tag();
        if tag == Asn1PrintableString::TAG {
            let (used, code) = Asn1PrintableString::decode_inner(buff, context)?;
            Ok((used, Self::from_alphabetic(code)?))
        } else if tag == Asn1Integer::TAG {
            let (used, code) = Asn1Integer::decode_inner(buff, context)?;
            Ok((used, Self::from_numeric(&code)?))
        } else {
            Err(Asn1Error::UnexpectedTag)
        }
    }
}

impl Decode for Iso4217CurrencyCode {}

impl EncodeContent for Iso4217CurrencyCode {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match &self.0 {
            Code::Alphabetic(code) => code.content_len(rules),
            Code::Numeric(code) => code.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match &self.0 {
            Code::Alphabetic(code) => code.encode_content(rules, out),
            Code::Numeric(code) => code.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for Iso4217CurrencyCode {}

// Each alternative writes its own tag.
impl Encode for Iso4217CurrencyCode {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match &self.0 {
            Code::Alphabetic(code) => code.encoded_len(rules),
            Code::Numeric(code) => code.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match &self.0 {
            Code::Alphabetic(code) => code.encode(rules, out),
            Code::Numeric(code) => code.encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::Iso4217CurrencyCode;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn a_numeric_code_round_trips_as_an_integer() {
        let code = Iso4217CurrencyCode::numeric(978).unwrap();
        let wire = b"\x02\x02\x03\xd2";
        assert_eq!(code.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        let back = Iso4217CurrencyCode::decode_der(wire, &options()).unwrap().1;
        assert_eq!(back.as_numeric(), Some(978));
        assert_eq!(back.as_alphabetic(), None);
    }

    #[test]
    fn codes_outside_the_constraints_are_rejected_when_built() {
        for text in ["", "EU", "EURO"] {
            assert_eq!(
                Iso4217CurrencyCode::alphabetic(text),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert!(Iso4217CurrencyCode::alphabetic("E@R").is_err());
        assert_eq!(
            Iso4217CurrencyCode::numeric(0),
            Err(Asn1Error::MalformedValue)
        );
        assert!(Iso4217CurrencyCode::numeric(1).is_ok());
        assert!(Iso4217CurrencyCode::numeric(999).is_ok());
    }

    #[test]
    fn codes_outside_the_constraints_are_rejected_when_decoded() {
        for wire in [
            &b"\x13\x02EU"[..],
            b"\x02\x01\x00",
            b"\x02\x02\x03\xe8",
            b"\x02\x01\xff",
        ] {
            assert_eq!(
                Iso4217CurrencyCode::decode_der(wire, &options()),
                Err(Asn1Error::MalformedValue),
                "{wire:02x?}"
            );
        }
        assert_eq!(
            Iso4217CurrencyCode::decode_der(b"\x0c\x03EUR", &options()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
