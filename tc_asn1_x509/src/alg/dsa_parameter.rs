//! RFC 3279 §2.3.2 DSA domain parameters.
//!
//! ```text
//! Dss-Parms ::= SEQUENCE {
//!     p INTEGER,
//!     q INTEGER,
//!     g INTEGER }
//! ```
//!
//! The parameters of an `id-dsa` subjectPublicKeyInfo algorithm. Whether the
//! values form a valid DSA group belongs to the key validator.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The prime modulus `p`, the subgroup order `q` and the generator `g`.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::alg::DsaParameter;
///
/// let parameters = DsaParameter::new(23.into(), 11.into(), 4.into());
/// assert_eq!(
///     parameters.encode_to_vec(&EncodingOptions::DER)?,
///     b"\x30\x09\x02\x01\x17\x02\x01\x0b\x02\x01\x04"
/// );
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DsaParameter {
    p: Asn1Integer,
    q: Asn1Integer,
    g: Asn1Integer,
}

impl DsaParameter {
    /// Stores the three integers as given; their arithmetic is not checked.
    pub fn new(p: Asn1Integer, q: Asn1Integer, g: Asn1Integer) -> Self {
        Self { p, q, g }
    }

    /// Returns the prime modulus `p`.
    pub fn p(&self) -> &Asn1Integer {
        &self.p
    }

    /// Returns the subgroup order `q`.
    pub fn q(&self) -> &Asn1Integer {
        &self.q
    }

    /// Returns the generator `g`.
    pub fn g(&self) -> &Asn1Integer {
        &self.g
    }
}

impl DecodeContent for DsaParameter {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let p = fields.get()?;
        let q = fields.get()?;
        let g = fields.get()?;
        fields.end()?;
        Ok(Self::new(p, q, g))
    }
}

impl DecodeInner for DsaParameter {
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

impl EncodeContent for DsaParameter {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.p.encoded_len(rules) + self.q.encoded_len(rules) + self.g.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.p.encode(rules, out)?;
        at += self.q.encode(rules, &mut out[at..])?;
        at += self.g.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for DsaParameter {}

impl Tagged for DsaParameter {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for DsaParameter {}

impl Encode for DsaParameter {
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

    use super::DsaParameter;

    #[test]
    fn the_three_integers_round_trip_in_order() {
        let wire = b"\x30\x0a\x02\x02\x00\x80\x02\x01\x0b\x02\x01\x04";
        let (used, value) = DsaParameter::decode_der(wire, &DecodingOptions::default()).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(value.p(), &128.into());
        assert_eq!(value.q(), &11.into());
        assert_eq!(value.g(), &4.into());
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
    }

    #[test]
    fn missing_or_extra_integers_are_rejected() {
        let options = DecodingOptions::default();
        assert!(DsaParameter::decode_der(b"\x30\x06\x02\x01\x17\x02\x01\x0b", &options).is_err());
        assert!(
            DsaParameter::decode_der(
                b"\x30\x0c\x02\x01\x17\x02\x01\x0b\x02\x01\x04\x02\x01\x01",
                &options
            )
            .is_err()
        );
        assert!(matches!(
            DsaParameter::decode_der(b"\x31\x00", &options),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
