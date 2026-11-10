//! RFC 5755 §4.2.6 attribute certificate validity period.
//!
//! ```text
//! AttCertValidityPeriod ::= SEQUENCE {
//!     notBeforeTime GeneralizedTime,
//!     notAfterTime  GeneralizedTime }
//! ```
//!
//! Both bounds use UTC GeneralizedTime with seconds, including years before 2050.
//! Whether the current time falls in the period is checked by the validator.

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// Inclusive validity bounds; the end cannot precede the start.
///
/// ```
/// use tc_asn1::Asn1GeneralizedTime;
/// use tc_asn1_x509::attr::AttCertValidityPeriod;
///
/// let start = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0)?;
/// let end = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0)?;
/// let period = AttCertValidityPeriod::new(start, end)?;
/// assert_eq!(period.not_before_time(), &start);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AttCertValidityPeriod {
    not_before_time: Asn1GeneralizedTime,
    not_after_time: Asn1GeneralizedTime,
}

impl AttCertValidityPeriod {
    /// Creates inclusive bounds; reversed times return `MalformedValue`.
    pub fn new(
        not_before_time: Asn1GeneralizedTime,
        not_after_time: Asn1GeneralizedTime,
    ) -> Result<Self, Asn1Error> {
        if not_before_time > not_after_time {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            not_before_time,
            not_after_time,
        })
    }

    /// Returns the inclusive start.
    pub fn not_before_time(&self) -> &Asn1GeneralizedTime {
        &self.not_before_time
    }

    /// Returns the inclusive end.
    pub fn not_after_time(&self) -> &Asn1GeneralizedTime {
        &self.not_after_time
    }
}

impl DecodeInner for AttCertValidityPeriod {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let start = fields.get()?;
        let end = fields.get()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(start, end)?))
    }
}

impl EncodeContent for AttCertValidityPeriod {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.not_before_time.encoded_len(rules) + self.not_after_time.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.not_before_time.encode(rules, out)?;
        Ok(at + self.not_after_time.encode(rules, &mut out[at..])?)
    }
}

impl Decode for AttCertValidityPeriod {}

impl Tagged for AttCertValidityPeriod {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AttCertValidityPeriod {}

impl Encode for AttCertValidityPeriod {
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

    use super::AttCertValidityPeriod;

    #[test]
    fn dates_before_2050_still_use_generalized_time_for_attribute_certificates() {
        let value = AttCertValidityPeriod::new(
            Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap(),
            Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let wire = b"\x30\x22\x18\x0f20260101000000Z\x18\x0f20270101000000Z";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            AttCertValidityPeriod::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn equal_validity_bounds_are_allowed_but_reversed_bounds_are_rejected() {
        let a = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let b = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0).unwrap();
        assert!(AttCertValidityPeriod::new(a, a).is_ok());
        assert_eq!(
            AttCertValidityPeriod::new(b, a),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            AttCertValidityPeriod::decode_der(
                b"\x30\x22\x18\x0f20270101000000Z\x18\x0f20260101000000Z",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue),
        );
    }

    #[test]
    fn missing_bounds_utc_time_and_trailing_fields_are_rejected() {
        for (wire, error) in [
            (
                &b"\x30\x11\x18\x0f20260101000000Z"[..],
                Asn1Error::Truncated,
            ),
            (
                &b"\x30\x0f\x17\x0d260101000000Z"[..],
                Asn1Error::UnexpectedTag,
            ),
            (
                &b"\x30\x24\x18\x0f20260101000000Z\x18\x0f20270101000000Z\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                AttCertValidityPeriod::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
