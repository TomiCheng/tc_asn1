//! RFC 5280 §4.2.1.11 policy processing constraints.
//!
//! ```text
//! PolicyConstraints ::= SEQUENCE {
//!     requireExplicitPolicy [0] SkipCerts OPTIONAL,
//!     inhibitPolicyMapping  [1] SkipCerts OPTIONAL }
//! SkipCerts ::= INTEGER (0..MAX)
//! ```
//!
//! Both fields are IMPLICIT. At least one must be present.
//! Criticality and path processing are left to the validator.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};

/// Non-negative policy skip counts; either or both may be specified.
///
/// # Examples
///
/// ```
/// use tc_asn1_x509::ext::PolicyConstraints;
///
/// let constraints = PolicyConstraints::new(Some(0.into()), None)?;
/// assert!(constraints.require_explicit_policy().is_some());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PolicyConstraints {
    require_explicit_policy: Option<Asn1Integer>,
    inhibit_policy_mapping: Option<Asn1Integer>,
}

impl PolicyConstraints {
    /// Rejects two absent fields or a negative count with `MalformedValue`.
    pub fn new(
        require_explicit_policy: Option<Asn1Integer>,
        inhibit_policy_mapping: Option<Asn1Integer>,
    ) -> Result<Self, Asn1Error> {
        if (require_explicit_policy.is_none() && inhibit_policy_mapping.is_none())
            || require_explicit_policy
                .as_ref()
                .is_some_and(Asn1Integer::is_negative)
            || inhibit_policy_mapping
                .as_ref()
                .is_some_and(Asn1Integer::is_negative)
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            require_explicit_policy,
            inhibit_policy_mapping,
        })
    }

    /// Returns the count before an explicit policy is required.
    pub fn require_explicit_policy(&self) -> Option<&Asn1Integer> {
        self.require_explicit_policy.as_ref()
    }

    /// Returns the count before policy mapping is inhibited.
    pub fn inhibit_policy_mapping(&self) -> Option<&Asn1Integer> {
        self.inhibit_policy_mapping.as_ref()
    }
}

impl fmt::Display for PolicyConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = &self.require_explicit_policy {
            write!(f, "requireExplicitPolicy: {n}")?;
        }
        if let Some(n) = &self.inhibit_policy_mapping {
            if self.require_explicit_policy.is_some() {
                f.write_str(", ")?;
            }
            write!(f, "inhibitPolicyMapping: {n}")?;
        }
        Ok(())
    }
}

impl DecodeInner for PolicyConstraints {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let explicit = fields.get_implicit_opt::<Asn1Integer>([0x80])?;
        let mapping = fields.get_implicit_opt::<Asn1Integer>([0x81])?;
        fields.end()?;
        Ok((element.total_len(), Self::new(explicit, mapping)?))
    }
}

impl EncodeContent for PolicyConstraints {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.require_explicit_policy
            .as_ref()
            .map_or(0, |v| Implicit::new(&[0x80], v).encoded_len(rules))
            + self
                .inhibit_policy_mapping
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x81], v).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.require_explicit_policy {
            at += Implicit::new(&[0x80], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.inhibit_policy_mapping {
            at += Implicit::new(&[0x81], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PolicyConstraints {}

impl Tagged for PolicyConstraints {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PolicyConstraints {}

impl Encode for PolicyConstraints {
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

    use super::PolicyConstraints;

    #[test]
    fn either_or_both_implicit_skip_counts_round_trip() {
        for wire in [
            &b"\x30\x03\x80\x01\x00"[..],
            &b"\x30\x03\x81\x01\x01"[..],
            &b"\x30\x06\x80\x01\x00\x81\x01\x02"[..],
        ] {
            let (used, value) =
                PolicyConstraints::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                PolicyConstraints::decode(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn empty_negative_repeated_and_out_of_order_constraints_are_rejected() {
        assert!(matches!(
            PolicyConstraints::decode(b"\x30\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyConstraints::decode(b"\x30\x03\x80\x01\xff", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyConstraints::decode(
                b"\x30\x06\x81\x01\x00\x80\x01\x01",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::TrailingData)
        ));
        assert!(matches!(
            PolicyConstraints::decode(
                b"\x30\x06\x80\x01\x00\x80\x01\x01",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::TrailingData)
        ));
        assert!(matches!(
            PolicyConstraints::decode(b"\x31\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn constraints_require_at_least_one_non_negative_skip_count() {
        assert!(matches!(
            PolicyConstraints::new(None, None),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyConstraints::new(None, Some((-1).into())),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
