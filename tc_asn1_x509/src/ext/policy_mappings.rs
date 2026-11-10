//! RFC 5280 §4.2.1.5 mappings between issuer and subject policy domains.
//!
//! ```text
//! PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
//!     issuerDomainPolicy  CertPolicyId,
//!     subjectDomainPolicy CertPolicyId }
//! CertPolicyId ::= OBJECT IDENTIFIER
//! ```
//!
//! Neither side may be anyPolicy. Repeated issuer OIDs are allowed so that one
//! issuer policy can map to several subject policies.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::ext::PolicyInformation;

/// One mapping between two policy domains.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PolicyMapping {
    issuer_domain_policy: Asn1Oid,
    subject_domain_policy: Asn1Oid,
}

impl PolicyMapping {
    /// Creates a mapping. Either OID being anyPolicy returns `MalformedValue`.
    pub fn new(issuer: impl Into<Asn1Oid>, subject: impl Into<Asn1Oid>) -> Result<Self, Asn1Error> {
        let issuer_domain_policy = issuer.into();
        let subject_domain_policy = subject.into();
        if PolicyInformation::ANY_POLICY == issuer_domain_policy
            || PolicyInformation::ANY_POLICY == subject_domain_policy
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            issuer_domain_policy,
            subject_domain_policy,
        })
    }

    /// Returns the issuer-domain policy OID.
    pub fn issuer_domain_policy(&self) -> &Asn1Oid {
        &self.issuer_domain_policy
    }

    /// Returns the subject-domain policy OID.
    pub fn subject_domain_policy(&self) -> &Asn1Oid {
        &self.subject_domain_policy
    }
}

impl fmt::Display for PolicyMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {}",
            self.issuer_domain_policy, self.subject_domain_policy
        )
    }
}

impl DecodeInner for PolicyMapping {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let issuer = fields.get::<Asn1Oid>()?;
        let subject = fields.get::<Asn1Oid>()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(issuer, subject)?))
    }
}

impl EncodeContent for PolicyMapping {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.issuer_domain_policy.encoded_len(rules) + self.subject_domain_policy.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.issuer_domain_policy.encode(rules, out)?;
        Ok(at + self.subject_domain_policy.encode(rules, &mut out[at..])?)
    }
}

impl Decode for PolicyMapping {}

impl Tagged for PolicyMapping {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PolicyMapping {}

impl Encode for PolicyMapping {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

/// A non-empty list of policy mappings in wire order.
///
/// # Examples
///
/// ```
/// use tc_asn1::Asn1Oid;
/// use tc_asn1_x509::ext::{PolicyMapping, PolicyMappings};
///
/// let mapping = PolicyMapping::new("1.2.3".parse::<Asn1Oid>()?, "1.2.4".parse::<Asn1Oid>()?)?;
/// let mappings = PolicyMappings::new(vec![mapping])?;
/// assert_eq!(mappings.mappings().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PolicyMappings {
    mappings: Asn1SequenceOf<PolicyMapping>,
}

impl PolicyMappings {
    /// Creates a list. An empty list returns `MalformedValue`.
    pub fn new(mappings: Vec<PolicyMapping>) -> Result<Self, Asn1Error> {
        if mappings.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            mappings: Asn1SequenceOf::new(mappings),
        })
    }

    /// Returns mappings in wire order.
    pub fn mappings(&self) -> &[PolicyMapping] {
        self.mappings.elements()
    }
}

impl fmt::Display for PolicyMappings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, v) in self.mappings().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{v}")?;
        }
        Ok(())
    }
}

impl DecodeContent for PolicyMappings {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Self::new(Asn1SequenceOf::<PolicyMapping>::decode_content(value, context)?.into_elements())
    }
}

impl DecodeInner for PolicyMappings {
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

impl EncodeContent for PolicyMappings {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.mappings.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.mappings.encode_content(rules, out)
    }
}

impl Decode for PolicyMappings {}

impl Tagged for PolicyMappings {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PolicyMappings {}

impl Encode for PolicyMappings {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Asn1Error, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::PolicyMappings;

    #[test]
    fn one_issuer_can_map_to_multiple_subject_policies_in_wire_order() {
        for wire in [
            &b"\x30\x0a\x30\x08\x06\x02\x2a\x03\x06\x02\x2a\x04"[..],
            &b"\x30\x14\x30\x08\x06\x02\x2a\x03\x06\x02\x2a\x04\x30\x08\x06\x02\x2a\x03\x06\x02\x2a\x05"[..],
        ] {
            let (used, value) = PolicyMappings::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(PolicyMappings::decode(wire, &DecodingOptions::default()).unwrap().1, value);
        }
    }

    #[test]
    fn empty_mappings_any_policy_and_malformed_pairs_are_rejected() {
        assert!(matches!(
            PolicyMappings::decode(b"\x30\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyMappings::decode(
                b"\x30\x0c\x30\x0a\x06\x04\x55\x1d\x20\x00\x06\x02\x2a\x03",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyMappings::decode(
                b"\x30\x0c\x30\x0a\x06\x02\x2a\x03\x06\x04\x55\x1d\x20\x00",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyMappings::decode(
                b"\x30\x06\x30\x04\x06\x02\x2a\x03",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::Truncated)
        ));
        assert!(matches!(
            PolicyMappings::decode(
                b"\x30\x0c\x30\x0a\x06\x02\x2a\x03\x06\x02\x2a\x04\x05\x00",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::TrailingData)
        ));
    }

    #[test]
    fn any_policy_is_forbidden_in_either_domain_and_mappings_cannot_be_empty() {
        use crate::ext::{PolicyInformation, PolicyMapping};
        let oid = "1.2.3".parse::<Asn1Oid>().unwrap();
        assert!(matches!(
            PolicyMapping::new(PolicyInformation::ANY_POLICY, oid.clone()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyMapping::new(oid, PolicyInformation::ANY_POLICY),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            PolicyMappings::new(vec![]),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
