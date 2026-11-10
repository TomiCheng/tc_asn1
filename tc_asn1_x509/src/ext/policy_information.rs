//! A certificate policy identifier and its optional qualifiers.
//!
//! ```text
//! PolicyInformation ::= SEQUENCE {
//!     policyIdentifier CertPolicyId,
//!     policyQualifiers SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
//! CertPolicyId ::= OBJECT IDENTIFIER
//! ```

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};

use crate::ext::PolicyQualifierInfo;

/// A policy OID with zero or more qualifiers. An empty qualifier list is omitted.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::{PolicyInformation, PolicyQualifierInfo};
///
/// let policy = PolicyInformation::new(PolicyInformation::ANY_POLICY)
///     .with_qualifiers(vec![PolicyQualifierInfo::cps("https://example.com/cps")?]);
/// assert_eq!(policy.policy_qualifiers().len(), 1);
/// let der = policy.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(PolicyInformation::decode_der(&der, &DecodingOptions::default())?.1, policy);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PolicyInformation {
    policy_identifier: Asn1Oid,
    policy_qualifiers: Asn1SequenceOf<PolicyQualifierInfo>,
}

impl PolicyInformation {
    /// The anyPolicy identifier, 2.5.29.32.0.
    pub const ANY_POLICY: NamedOid =
        NamedOid::new(&[0x55, 0x1d, 0x20, 0], "2.5.29.32.0", "anyPolicy");
    /// Creates a policy without qualifiers.
    pub fn new(oid: impl Into<Asn1Oid>) -> Self {
        Self {
            policy_identifier: oid.into(),
            policy_qualifiers: Asn1SequenceOf::new(Vec::new()),
        }
    }

    /// Replaces the qualifiers; an empty list omits the optional field.
    pub fn with_qualifiers(mut self, qualifiers: Vec<PolicyQualifierInfo>) -> Self {
        self.policy_qualifiers = Asn1SequenceOf::new(qualifiers);
        self
    }

    /// Returns the policy identifier.
    pub fn policy_identifier(&self) -> &Asn1Oid {
        &self.policy_identifier
    }

    /// Returns the qualifiers; empty means the field is absent.
    pub fn policy_qualifiers(&self) -> &[PolicyQualifierInfo] {
        self.policy_qualifiers.elements()
    }
}

impl fmt::Display for PolicyInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.policy_identifier)?;
        for qualifier in self.policy_qualifiers() {
            write!(f, ", {qualifier}")?;
        }
        Ok(())
    }
}

impl DecodeInner for PolicyInformation {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let oid = fields.get::<Asn1Oid>()?;
        let qualifiers = fields.get_opt::<Asn1SequenceOf<PolicyQualifierInfo>>()?;
        fields.end()?;
        let qualifiers = match qualifiers {
            Some(v) if v.elements().is_empty() => return Err(Asn1Error::MalformedValue),
            Some(v) => v.into_elements(),
            None => Vec::new(),
        };
        Ok((
            element.total_len(),
            Self::new(oid).with_qualifiers(qualifiers),
        ))
    }
}

impl EncodeContent for PolicyInformation {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.policy_identifier.encoded_len(rules)
            + if self.policy_qualifiers().is_empty() {
                0
            } else {
                self.policy_qualifiers.encoded_len(rules)
            }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.policy_identifier.encode(rules, out)?;
        if !self.policy_qualifiers().is_empty() {
            at += self.policy_qualifiers.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PolicyInformation {}

impl Tagged for PolicyInformation {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PolicyInformation {}

impl Encode for PolicyInformation {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyInformation;
    use crate::ext::PolicyQualifierInfo;
    use alloc::vec;
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    #[test]
    fn missing_identifier_is_rejected() {
        let wire = &b"\x30\x00"[..];
        assert!(matches!(
            PolicyInformation::decode(wire, &DecodingOptions::default()),
            Err(tc_asn1::Asn1Error::Truncated)
        ));
    }

    #[test]
    fn extra_or_mistagged_optional_fields_are_rejected() {
        let wire = &b"\x30\x08\x06\x04\x55\x1d\x20\x00\x05\x00"[..];
        assert!(matches!(
            PolicyInformation::decode(wire, &DecodingOptions::default()),
            Err(tc_asn1::Asn1Error::TrailingData)
        ));
    }

    #[test]
    fn wrong_container_or_identifier_tags_are_rejected() {
        for wire in [&b"\x31\x00"[..], &b"\x30\x02\x05\x00"[..]] {
            assert!(matches!(
                PolicyInformation::decode(wire, &DecodingOptions::default()),
                Err(tc_asn1::Asn1Error::UnexpectedTag)
            ));
        }
    }

    #[test]
    fn absent_qualifiers_are_omitted_and_present_qualifiers_round_trip() {
        let bare = PolicyInformation::new(PolicyInformation::ANY_POLICY);
        assert_eq!(
            bare.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x30\x06\x06\x04\x55\x1d\x20\x00"
        );
        for value in [
            bare.clone(),
            bare.with_qualifiers(vec![PolicyQualifierInfo::cps("x").unwrap()]),
        ] {
            let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                PolicyInformation::decode_der(&der, &DecodingOptions::default()).unwrap(),
                (der.len(), value)
            );
        }
        assert!(matches!(
            PolicyInformation::decode(
                b"\x30\x08\x06\x04\x55\x1d\x20\x00\x30\x00",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
