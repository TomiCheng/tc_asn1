//! RFC 5280 certificatePolicies: a non-empty list with distinct policy OIDs.
//!
//! ```text
//! CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//! ```

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::ext::PolicyInformation;

/// Certificate policies in wire order. Duplicate policy identifiers are rejected.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::{CertificatePolicies, PolicyInformation, PolicyQualifierInfo};
///
/// let policy = PolicyInformation::new("1.2.3".parse::<Asn1Oid>()?)
///     .with_qualifiers(vec![PolicyQualifierInfo::cps("https://example.com/cps")?]);
/// let policies = CertificatePolicies::new(vec![policy])?;
/// let der = policies.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(CertificatePolicies::decode_der(&der, &DecodingOptions::default())?.1, policies);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificatePolicies {
    policies: Asn1SequenceOf<PolicyInformation>,
}

impl CertificatePolicies {
    /// Creates a non-empty list with unique policy OIDs.
    /// Empty lists or repeated OIDs return `MalformedValue`.
    pub fn new(policies: Vec<PolicyInformation>) -> Result<Self, Asn1Error> {
        if policies.is_empty()
            || policies.iter().enumerate().any(|(i, p)| {
                policies[..i]
                    .iter()
                    .any(|q| p.policy_identifier() == q.policy_identifier())
            })
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            policies: Asn1SequenceOf::new(policies),
        })
    }

    /// Returns the policies in wire order.
    pub fn policies(&self) -> &[PolicyInformation] {
        self.policies.elements()
    }
}

impl fmt::Display for CertificatePolicies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.policies().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{p}")?;
        }
        Ok(())
    }
}

impl DecodeContent for CertificatePolicies {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        Self::new(
            Asn1SequenceOf::<PolicyInformation>::decode_content(value, context)?.into_elements(),
        )
    }
}

impl DecodeInner for CertificatePolicies {
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

impl EncodeContent for CertificatePolicies {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.policies.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.policies.encode_content(rules, out)
    }
}

impl Decode for CertificatePolicies {}

impl Tagged for CertificatePolicies {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertificatePolicies {}

impl Encode for CertificatePolicies {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::CertificatePolicies;
    use crate::ext::{PolicyInformation, PolicyQualifierInfo};
    use alloc::vec;
    use tc_asn1::{Asn1Error, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    #[test]
    fn policies_preserve_order_and_reject_repeated_oids_even_with_different_qualifiers() {
        let a = PolicyInformation::new(PolicyInformation::ANY_POLICY);
        let b = PolicyInformation::new("1.2.3".parse::<Asn1Oid>().unwrap());
        let value = CertificatePolicies::new(vec![a.clone(), b.clone()]).unwrap();
        let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            CertificatePolicies::decode_der(&der, &DecodingOptions::default()).unwrap(),
            (der.len(), value.clone())
        );
        assert_eq!(value.policies(), &[a.clone(), b]);
        assert!(matches!(
            CertificatePolicies::new(vec![
                a.clone(),
                a.with_qualifiers(vec![PolicyQualifierInfo::cps("x").unwrap()])
            ]),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            CertificatePolicies::new(vec![]),
            Err(Asn1Error::MalformedValue)
        ));
        for wire in [
            &b"\x30\x00"[..],
            b"\x30\x10\x30\x06\x06\x04\x55\x1d\x20\x00\x30\x06\x06\x04\x55\x1d\x20\x00",
        ] {
            assert!(matches!(
                CertificatePolicies::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }
}
