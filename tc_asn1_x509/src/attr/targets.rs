//! RFC 5755 §4.3.2 targets, and the targetInformation extension value.
//!
//! ```text
//! Targets ::= SEQUENCE OF Target
//! -- the value of id-ce-targetInformation
//! TargetInformation ::= SEQUENCE OF Targets
//! ```
//!
//! Neither list has a size constraint, so empty lists are kept. Whether a
//! verifier is among the targets belongs to the validator.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::attr::Target;

/// The targets in one element of a targetInformation extension.
///
/// ```
/// use tc_asn1_x509::{attr::{Target, Targets}, name::GeneralName};
///
/// let targets = Targets::new(vec![Target::Name(GeneralName::dns_name("a.example")?)]);
/// assert_eq!(targets.targets().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Targets {
    targets: Asn1SequenceOf<Target>,
}

impl Targets {
    /// Keeps the targets in the given order; an empty list is allowed.
    pub fn new(targets: Vec<Target>) -> Self {
        Self {
            targets: Asn1SequenceOf::new(targets),
        }
    }

    /// The targets in wire order.
    pub fn targets(&self) -> &[Target] {
        self.targets.elements()
    }
}

impl DecodeContent for Targets {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let targets = Asn1SequenceOf::<Target>::decode_content(value, context)?;
        Ok(Self::new(targets.into_elements()))
    }
}

impl DecodeInner for Targets {
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

impl Decode for Targets {}

impl Tagged for Targets {
    const TAG: &'static [u8] = Asn1SequenceOf::<Target>::TAG;
}

impl EncodeContent for Targets {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.targets.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.targets.encode_content(rules, out)
    }
}

impl EncodeTagged for Targets {}

impl Encode for Targets {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

/// The value of the targetInformation extension: one or more [`Targets`] lists.
///
/// ```
/// use tc_asn1_x509::{attr::{Target, TargetInformation, Targets}, name::GeneralName};
///
/// let name = Target::Group(GeneralName::dns_name("servers.example")?);
/// let information = TargetInformation::new(vec![Targets::new(vec![name])]);
/// assert_eq!(information.targets()[0].targets().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TargetInformation {
    targets: Asn1SequenceOf<Targets>,
}

impl TargetInformation {
    /// Keeps the lists in the given order; an empty list is allowed.
    pub fn new(targets: Vec<Targets>) -> Self {
        Self {
            targets: Asn1SequenceOf::new(targets),
        }
    }

    /// The lists in wire order.
    pub fn targets(&self) -> &[Targets] {
        self.targets.elements()
    }
}

impl DecodeContent for TargetInformation {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let targets = Asn1SequenceOf::<Targets>::decode_content(value, context)?;
        Ok(Self::new(targets.into_elements()))
    }
}

impl DecodeInner for TargetInformation {
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

impl Decode for TargetInformation {}

impl Tagged for TargetInformation {
    const TAG: &'static [u8] = Asn1SequenceOf::<Targets>::TAG;
}

impl EncodeContent for TargetInformation {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.targets.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.targets.encode_content(rules, out)
    }
}

impl EncodeTagged for TargetInformation {}

impl Encode for TargetInformation {
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

    use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};

    use super::{TargetInformation, Targets};
    use crate::{attr::Target, name::GeneralName};

    #[test]
    fn nested_lists_round_trip_and_keep_their_order() {
        let a = Target::Name(GeneralName::dns_name("a").unwrap());
        let b = Target::Group(GeneralName::dns_name("b").unwrap());
        let information = TargetInformation::new(vec![
            Targets::new(vec![a.clone(), b.clone()]),
            Targets::new(vec![b]),
        ]);
        let wire = information.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            wire,
            b"\x30\x13\x30\x0a\xa0\x03\x82\x01a\xa1\x03\x82\x01b\x30\x05\xa1\x03\x82\x01b"
        );
        let back = TargetInformation::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back, information);
        assert_eq!(back.targets()[0].targets()[0], a);
    }

    #[test]
    fn empty_lists_are_kept_because_neither_has_a_size_constraint() {
        let options = DecodingOptions::default();
        let empty = TargetInformation::decode_der(b"\x30\x00", &options)
            .unwrap()
            .1;
        assert!(empty.targets().is_empty());
        let inner = TargetInformation::decode_der(b"\x30\x02\x30\x00", &options)
            .unwrap()
            .1;
        assert!(inner.targets()[0].targets().is_empty());
    }

    #[test]
    fn a_target_cert_inside_a_list_is_rejected() {
        assert!(
            Targets::decode_der(b"\x30\x05\xa2\x03\x82\x01a", &DecodingOptions::default()).is_err()
        );
    }
}
