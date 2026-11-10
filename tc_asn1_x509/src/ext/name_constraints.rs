//! RFC 5280 §4.2.1.10 `NameConstraints`, the value of extension 2.5.29.30.
//!
//! ```text
//! NameConstraints ::= SEQUENCE {
//!     permittedSubtrees  [0] GeneralSubtrees OPTIONAL,
//!     excludedSubtrees   [1] GeneralSubtrees OPTIONAL }
//! ```
//!
//! Both fields are IMPLICIT and at least one must be present. This type
//! represents the extension value only. Applying the permitted and excluded
//! name spaces while validating a certification path belongs to the
//! validator.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Implicit, Tagged, tag,
};

use crate::ext::GeneralSubtrees;

const PERMITTED_SUBTREES: &[u8] = &[0xA0];
const EXCLUDED_SUBTREES: &[u8] = &[0xA1];

/// The permitted and excluded name spaces for subsequent certificates in a
/// certification path.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{ext::{GeneralSubtree, GeneralSubtrees, NameConstraints}, name::GeneralName};
///
/// let permitted = GeneralSubtrees::new(vec![
///     GeneralSubtree::new(GeneralName::dns_name("example.com")?)?,
/// ])?;
/// let constraints = NameConstraints::permitted(permitted);
/// assert_eq!(constraints.to_string(), "permitted: DNS:example.com");
///
/// let der = constraints.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = NameConstraints::decode(&der, &DecodingOptions::default())?;
/// assert!(back.permitted_subtrees().is_some());
/// assert!(back.excluded_subtrees().is_none());
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NameConstraints {
    permitted_subtrees: Option<GeneralSubtrees>,
    excluded_subtrees: Option<GeneralSubtrees>,
}

impl NameConstraints {
    /// Creates constraints from either or both non-empty subtree lists.
    /// Supplying neither is `MalformedValue`.
    pub fn new(
        permitted_subtrees: Option<GeneralSubtrees>,
        excluded_subtrees: Option<GeneralSubtrees>,
    ) -> Result<Self, Asn1Error> {
        if permitted_subtrees.is_none() && excluded_subtrees.is_none() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            permitted_subtrees,
            excluded_subtrees,
        })
    }

    /// Constraints containing only permitted name spaces.
    pub fn permitted(subtrees: GeneralSubtrees) -> Self {
        Self {
            permitted_subtrees: Some(subtrees),
            excluded_subtrees: None,
        }
    }

    /// Constraints containing only excluded name spaces.
    pub fn excluded(subtrees: GeneralSubtrees) -> Self {
        Self {
            permitted_subtrees: None,
            excluded_subtrees: Some(subtrees),
        }
    }

    /// The subtrees the names must fall within.
    pub fn permitted_subtrees(&self) -> Option<&GeneralSubtrees> {
        self.permitted_subtrees.as_ref()
    }

    /// The subtrees the names must stay out of.
    pub fn excluded_subtrees(&self) -> Option<&GeneralSubtrees> {
        self.excluded_subtrees.as_ref()
    }
}

/// The permitted list followed by the excluded list, when present.
impl fmt::Display for NameConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(permitted) = &self.permitted_subtrees {
            write!(f, "permitted: {permitted}")?;
        }
        if let Some(excluded) = &self.excluded_subtrees {
            if self.permitted_subtrees.is_some() {
                f.write_str(", ")?;
            }
            write!(f, "excluded: {excluded}")?;
        }
        Ok(())
    }
}

impl DecodeInner for NameConstraints {
    /// Both optional fields are read in schema order. An empty outer
    /// SEQUENCE or an empty subtree list is `MalformedValue`. Variable time:
    /// branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let permitted_subtrees = fields.get_implicit_opt::<GeneralSubtrees>(PERMITTED_SUBTREES)?;
        let excluded_subtrees = fields.get_implicit_opt::<GeneralSubtrees>(EXCLUDED_SUBTREES)?;
        fields.end()?;
        Ok((
            element.total_len(),
            Self::new(permitted_subtrees, excluded_subtrees)?,
        ))
    }
}

impl Decode for NameConstraints {}

impl Tagged for NameConstraints {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for NameConstraints {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.permitted_subtrees.as_ref().map_or(0, |subtrees| {
            Implicit::new(PERMITTED_SUBTREES, subtrees).encoded_len(rules)
        }) + self.excluded_subtrees.as_ref().map_or(0, |subtrees| {
            Implicit::new(EXCLUDED_SUBTREES, subtrees).encoded_len(rules)
        })
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(subtrees) = &self.permitted_subtrees {
            at += Implicit::new(PERMITTED_SUBTREES, subtrees).encode(rules, out)?;
        }
        if let Some(subtrees) = &self.excluded_subtrees {
            at += Implicit::new(EXCLUDED_SUBTREES, subtrees).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for NameConstraints {}

impl Encode for NameConstraints {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::NameConstraints;
    use crate::{
        ext::{GeneralSubtree, GeneralSubtrees},
        name::GeneralName,
    };

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn dns(name: &str) -> GeneralSubtrees {
        GeneralSubtrees::new(Vec::from([GeneralSubtree::new(
            GeneralName::dns_name(name).unwrap(),
        )
        .unwrap()]))
        .unwrap()
    }

    #[test]
    fn permitted_and_excluded_subtrees_are_implicitly_tagged_and_round_trip() {
        let constraints = NameConstraints::new(Some(dns("x.tw")), Some(dns("bad.x.tw"))).unwrap();
        let der = constraints.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            der,
            b"\x30\x18\xa0\x08\x30\x06\x82\x04x.tw\xa1\x0c\x30\x0a\x82\x08bad.x.tw"
        );
        let (used, back) = NameConstraints::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &constraints));
        assert_eq!(
            NameConstraints::decode_der(&der, &options()).unwrap().1,
            constraints
        );
        assert_eq!(
            back.to_string(),
            "permitted: DNS:x.tw, excluded: DNS:bad.x.tw"
        );
    }

    #[test]
    fn either_kind_of_subtree_can_appear_alone() {
        let permitted = NameConstraints::permitted(dns("x.tw"));
        assert_eq!(
            permitted.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x30\x0a\xa0\x08\x30\x06\x82\x04x.tw"
        );
        assert!(permitted.permitted_subtrees().is_some());
        assert!(permitted.excluded_subtrees().is_none());

        let excluded = NameConstraints::excluded(dns("x.tw"));
        assert_eq!(
            excluded.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x30\x0a\xa1\x08\x30\x06\x82\x04x.tw"
        );
        assert!(excluded.permitted_subtrees().is_none());
        assert!(excluded.excluded_subtrees().is_some());
        assert_eq!(excluded.to_string(), "excluded: DNS:x.tw");
    }

    #[test]
    fn an_empty_constraint_or_subtree_list_is_rejected() {
        assert!(matches!(
            NameConstraints::new(None, None),
            Err(Asn1Error::MalformedValue)
        ));
        for wire in [
            &b"\x30\x00"[..],
            &b"\x30\x02\xa0\x00"[..],
            &b"\x30\x02\xa1\x00"[..],
        ] {
            assert!(matches!(
                NameConstraints::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn fields_out_of_order_repeated_or_explicitly_tagged_are_rejected() {
        for wire in [
            &b"\x30\x14\xa1\x08\x30\x06\x82\x04x.tw\xa0\x08\x30\x06\x82\x04x.tw"[..],
            &b"\x30\x14\xa0\x08\x30\x06\x82\x04x.tw\xa0\x08\x30\x06\x82\x04x.tw"[..],
            &b"\x30\x0c\xa0\x0a\x30\x08\x30\x06\x82\x04x.tw"[..],
        ] {
            assert!(
                NameConstraints::decode(wire, &options()).is_err(),
                "{wire:02X?}"
            );
        }
    }

    #[test]
    fn a_non_sequence_outer_tag_and_trailing_field_are_rejected() {
        assert!(matches!(
            NameConstraints::decode(b"\x31\x0a\xa0\x08\x30\x06\x82\x04x.tw", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            NameConstraints::decode(b"\x30\x0c\xa0\x08\x30\x06\x82\x04x.tw\x05\x00", &options()),
            Err(Asn1Error::TrailingData)
        ));
    }
}
