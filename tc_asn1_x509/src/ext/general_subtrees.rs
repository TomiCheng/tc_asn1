//! RFC 5280 §4.2.1.10 `GeneralSubtrees`.
//!
//! ```text
//! GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
//! ```
//!
//! The permitted or the excluded name spaces of a name constraint, never
//! empty. Inside `NameConstraints` the list sits under an IMPLICIT context
//! tag, so it decodes from its contents alone.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::ext::GeneralSubtree;

/// A non-empty list of name spaces.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{ext::{GeneralSubtree, GeneralSubtrees}, name::GeneralName};
///
/// let subtrees = GeneralSubtrees::new(vec![
///     GeneralSubtree::new(GeneralName::dns_name("example.com")?)?,
///     GeneralSubtree::new(GeneralName::rfc822_name("example.com")?)?,
/// ])?;
/// assert_eq!(subtrees.to_string(), "DNS:example.com, email:example.com");
///
/// let der = subtrees.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = GeneralSubtrees::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.subtrees().len(), 2);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GeneralSubtrees {
    subtrees: Asn1SequenceOf<GeneralSubtree>,
}

impl GeneralSubtrees {
    /// An empty list violates `SIZE (1..MAX)` and is `MalformedValue`.
    pub fn new(subtrees: Vec<GeneralSubtree>) -> Result<Self, Asn1Error> {
        if subtrees.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            subtrees: Asn1SequenceOf::new(subtrees),
        })
    }

    /// The subtrees in wire order, never empty.
    pub fn subtrees(&self) -> &[GeneralSubtree] {
        self.subtrees.elements()
    }
}

/// The subtrees joined with `, `, each as [`GeneralSubtree`] prints it.
impl fmt::Display for GeneralSubtrees {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, subtree) in self.subtrees().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{subtree}")?;
        }
        Ok(())
    }
}

impl DecodeContent for GeneralSubtrees {
    /// The subtrees back to back; none is `MalformedValue`.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let subtrees = Asn1SequenceOf::<GeneralSubtree>::decode_content(value, context)?;
        Self::new(subtrees.into_elements())
    }
}

impl DecodeInner for GeneralSubtrees {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for GeneralSubtrees {}

impl Tagged for GeneralSubtrees {
    const TAG: &'static [u8] = Asn1SequenceOf::<GeneralSubtree>::TAG;
}

impl EncodeContent for GeneralSubtrees {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.subtrees.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.subtrees.encode_content(rules, out)
    }
}

impl EncodeTagged for GeneralSubtrees {}

impl Encode for GeneralSubtrees {
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

    use super::GeneralSubtrees;
    use crate::{ext::GeneralSubtree, name::GeneralName};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn subtrees_round_trip_in_order_and_print_joined() {
        let subtrees = GeneralSubtrees::new(Vec::from([
            GeneralSubtree::new(GeneralName::dns_name("x.tw").unwrap()).unwrap(),
            GeneralSubtree::new(GeneralName::ip_address(&[10, 0, 0, 0, 255, 0, 0, 0])).unwrap(),
        ]))
        .unwrap();
        let der = subtrees.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            der,
            b"\x30\x14\x30\x06\x82\x04x.tw\x30\x0a\x87\x08\x0a\x00\x00\x00\xff\x00\x00\x00"
        );
        let (used, back) = GeneralSubtrees::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &subtrees));
        assert_eq!(back.to_string(), "DNS:x.tw, IP:10.0.0.0/255.0.0.0");
        assert_eq!(
            GeneralSubtrees::decode_der(&der, &options()).unwrap().1,
            subtrees
        );
    }

    #[test]
    fn an_empty_list_is_rejected_when_built_or_decoded() {
        assert!(matches!(
            GeneralSubtrees::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            GeneralSubtrees::decode(b"\x30\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_bare_name_among_the_subtrees_is_unexpected() {
        assert!(matches!(
            GeneralSubtrees::decode(b"\x30\x06\x82\x04x.tw", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
