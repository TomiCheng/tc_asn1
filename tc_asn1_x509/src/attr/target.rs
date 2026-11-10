//! RFC 5755 §4.3.2 target of an attribute certificate.
//!
//! ```text
//! Target ::= CHOICE {
//!     targetName  [0] GeneralName,
//!     targetGroup [1] GeneralName,
//!     targetCert  [2] TargetCert }
//! ```
//!
//! GeneralName is a CHOICE, so both tags are EXPLICIT. RFC 5755 says the
//! targetCert alternative MUST NOT be used; as in Bouncy Castle it is not
//! supported, and `[2]` is `UnexpectedTag`.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

use crate::name::GeneralName;

const TARGET_NAME: &[u8] = &[0xa0];
const TARGET_GROUP: &[u8] = &[0xa1];

/// A server or service, or a group of them, that an attribute certificate targets.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::{attr::Target, name::GeneralName};
///
/// let target = Target::Name(GeneralName::dns_name("www.example.com")?);
/// assert_eq!(target.encode_to_vec(&EncodingOptions::DER)?[0], 0xa0);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Target {
    /// `targetName`, encoded with an EXPLICIT `[0]` tag.
    Name(GeneralName),
    /// `targetGroup`, encoded with an EXPLICIT `[1]` tag.
    Group(GeneralName),
}

impl Target {
    /// Returns the name of either alternative.
    pub fn general_name(&self) -> &GeneralName {
        match self {
            Self::Name(name) | Self::Group(name) => name,
        }
    }

    fn tag(&self) -> &'static [u8] {
        match self {
            Self::Name(_) => TARGET_NAME,
            Self::Group(_) => TARGET_GROUP,
        }
    }
}

impl DecodeInner for Target {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let wrap: fn(GeneralName) -> Self = match element.tag() {
            [0xa0] => Self::Name,
            [0xa1] => Self::Group,
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        // the EXPLICIT tag holds exactly one GeneralName
        let mut inner = Children::from_contents(element.value(), context)?;
        let name = inner.get::<GeneralName>()?;
        inner.end()?;
        Ok((element.total_len(), wrap(name)))
    }
}

impl Decode for Target {}

impl EncodeContent for Target {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.general_name().encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.general_name().encode(rules, out)
    }
}

impl EncodeTagged for Target {}

impl Encode for Target {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag(), rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag(), rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::Target;
    use crate::name::GeneralName;

    #[test]
    fn name_and_group_wrap_the_general_name_in_explicit_a0_and_a1() {
        let name = GeneralName::dns_name("a").unwrap();
        for (target, wire) in [
            (Target::Name(name.clone()), &b"\xa0\x03\x82\x01a"[..]),
            (Target::Group(name.clone()), &b"\xa1\x03\x82\x01a"[..]),
        ] {
            assert_eq!(target.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(target.general_name(), &name);
            let (used, back) = Target::decode_der(wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(back, target);
        }
    }

    #[test]
    fn target_cert_and_other_tags_are_rejected() {
        let options = DecodingOptions::default();
        assert!(matches!(
            Target::decode_der(b"\xa2\x03\x82\x01a", &options),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            Target::decode_der(b"\x82\x01a", &options),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn an_explicit_tag_must_hold_exactly_one_name() {
        let options = DecodingOptions::default();
        assert!(Target::decode_der(b"\xa0\x00", &options).is_err());
        assert!(Target::decode_der(b"\xa0\x06\x82\x01a\x82\x01b", &options).is_err());
    }
}
