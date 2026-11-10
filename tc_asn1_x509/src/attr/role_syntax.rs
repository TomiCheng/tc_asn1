//! RFC 5755 §4.4.5 role attribute of an attribute certificate.
//!
//! ```text
//! RoleSyntax ::= SEQUENCE {
//!     roleAuthority [0] GeneralNames OPTIONAL,
//!     roleName      [1] GeneralName }
//! ```
//!
//! `roleAuthority` is IMPLICIT. `roleName` is a CHOICE, so its tag is EXPLICIT.
//! What a role grants belongs to the application.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Implicit, Tagged, tag,
};

use crate::name::{GeneralName, GeneralNames};

const ROLE_AUTHORITY: &[u8] = &[0xa0];
const ROLE_NAME: &[u8] = &[0xa1];

/// A role name, optionally with the authorities that issue it.
///
/// ```
/// use tc_asn1_x509::{attr::RoleSyntax, name::GeneralName};
///
/// let role = RoleSyntax::new(None, GeneralName::uri("urn:role:admin")?);
/// assert!(role.role_authority().is_none());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RoleSyntax {
    role_authority: Option<GeneralNames>,
    role_name: GeneralName,
}

impl RoleSyntax {
    /// Creates a role; the name forms are not checked against the RFC 5755 profile.
    pub fn new(role_authority: Option<GeneralNames>, role_name: GeneralName) -> Self {
        Self {
            role_authority,
            role_name,
        }
    }

    /// Returns `roleAuthority`, if supplied.
    pub fn role_authority(&self) -> Option<&GeneralNames> {
        self.role_authority.as_ref()
    }

    /// Returns `roleName`.
    pub fn role_name(&self) -> &GeneralName {
        &self.role_name
    }
}

impl DecodeContent for RoleSyntax {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let role_authority = fields.get_implicit_opt::<GeneralNames>(ROLE_AUTHORITY)?;
        let role_name = fields.get_explicit::<GeneralName>(ROLE_NAME)?;
        fields.end()?;
        Ok(Self::new(role_authority, role_name))
    }
}

impl DecodeInner for RoleSyntax {
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

impl EncodeContent for RoleSyntax {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.role_authority.as_ref().map_or(0, |value| {
            Implicit::new(ROLE_AUTHORITY, value).encoded_len(rules)
        }) + Explicit::new(ROLE_NAME, &self.role_name).encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(value) = &self.role_authority {
            at += Implicit::new(ROLE_AUTHORITY, value).encode(rules, &mut out[at..])?;
        }
        at += Explicit::new(ROLE_NAME, &self.role_name).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for RoleSyntax {}

impl Tagged for RoleSyntax {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RoleSyntax {}

impl Encode for RoleSyntax {
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

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::RoleSyntax;
    use crate::name::{GeneralName, GeneralNames};

    #[test]
    fn a_role_without_authority_wraps_the_name_in_an_explicit_a1() {
        // [1] { [6] "a" }: the uniformResourceIdentifier keeps its own tag inside
        let role = RoleSyntax::new(None, GeneralName::uri("a").unwrap());
        let wire = b"\x30\x05\xa1\x03\x86\x01a";
        assert_eq!(role.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            RoleSyntax::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            role
        );
    }

    #[test]
    fn the_authority_uses_an_implicit_a0_before_the_name() {
        let authority = GeneralNames::new(vec![GeneralName::dns_name("b").unwrap()]).unwrap();
        let role = RoleSyntax::new(Some(authority.clone()), GeneralName::uri("a").unwrap());
        // [0] replaces the SEQUENCE tag of GeneralNames: a0 03 82 01 'b'
        let wire = b"\x30\x0a\xa0\x03\x82\x01b\xa1\x03\x86\x01a";
        assert_eq!(role.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        let back = RoleSyntax::decode_der(wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back.role_authority(), Some(&authority));
    }

    #[test]
    fn a_missing_role_name_is_rejected() {
        assert!(RoleSyntax::decode_der(b"\x30\x00", &DecodingOptions::default()).is_err());
        assert!(matches!(
            RoleSyntax::decode_der(b"\x31\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
