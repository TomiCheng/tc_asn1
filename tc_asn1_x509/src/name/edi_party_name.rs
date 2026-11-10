//! RFC 5280 §4.2.1.6 `EDIPartyName`, the `[5]` alternative of `GeneralName`.
//!
//! ```text
//! EDIPartyName ::= SEQUENCE {
//!     nameAssigner  [0] DirectoryString OPTIONAL,
//!     partyName     [1] DirectoryString }
//! ```
//!
//! A party in an electronic data interchange, named by the party that
//! assigned the name and the name itself. `DirectoryString` is a CHOICE, so
//! both tags are EXPLICIT despite the module's IMPLICIT TAGS: `A0 { string }`
//! and `A1 { string }`. Rare in practice; here for completeness of the
//! GeneralName CHOICE. Inside a GeneralName the SEQUENCE tag is replaced by
//! `A5`, on its own it is `30`.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x500::DirectoryString;

const NAME_ASSIGNER: &[u8] = &[0xA0];
const PARTY_NAME: &[u8] = &[0xA1];

/// A party name with an optional name assigner.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x500::DirectoryString;
/// use tc_asn1_x509::name::EdiPartyName;
///
/// let party = EdiPartyName::new(DirectoryString::new("Acme")?)
///     .with_name_assigner(DirectoryString::new("Registry")?);
/// assert_eq!(party.to_string(), "Registry/Acme");
///
/// let der = party.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = EdiPartyName::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.party_name().as_str(), Some("Acme"));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EdiPartyName {
    name_assigner: Option<DirectoryString>,
    party_name: DirectoryString,
}

impl EdiPartyName {
    /// A party name with no name assigner.
    pub fn new(party_name: DirectoryString) -> Self {
        Self {
            name_assigner: None,
            party_name,
        }
    }

    /// Adds the authority that assigned the party name.
    pub fn with_name_assigner(mut self, name_assigner: DirectoryString) -> Self {
        self.name_assigner = Some(name_assigner);
        self
    }

    /// The authority that assigned the party name, if any.
    pub fn name_assigner(&self) -> Option<&DirectoryString> {
        self.name_assigner.as_ref()
    }

    /// The party's name.
    pub fn party_name(&self) -> &DirectoryString {
        &self.party_name
    }
}

/// `assigner/party`, or the party name alone.
impl fmt::Display for EdiPartyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(assigner) = &self.name_assigner {
            write!(f, "{assigner}/")?;
        }
        write!(f, "{}", self.party_name)
    }
}

impl DecodeContent for EdiPartyName {
    /// The two fields, as under `30` on its own or `A5` inside a
    /// GeneralName.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let name_assigner = fields.get_explicit_opt(NAME_ASSIGNER)?;
        let party_name = fields.get_explicit(PARTY_NAME)?;
        fields.end()?;
        Ok(Self {
            name_assigner,
            party_name,
        })
    }
}

impl DecodeInner for EdiPartyName {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for EdiPartyName {}

impl Tagged for EdiPartyName {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for EdiPartyName {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.name_assigner.as_ref().map_or(0, |assigner| {
            Explicit::new(NAME_ASSIGNER, assigner).encoded_len(rules)
        }) + Explicit::new(PARTY_NAME, &self.party_name).encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(assigner) = &self.name_assigner {
            at += Explicit::new(NAME_ASSIGNER, assigner).encode(rules, out)?;
        }
        at += Explicit::new(PARTY_NAME, &self.party_name).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for EdiPartyName {}

impl Encode for EdiPartyName {
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

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x500::DirectoryString;

    use super::EdiPartyName;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_party_name_alone_is_one_explicit_field() {
        let party = EdiPartyName::new(DirectoryString::new("Acme").unwrap());
        let der = party.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der, b"\x30\x08\xa1\x06\x13\x04Acme");
        let (used, back) = EdiPartyName::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &party));
        assert!(back.name_assigner().is_none());
        assert_eq!(back.party_name().as_str(), Some("Acme"));
        assert_eq!(back.to_string(), "Acme");
        assert_eq!(EdiPartyName::decode_der(&der, &options()).unwrap().1, party);
    }

    #[test]
    fn the_name_assigner_comes_first_and_may_use_another_string_type() {
        let party = EdiPartyName::new(DirectoryString::new("Acme").unwrap())
            .with_name_assigner(DirectoryString::new("caf\u{e9}").unwrap());
        let der = party.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            der,
            b"\x30\x11\xa0\x07\x0c\x05caf\xc3\xa9\xa1\x06\x13\x04Acme"
        );
        let (_, back) = EdiPartyName::decode(&der, &options()).unwrap();
        assert_eq!(back, party);
        assert_eq!(back.to_string(), "caf\u{e9}/Acme");
    }

    #[test]
    fn a_missing_party_name_or_a_bare_string_is_rejected() {
        for (wire, error) in [
            (&b"\x30\x00"[..], Asn1Error::Truncated),
            (b"\x30\x06\xa0\x04\x13\x02Ab", Asn1Error::Truncated), // assigner only
            (b"\x30\x04\x13\x02Ab", Asn1Error::UnexpectedTag),     // no wrapper
        ] {
            assert_eq!(
                EdiPartyName::decode(wire, &options()).unwrap_err(),
                error,
                "{wire:02X?}"
            );
        }
    }
}
