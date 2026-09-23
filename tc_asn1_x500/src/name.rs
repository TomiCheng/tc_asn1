//! X.501 `Name`, as profiled by RFC 5280 §4.1.2.4.
//!
//! ```text
//! Name ::= CHOICE {          -- only one possibility for now --
//!     rdnSequence  RDNSequence }
//!
//! RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//! ```
//!
//! A distinguished name: the path from the root of the directory to the
//! entry, so the order of the RDNs matters and is kept. The CHOICE has a
//! single alternative and no tag of its own, but being a CHOICE it must be
//! tagged EXPLICIT wherever it is tagged (X.680 §31.2.7), as in
//! `GeneralName`'s `directoryName [4]`.
//!
//! An empty sequence is a valid `Name`: RFC 5280 allows an empty subject
//! when the subjectAltName extension carries the identity. Whether a
//! particular field may be empty is a profile check, not this type's.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

use crate::RelativeDistinguishedName;

mod from_str;

/// A distinguished name as a sequence of RDNs, root first. Parses from and
/// prints as its RFC 4514 string form.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x500::{
///     AttributeType, AttributeTypeAndValue, DirectoryString, Name, RelativeDistinguishedName,
/// };
///
/// // The RFC 4514 text form is the easy way to build one ...
/// let name: Name = "CN=Alice,O=Example,C=TW".parse()?;
/// assert_eq!(name.rdns().len(), 3);   // root first: C, O, CN
///
/// // ... and the structured way when the values come from elsewhere.
/// let same = Name::new(vec![
///     RelativeDistinguishedName::single(AttributeTypeAndValue::new(
///         AttributeType::COUNTRY_NAME.oid(),
///         DirectoryString::new("TW")?,
///     )),
///     RelativeDistinguishedName::single(AttributeTypeAndValue::new(
///         AttributeType::ORGANIZATION_NAME.oid(),
///         DirectoryString::new("Example")?,
///     )),
///     RelativeDistinguishedName::single(AttributeTypeAndValue::new(
///         AttributeType::COMMON_NAME.oid(),
///         DirectoryString::new("Alice")?,
///     )),
/// ]);
/// assert_eq!(same, name);
///
/// // Encode it as DER and read it back.
/// let der = name.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, decoded) = Name::decode(&der, &DecodingOptions::default())?;
/// println!("{decoded}");   // CN=Alice,O=Example,C=TW
///
/// // `==` compares the DER; `equivalent` applies RFC 5280's relaxed matching.
/// let other: Name = "cn=ALICE, o=example, c=tw".parse()?;
/// assert_ne!(other, name);
/// assert!(other.equivalent(&name));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Name {
    rdns: Asn1SequenceOf<RelativeDistinguishedName>,
}

impl Name {
    /// The RDNs in order, root first. May be empty.
    pub fn new(rdns: Vec<RelativeDistinguishedName>) -> Self {
        Self {
            rdns: Asn1SequenceOf::new(rdns),
        }
    }

    /// The RDNs in order, root first.
    pub fn rdns(&self) -> &[RelativeDistinguishedName] {
        self.rdns.elements()
    }

    pub fn is_empty(&self) -> bool {
        self.rdns.elements().is_empty()
    }

    /// RFC 5280 §7.1 relaxed comparison: the same number of RDNs, each
    /// [`RelativeDistinguishedName::equivalent`] to the one at the same
    /// position. Use `==` for the strict, DER-level comparison that §7.1
    /// allows first. Variable time; for public values.
    pub fn equivalent(&self, other: &Self) -> bool {
        let (a, b) = (self.rdns(), other.rdns());
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.equivalent(y))
    }
}

/// The RDNs in RFC 4514 order, most specific first, joined with `,`; each
/// RDN as [`RelativeDistinguishedName`] prints it. An empty name prints
/// nothing.
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, rdn) in self.rdns().iter().rev().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{rdn}")?;
        }
        Ok(())
    }
}

impl DecodeInner for Name {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, rdns) = Asn1SequenceOf::decode_inner(buff, context)?;
        Ok((used, Self { rdns }))
    }
}

impl Decode for Name {}

impl Tagged for Name {
    const TAG: &'static [u8] = Asn1SequenceOf::<RelativeDistinguishedName>::TAG;
}

impl EncodeContent for Name {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.rdns.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.rdns.encode_content(rules, out)
    }
}

impl EncodeTagged for Name {}

impl Encode for Name {
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

    use super::Name;
    use crate::{AttributeTypeAndValue, DirectoryString, RelativeDistinguishedName};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn rdn(oid: &str, text: &str) -> RelativeDistinguishedName {
        RelativeDistinguishedName::single(AttributeTypeAndValue::new(
            oid.parse().unwrap(),
            DirectoryString::new(text).unwrap(),
        ))
    }

    /// C=TW, O=Example, CN=Alice
    const NAME: &[u8] = b"\x30\x2f\
        \x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02TW\
        \x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07Example\
        \x31\x0e\x30\x0c\x06\x03\x55\x04\x03\x13\x05Alice";

    #[test]
    fn a_name_round_trips_and_keeps_its_rdn_order() {
        let name = Name::new(Vec::from([
            rdn("2.5.4.6", "TW"),
            rdn("2.5.4.10", "Example"),
            rdn("2.5.4.3", "Alice"),
        ]));
        assert_eq!(name.encode_to_vec(&der()).unwrap(), NAME);
        let (used, decoded) = Name::decode(NAME, &options()).unwrap();
        assert_eq!((used, &decoded), (NAME.len(), &name));
        assert_eq!(decoded.rdns()[0], rdn("2.5.4.6", "TW"));
        assert_eq!(decoded.rdns()[2], rdn("2.5.4.3", "Alice"));
        assert!(!decoded.is_empty());

        let reversed = Name::new(Vec::from([
            rdn("2.5.4.3", "Alice"),
            rdn("2.5.4.10", "Example"),
            rdn("2.5.4.6", "TW"),
        ]));
        assert_ne!(reversed, name);
        assert_ne!(reversed.encode_to_vec(&der()).unwrap(), NAME);
    }

    #[test]
    fn display_lists_the_rdns_most_specific_first() {
        let (_, name) = Name::decode(NAME, &options()).unwrap();
        assert_eq!(name.to_string(), "CN=Alice,O=Example,C=TW");
        assert_eq!(Name::new(Vec::new()).to_string(), "");
    }

    #[test]
    fn equivalence_keeps_the_order_but_relaxes_the_values() {
        let (_, name) = Name::decode(NAME, &options()).unwrap();
        let relaxed: Name = "cn=ALICE, o=example, c=TW".parse().unwrap();
        assert_ne!(relaxed, name);
        assert!(relaxed.equivalent(&name));
        let reordered: Name = "C=TW,O=Example,CN=Alice".parse().unwrap();
        assert!(!reordered.equivalent(&name));
        let shorter: Name = "CN=Alice,O=Example".parse().unwrap();
        assert!(!shorter.equivalent(&name));
        assert!(Name::new(Vec::new()).equivalent(&Name::new(Vec::new())));
    }

    #[test]
    fn an_empty_name_is_valid() {
        let empty = Name::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.encode_to_vec(&der()).unwrap(), b"\x30\x00");
        let (_, decoded) = Name::decode(b"\x30\x00", &options()).unwrap();
        assert_eq!(decoded, empty);
    }

    #[test]
    fn a_set_in_place_of_the_sequence_and_a_bad_rdn_are_rejected() {
        let mut as_set: Vec<u8> = NAME.to_vec();
        as_set[0] = 0x31;
        assert!(matches!(
            Name::decode(&as_set, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        // an RDN that is a SEQUENCE instead of a SET
        let mut bad_rdn: Vec<u8> = NAME.to_vec();
        bad_rdn[2] = 0x30;
        assert!(matches!(
            Name::decode(&bad_rdn, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        // an empty RDN
        let empty_rdn = b"\x30\x02\x31\x00";
        assert!(matches!(
            Name::decode(empty_rdn, &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
