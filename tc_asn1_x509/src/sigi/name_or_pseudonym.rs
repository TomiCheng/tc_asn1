//! Common PKI (SigI) name or pseudonym, the first field of [`PersonalData`](crate::sigi::PersonalData).
//!
//! ```text
//! NameOrPseudonym ::= CHOICE {
//!     surAndGivenName SEQUENCE {
//!         surName   DirectoryString,
//!         givenName SEQUENCE OF DirectoryString },
//!     pseudonym DirectoryString }
//! ```
//!
//! `givenName` has no size constraint, so an empty list is kept.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::DirectoryString;

/// A surname with the given names, in order.
///
/// ```
/// use tc_asn1_x500::DirectoryString;
/// use tc_asn1_x509::sigi::SurAndGivenName;
///
/// let name = SurAndGivenName::new(
///     DirectoryString::new("Mustermann")?,
///     vec![DirectoryString::new("Erika")?],
/// );
/// assert_eq!(name.given_name().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SurAndGivenName {
    surname: DirectoryString,
    given_name: Asn1SequenceOf<DirectoryString>,
}

impl SurAndGivenName {
    /// Keeps the given names in the given order; an empty list is allowed.
    pub fn new(surname: DirectoryString, given_name: Vec<DirectoryString>) -> Self {
        Self {
            surname,
            given_name: Asn1SequenceOf::new(given_name),
        }
    }

    /// Returns `surName`.
    pub fn surname(&self) -> &DirectoryString {
        &self.surname
    }

    /// The given names in wire order.
    pub fn given_name(&self) -> &[DirectoryString] {
        self.given_name.elements()
    }
}

impl DecodeContent for SurAndGivenName {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let surname = fields.get()?;
        let given_name = fields.get()?;
        fields.end()?;
        Ok(Self {
            surname,
            given_name,
        })
    }
}

impl DecodeInner for SurAndGivenName {
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

impl EncodeContent for SurAndGivenName {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.surname.encoded_len(rules) + self.given_name.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.surname.encode(rules, out)?;
        at += self.given_name.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for SurAndGivenName {}

impl Tagged for SurAndGivenName {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SurAndGivenName {}

impl Encode for SurAndGivenName {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

/// A real name split into surname and given names, or a pseudonym.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x500::DirectoryString;
/// use tc_asn1_x509::sigi::NameOrPseudonym;
///
/// let pseudonym = NameOrPseudonym::Pseudonym(DirectoryString::new("Tux")?);
/// assert_eq!(pseudonym.encode_to_vec(&EncodingOptions::DER)?, b"\x13\x03Tux");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum NameOrPseudonym {
    /// `surAndGivenName`.
    SurAndGivenName(SurAndGivenName),
    /// `pseudonym`.
    Pseudonym(DirectoryString),
}

impl DecodeInner for NameOrPseudonym {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        if Asn1Ref::parse(buff, context)?.tag() == SurAndGivenName::TAG {
            let (used, value) = SurAndGivenName::decode_inner(buff, context)?;
            Ok((used, Self::SurAndGivenName(value)))
        } else {
            let (used, value) = DirectoryString::decode_inner(buff, context)?;
            Ok((used, Self::Pseudonym(value)))
        }
    }
}

impl Decode for NameOrPseudonym {}

impl EncodeContent for NameOrPseudonym {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::SurAndGivenName(value) => value.content_len(rules),
            Self::Pseudonym(value) => value.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::SurAndGivenName(value) => value.encode_content(rules, out),
            Self::Pseudonym(value) => value.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for NameOrPseudonym {}

// Each alternative writes its own tag.
impl Encode for NameOrPseudonym {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::SurAndGivenName(value) => value.encoded_len(rules),
            Self::Pseudonym(value) => value.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::SurAndGivenName(value) => value.encode(rules, out),
            Self::Pseudonym(value) => value.encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x500::DirectoryString;

    use super::{NameOrPseudonym, SurAndGivenName};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn text(value: &str) -> DirectoryString {
        DirectoryString::new(value).unwrap()
    }

    #[test]
    fn a_surname_with_given_names_round_trips_in_order() {
        let name = NameOrPseudonym::SurAndGivenName(SurAndGivenName::new(
            text("M"),
            vec![text("E"), text("A")],
        ));
        let wire = b"\x30\x0b\x13\x01M\x30\x06\x13\x01E\x13\x01A";
        assert_eq!(name.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        let back = NameOrPseudonym::decode_der(wire, &options()).unwrap().1;
        let NameOrPseudonym::SurAndGivenName(back) = back else {
            panic!("expected surAndGivenName");
        };
        assert_eq!(back.surname(), &text("M"));
        assert_eq!(back.given_name(), &[text("E"), text("A")]);
    }

    #[test]
    fn a_pseudonym_is_the_bare_directory_string() {
        let wire = b"\x0c\x02\xc3\xa9";
        let back = NameOrPseudonym::decode_der(wire, &options()).unwrap().1;
        assert_eq!(back, NameOrPseudonym::Pseudonym(text("\u{e9}")));
        assert_eq!(back.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
    }

    #[test]
    fn empty_given_names_are_kept_but_a_missing_list_is_rejected() {
        let back = NameOrPseudonym::decode_der(b"\x30\x05\x13\x01M\x30\x00", &options())
            .unwrap()
            .1;
        assert!(matches!(
            back,
            NameOrPseudonym::SurAndGivenName(ref name) if name.given_name().is_empty()
        ));
        assert!(NameOrPseudonym::decode_der(b"\x30\x03\x13\x01M", &options()).is_err());
        assert!(matches!(
            NameOrPseudonym::decode_der(b"\x02\x01\x00", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
