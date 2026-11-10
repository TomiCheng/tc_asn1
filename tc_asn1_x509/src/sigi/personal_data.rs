//! Common PKI (SigI) personal data, an `OtherName` value under
//! [`SigiId::PERSONAL_DATA`](crate::sigi::SigiId::PERSONAL_DATA).
//!
//! ```text
//! PersonalData ::= SEQUENCE {
//!     nameOrPseudonym   NameOrPseudonym,
//!     nameDistinguisher [0] INTEGER OPTIONAL,
//!     dateOfBirth       [1] GeneralizedTime OPTIONAL,
//!     placeOfBirth      [2] DirectoryString OPTIONAL,
//!     gender            [3] PrintableString OPTIONAL,
//!     postalAddress     [4] DirectoryString OPTIONAL }
//! ```
//!
//! As in Bouncy Castle, `placeOfBirth` and `postalAddress` are EXPLICIT
//! because a CHOICE cannot take an implicit tag; the other tags are IMPLICIT.

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Integer, Asn1PrintableString, Asn1Ref, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Implicit, Tagged, tag,
};
use tc_asn1_x500::DirectoryString;

use crate::sigi::NameOrPseudonym;

const NAME_DISTINGUISHER: &[u8] = &[0x80];
const DATE_OF_BIRTH: &[u8] = &[0x81];
const PLACE_OF_BIRTH: &[u8] = &[0xa2];
const GENDER: &[u8] = &[0x83];
const POSTAL_ADDRESS: &[u8] = &[0xa4];

/// A name or pseudonym with optional identifying details.
///
/// ```
/// use tc_asn1::{Asn1GeneralizedTime, Asn1PrintableString};
/// use tc_asn1_x500::DirectoryString;
/// use tc_asn1_x509::sigi::{NameOrPseudonym, PersonalData};
///
/// let data = PersonalData::new(NameOrPseudonym::Pseudonym(DirectoryString::new("Tux")?))
///     .with_date_of_birth(Asn1GeneralizedTime::new(1991, 8, 25, 0, 0, 0)?)
///     .with_gender(Asn1PrintableString::new("M")?);
/// assert!(data.place_of_birth().is_none());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PersonalData {
    name_or_pseudonym: NameOrPseudonym,
    name_distinguisher: Option<Asn1Integer>,
    date_of_birth: Option<Asn1GeneralizedTime>,
    place_of_birth: Option<DirectoryString>,
    gender: Option<Asn1PrintableString>,
    postal_address: Option<DirectoryString>,
}

impl PersonalData {
    /// Creates the data with only `nameOrPseudonym`; every optional field starts absent.
    pub fn new(name_or_pseudonym: NameOrPseudonym) -> Self {
        Self {
            name_or_pseudonym,
            name_distinguisher: None,
            date_of_birth: None,
            place_of_birth: None,
            gender: None,
            postal_address: None,
        }
    }

    /// Sets `nameDistinguisher`.
    pub fn with_name_distinguisher(mut self, name_distinguisher: impl Into<Asn1Integer>) -> Self {
        self.name_distinguisher = Some(name_distinguisher.into());
        self
    }

    /// Sets `dateOfBirth`.
    pub fn with_date_of_birth(mut self, date_of_birth: Asn1GeneralizedTime) -> Self {
        self.date_of_birth = Some(date_of_birth);
        self
    }

    /// Sets `placeOfBirth`.
    pub fn with_place_of_birth(mut self, place_of_birth: DirectoryString) -> Self {
        self.place_of_birth = Some(place_of_birth);
        self
    }

    /// Sets `gender`.
    pub fn with_gender(mut self, gender: Asn1PrintableString) -> Self {
        self.gender = Some(gender);
        self
    }

    /// Sets `postalAddress`.
    pub fn with_postal_address(mut self, postal_address: DirectoryString) -> Self {
        self.postal_address = Some(postal_address);
        self
    }

    /// Returns `nameOrPseudonym`.
    pub fn name_or_pseudonym(&self) -> &NameOrPseudonym {
        &self.name_or_pseudonym
    }

    /// Returns `nameDistinguisher`, if present.
    pub fn name_distinguisher(&self) -> Option<&Asn1Integer> {
        self.name_distinguisher.as_ref()
    }

    /// Returns `dateOfBirth`, if present.
    pub fn date_of_birth(&self) -> Option<&Asn1GeneralizedTime> {
        self.date_of_birth.as_ref()
    }

    /// Returns `placeOfBirth`, if present.
    pub fn place_of_birth(&self) -> Option<&DirectoryString> {
        self.place_of_birth.as_ref()
    }

    /// Returns `gender`, if present.
    pub fn gender(&self) -> Option<&Asn1PrintableString> {
        self.gender.as_ref()
    }

    /// Returns `postalAddress`, if present.
    pub fn postal_address(&self) -> Option<&DirectoryString> {
        self.postal_address.as_ref()
    }
}

impl DecodeContent for PersonalData {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let name_or_pseudonym = fields.get()?;
        let name_distinguisher = fields.get_implicit_opt(NAME_DISTINGUISHER)?;
        let date_of_birth = fields.get_implicit_opt(DATE_OF_BIRTH)?;
        let place_of_birth = fields.get_explicit_opt(PLACE_OF_BIRTH)?;
        let gender = fields.get_implicit_opt(GENDER)?;
        let postal_address = fields.get_explicit_opt(POSTAL_ADDRESS)?;
        fields.end()?;
        Ok(Self {
            name_or_pseudonym,
            name_distinguisher,
            date_of_birth,
            place_of_birth,
            gender,
            postal_address,
        })
    }
}

impl DecodeInner for PersonalData {
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

impl EncodeContent for PersonalData {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.name_or_pseudonym.encoded_len(rules)
            + self.name_distinguisher.as_ref().map_or(0, |value| {
                Implicit::new(NAME_DISTINGUISHER, value).encoded_len(rules)
            })
            + self.date_of_birth.as_ref().map_or(0, |value| {
                Implicit::new(DATE_OF_BIRTH, value).encoded_len(rules)
            })
            + self.place_of_birth.as_ref().map_or(0, |value| {
                Explicit::new(PLACE_OF_BIRTH, value).encoded_len(rules)
            })
            + self
                .gender
                .as_ref()
                .map_or(0, |value| Implicit::new(GENDER, value).encoded_len(rules))
            + self.postal_address.as_ref().map_or(0, |value| {
                Explicit::new(POSTAL_ADDRESS, value).encoded_len(rules)
            })
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.name_or_pseudonym.encode(rules, out)?;
        if let Some(value) = &self.name_distinguisher {
            at += Implicit::new(NAME_DISTINGUISHER, value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.date_of_birth {
            at += Implicit::new(DATE_OF_BIRTH, value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.place_of_birth {
            at += Explicit::new(PLACE_OF_BIRTH, value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.gender {
            at += Implicit::new(GENDER, value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.postal_address {
            at += Explicit::new(POSTAL_ADDRESS, value).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PersonalData {}

impl Tagged for PersonalData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PersonalData {}

impl Encode for PersonalData {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{
        Asn1GeneralizedTime, Asn1PrintableString, Decode, DecodingOptions, Encode, EncodingOptions,
    };
    use tc_asn1_x500::DirectoryString;

    use super::PersonalData;
    use crate::sigi::NameOrPseudonym;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn name() -> NameOrPseudonym {
        NameOrPseudonym::Pseudonym(DirectoryString::new("T").unwrap())
    }

    #[test]
    fn only_the_name_is_required() {
        let wire = b"\x30\x03\x13\x01T";
        let value = PersonalData::new(name());
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(PersonalData::decode_der(wire, &options()).unwrap().1, value);
    }

    #[test]
    fn every_field_round_trips_with_implicit_and_explicit_tags() {
        let value = PersonalData::new(name())
            .with_name_distinguisher(7)
            .with_date_of_birth(Asn1GeneralizedTime::new(1991, 8, 25, 0, 0, 0).unwrap())
            .with_place_of_birth(DirectoryString::new("B").unwrap())
            .with_gender(Asn1PrintableString::new("F").unwrap())
            .with_postal_address(DirectoryString::new("P").unwrap());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            wire,
            b"\x30\x24\x13\x01T\x80\x01\x07\x81\x0f19910825000000Z\
              \xa2\x03\x13\x01B\x83\x01F\xa4\x03\x13\x01P"
        );
        assert_eq!(
            PersonalData::decode_der(&wire, &options()).unwrap().1,
            value
        );
    }

    #[test]
    fn fields_out_of_order_or_untagged_are_rejected() {
        // gender before placeOfBirth
        assert!(
            PersonalData::decode_der(b"\x30\x0b\x13\x01T\x83\x01F\xa2\x03\x13\x01B", &options())
                .is_err()
        );
        // placeOfBirth without its EXPLICIT wrapper
        assert!(PersonalData::decode_der(b"\x30\x06\x13\x01T\x82\x01B", &options()).is_err());
    }
}
