//! Attribute types that occur in names, with their text names.
//!
//! Most OIDs are X.520's; the rest come from RFC 4519 (`DC`, `UID`), PKCS#9
//! (`emailAddress` and friends), RFC 3739 (personal data), ISIS-MTT and the
//! CA/Browser Forum EV Guidelines, because they appear in real names. The
//! short names are the RFC 4514 §3 ones where it defines them and each
//! type's registered descriptor otherwise (RFC 4519, X.520, RFC 3739, PKCS#9,
//! the EV Guidelines). Lookup by name ignores case. Bouncy Castle prints
//! some of these differently (`SERIALNUMBER`, `E`, `DN`, `T`); `SN` here is
//! surname as in RFC 4519, not serialNumber.

use tc_asn1::{Asn1Oid, NamedOid};

/// The known attribute types, as [`NamedOid`] constants with lookups.
///
/// # Examples
///
/// ```
/// use tc_asn1_x500::AttributeType;
///
/// let cn = AttributeType::COMMON_NAME;
/// assert_eq!(cn.name(), "CN");
/// assert_eq!(cn.oid().to_string(), "2.5.4.3");
///
/// // Both directions; the name lookup ignores case.
/// assert_eq!(AttributeType::from_oid(&"2.5.4.10".parse()?), Some(AttributeType::ORGANIZATION_NAME));
/// assert_eq!(AttributeType::from_short_name("ou"), Some(AttributeType::ORGANIZATIONAL_UNIT_NAME));
/// assert_eq!(AttributeType::from_short_name("nope"), None);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub struct AttributeType;

impl AttributeType {
    /// X.520 commonName.
    pub const COMMON_NAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x03], "2.5.4.3", "CN");
    /// X.520 surname; `SN` is this, not serialNumber.
    pub const SURNAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x04], "2.5.4.4", "SN");
    /// X.520 serialNumber; a PrintableString.
    pub const SERIAL_NUMBER: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x05], "2.5.4.5", "serialNumber");
    /// X.520 countryName; a two-letter PrintableString.
    pub const COUNTRY_NAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x06], "2.5.4.6", "C");
    /// X.520 localityName.
    pub const LOCALITY_NAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x07], "2.5.4.7", "L");
    /// X.520 stateOrProvinceName.
    pub const STATE_OR_PROVINCE_NAME: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x08], "2.5.4.8", "ST");
    /// X.520 streetAddress.
    pub const STREET_ADDRESS: NamedOid = NamedOid::new(&[0x55, 0x04, 0x09], "2.5.4.9", "STREET");
    /// X.520 organizationName.
    pub const ORGANIZATION_NAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x0a], "2.5.4.10", "O");
    /// X.520 organizationalUnitName.
    pub const ORGANIZATIONAL_UNIT_NAME: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x0b], "2.5.4.11", "OU");
    /// X.520 title.
    pub const TITLE: NamedOid = NamedOid::new(&[0x55, 0x04, 0x0c], "2.5.4.12", "title");
    /// X.520 description.
    pub const DESCRIPTION: NamedOid = NamedOid::new(&[0x55, 0x04, 0x0d], "2.5.4.13", "description");
    /// X.520 businessCategory.
    pub const BUSINESS_CATEGORY: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x0f], "2.5.4.15", "businessCategory");
    /// A SEQUENCE OF DirectoryString, not a single string.
    pub const POSTAL_ADDRESS: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x10], "2.5.4.16", "postalAddress");
    /// X.520 postalCode.
    pub const POSTAL_CODE: NamedOid = NamedOid::new(&[0x55, 0x04, 0x11], "2.5.4.17", "postalCode");
    /// X.520 telephoneNumber; a PrintableString.
    pub const TELEPHONE_NUMBER: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x14], "2.5.4.20", "telephoneNumber");
    /// X.520 name.
    pub const NAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x29], "2.5.4.41", "name");
    /// X.520 givenName.
    pub const GIVEN_NAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x2a], "2.5.4.42", "givenName");
    /// X.520 initials.
    pub const INITIALS: NamedOid = NamedOid::new(&[0x55, 0x04, 0x2b], "2.5.4.43", "initials");
    /// X.520 generationQualifier.
    pub const GENERATION_QUALIFIER: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x2c], "2.5.4.44", "generationQualifier");
    /// A BIT STRING.
    pub const X500_UNIQUE_IDENTIFIER: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x2d], "2.5.4.45", "x500UniqueIdentifier");
    /// X.520 dnQualifier; a PrintableString.
    pub const DN_QUALIFIER: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x2e], "2.5.4.46", "dnQualifier");
    /// X.520 dmdName.
    pub const DMD_NAME: NamedOid = NamedOid::new(&[0x55, 0x04, 0x36], "2.5.4.54", "dmdName");
    /// X.520 pseudonym.
    pub const PSEUDONYM: NamedOid = NamedOid::new(&[0x55, 0x04, 0x41], "2.5.4.65", "pseudonym");
    /// X.520 role.
    pub const ROLE: NamedOid = NamedOid::new(&[0x55, 0x04, 0x48], "2.5.4.72", "role");
    /// X.520 organizationIdentifier.
    pub const ORGANIZATION_IDENTIFIER: NamedOid =
        NamedOid::new(&[0x55, 0x04, 0x61], "2.5.4.97", "organizationIdentifier");
    /// RFC 3739 personal data; a GeneralizedTime.
    pub const DATE_OF_BIRTH: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x01],
        "1.3.6.1.5.5.7.9.1",
        "dateOfBirth",
    );
    /// RFC 3739 personal data.
    pub const PLACE_OF_BIRTH: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x02],
        "1.3.6.1.5.5.7.9.2",
        "placeOfBirth",
    );
    /// RFC 3739 personal data; a one-character PrintableString.
    pub const GENDER: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x03],
        "1.3.6.1.5.5.7.9.3",
        "gender",
    );
    /// RFC 3739 personal data.
    pub const COUNTRY_OF_CITIZENSHIP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x04],
        "1.3.6.1.5.5.7.9.4",
        "countryOfCitizenship",
    );
    /// RFC 3739 personal data.
    pub const COUNTRY_OF_RESIDENCE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x05],
        "1.3.6.1.5.5.7.9.5",
        "countryOfResidence",
    );
    /// ISIS-MTT.
    pub const NAME_AT_BIRTH: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0e],
        "1.3.36.8.3.14",
        "nameAtBirth",
    );
    /// RFC 4519; an IA5String.
    pub const DOMAIN_COMPONENT: NamedOid = NamedOid::new(
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19],
        "0.9.2342.19200300.100.1.25",
        "DC",
    );
    /// RFC 4519.
    pub const USER_ID: NamedOid = NamedOid::new(
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01],
        "0.9.2342.19200300.100.1.1",
        "UID",
    );
    /// PKCS#9; an IA5String.
    pub const EMAIL_ADDRESS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01],
        "1.2.840.113549.1.9.1",
        "emailAddress",
    );
    /// PKCS#9.
    pub const UNSTRUCTURED_NAME: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x02],
        "1.2.840.113549.1.9.2",
        "unstructuredName",
    );
    /// PKCS#9.
    pub const UNSTRUCTURED_ADDRESS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x08],
        "1.2.840.113549.1.9.8",
        "unstructuredAddress",
    );
    /// CA/Browser Forum EV Guidelines.
    pub const JURISDICTION_LOCALITY_NAME: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x01,
        ],
        "1.3.6.1.4.1.311.60.2.1.1",
        "jurisdictionLocalityName",
    );
    /// CA/Browser Forum EV Guidelines.
    pub const JURISDICTION_STATE_OR_PROVINCE_NAME: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x02,
        ],
        "1.3.6.1.4.1.311.60.2.1.2",
        "jurisdictionStateOrProvinceName",
    );
    /// CA/Browser Forum EV Guidelines.
    pub const JURISDICTION_COUNTRY_NAME: NamedOid = NamedOid::new(
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03,
        ],
        "1.3.6.1.4.1.311.60.2.1.3",
        "jurisdictionCountryName",
    );

    /// Every known type, for lookups.
    pub const ALL: &'static [NamedOid] = &[
        Self::COMMON_NAME,
        Self::SURNAME,
        Self::SERIAL_NUMBER,
        Self::COUNTRY_NAME,
        Self::LOCALITY_NAME,
        Self::STATE_OR_PROVINCE_NAME,
        Self::STREET_ADDRESS,
        Self::ORGANIZATION_NAME,
        Self::ORGANIZATIONAL_UNIT_NAME,
        Self::TITLE,
        Self::DESCRIPTION,
        Self::BUSINESS_CATEGORY,
        Self::POSTAL_ADDRESS,
        Self::POSTAL_CODE,
        Self::TELEPHONE_NUMBER,
        Self::NAME,
        Self::GIVEN_NAME,
        Self::INITIALS,
        Self::GENERATION_QUALIFIER,
        Self::X500_UNIQUE_IDENTIFIER,
        Self::DN_QUALIFIER,
        Self::DMD_NAME,
        Self::PSEUDONYM,
        Self::ROLE,
        Self::ORGANIZATION_IDENTIFIER,
        Self::DATE_OF_BIRTH,
        Self::PLACE_OF_BIRTH,
        Self::GENDER,
        Self::COUNTRY_OF_CITIZENSHIP,
        Self::COUNTRY_OF_RESIDENCE,
        Self::NAME_AT_BIRTH,
        Self::DOMAIN_COMPONENT,
        Self::USER_ID,
        Self::EMAIL_ADDRESS,
        Self::UNSTRUCTURED_NAME,
        Self::UNSTRUCTURED_ADDRESS,
        Self::JURISDICTION_LOCALITY_NAME,
        Self::JURISDICTION_STATE_OR_PROVINCE_NAME,
        Self::JURISDICTION_COUNTRY_NAME,
    ];

    /// The known type with this OID, if any. Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }

    /// The known type with this short name, compared ignoring ASCII case.
    pub fn from_short_name(name: &str) -> Option<NamedOid> {
        NamedOid::find_by_name(Self::ALL, name)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::AttributeType;

    #[test]
    fn every_entry_encodes_its_dotted_form() {
        for attribute_type in AttributeType::ALL {
            let parsed: tc_asn1::Asn1Oid = attribute_type.dotted().parse().unwrap();
            assert_eq!(parsed, attribute_type.oid(), "{}", attribute_type.dotted());
            assert_eq!(attribute_type.oid().to_string(), attribute_type.dotted());
        }
    }

    #[test]
    fn lookups_round_trip_and_ignore_case_in_names() {
        for attribute_type in AttributeType::ALL {
            assert_eq!(
                AttributeType::from_oid(&attribute_type.oid()),
                Some(*attribute_type)
            );
            assert_eq!(
                AttributeType::from_short_name(&attribute_type.name().to_uppercase()),
                Some(*attribute_type)
            );
        }
        assert_eq!(
            AttributeType::from_short_name("cn"),
            Some(AttributeType::COMMON_NAME)
        );
        assert_eq!(AttributeType::from_short_name("CN "), None);
        assert_eq!(AttributeType::from_oid(&"1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn short_names_are_unique() {
        for (i, a) in AttributeType::ALL.iter().enumerate() {
            for b in &AttributeType::ALL[i + 1..] {
                assert!(!a.name().eq_ignore_ascii_case(b.name()));
                assert_ne!(a.oid(), b.oid());
            }
        }
    }
}
