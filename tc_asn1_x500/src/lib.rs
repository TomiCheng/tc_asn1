//! X.500 distinguished names on [`tc_asn1`], as used for the subject and
//! issuer of X.509 certificates.
//!
//! A [`Name`] is a sequence of [`RelativeDistinguishedName`]s, each a set of
//! [`AttributeTypeAndValue`] pairs whose values are mostly
//! [`DirectoryString`]s; [`AttributeType`] has the OIDs that occur in names,
//! and [`Attribute`] carries a set of values, as in certificate requests.
//! Every type decodes any BER and encodes under BER, CER or DER through the
//! `tc_asn1` traits. A `Name` also parses from and prints as RFC 4514 text,
//! and compares strictly with `==` or with the relaxed matching of RFC 5280
//! §7.1 through `equivalent`.
//!
//! ```
//! use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
//! use tc_asn1_x500::Name;
//!
//! let name: Name = "CN=Alice,O=Example,C=TW".parse()?;
//! let der = name.encode_to_vec(&EncodingOptions::DER)?;
//! let (_, decoded) = Name::decode(&der, &DecodingOptions::default())?;
//! assert_eq!(decoded.to_string(), "CN=Alice,O=Example,C=TW");
//! assert!(decoded.equivalent(&"cn=alice, o=EXAMPLE, c=TW".parse()?));
//! # Ok::<(), tc_asn1::Asn1Error>(())
//! ```

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod attribute;
mod attribute_type;
mod attribute_type_and_value;
mod directory_string;
mod name;
mod relative_distinguished_name;
mod string_prep;

pub use attribute::Attribute;
pub use attribute_type::AttributeType;
pub use attribute_type_and_value::{AttributeTypeAndValue, AttributeValue};
pub use directory_string::DirectoryString;
pub use name::Name;
pub use relative_distinguished_name::RelativeDistinguishedName;
