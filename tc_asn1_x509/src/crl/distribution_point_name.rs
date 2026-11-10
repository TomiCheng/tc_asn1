//! A CRL distribution point identified by full names or an issuer-relative name.
//!
//! ```text
//! DistributionPointName ::= CHOICE {
//!     fullName                [0] GeneralNames,
//!     nameRelativeToCRLIssuer  [1] RelativeDistinguishedName }
//! ```
//!
//! Both alternatives use IMPLICIT tagging: their contents appear directly under
//! the context-specific tag, without a SEQUENCE or SET wrapper.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};
use tc_asn1_x500::RelativeDistinguishedName;

use crate::name::GeneralNames;

/// The name of a CRL distribution point.
///
/// Convert [`GeneralNames`] or [`RelativeDistinguishedName`] with `From`.
/// Formatting displays the contained names without an additional prefix.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{crl::DistributionPointName, name::{GeneralName, GeneralNames}};
///
/// let point = DistributionPointName::from(GeneralNames::new(vec![
///     GeneralName::uri("http://example.com/ca.crl")?,
/// ])?);
/// assert_eq!(point.to_string(), "URI:http://example.com/ca.crl");
/// let der = point.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = DistributionPointName::decode_der(&der, &DecodingOptions::default())?;
/// assert_eq!(back, point);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum DistributionPointName {
    /// One or more full names identifying the distribution point.
    FullName(GeneralNames),
    /// A name fragment relative to the CRL issuer's distinguished name.
    NameRelativeToCrlIssuer(RelativeDistinguishedName),
}

impl DistributionPointName {
    fn tag(&self) -> &'static [u8] {
        match self {
            Self::FullName(_) => &[0xA0],
            Self::NameRelativeToCrlIssuer(_) => &[0xA1],
        }
    }
}

impl From<GeneralNames> for DistributionPointName {
    fn from(value: GeneralNames) -> Self {
        Self::FullName(value)
    }
}

impl From<RelativeDistinguishedName> for DistributionPointName {
    fn from(value: RelativeDistinguishedName) -> Self {
        Self::NameRelativeToCrlIssuer(value)
    }
}

impl fmt::Display for DistributionPointName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullName(value) => value.fmt(f),
            Self::NameRelativeToCrlIssuer(value) => value.fmt(f),
        }
    }
}

impl DecodeInner for DistributionPointName {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0xA0] => Self::FullName(GeneralNames::decode_content(element.value(), context)?),
            [0xA1] => Self::NameRelativeToCrlIssuer(RelativeDistinguishedName::decode_content(
                element.value(),
                context,
            )?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for DistributionPointName {}

impl EncodeContent for DistributionPointName {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::FullName(value) => value.content_len(rules),
            Self::NameRelativeToCrlIssuer(value) => value.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::FullName(value) => value.encode_content(rules, out),
            Self::NameRelativeToCrlIssuer(value) => value.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for DistributionPointName {}

impl Encode for DistributionPointName {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag(), rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag(), rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x500::{AttributeTypeAndValue, DirectoryString, RelativeDistinguishedName};

    use super::DistributionPointName;
    use crate::name::{GeneralName, GeneralNames};

    #[test]
    fn both_alternatives_round_trip_without_an_inner_container_wrapper() {
        let full = GeneralNames::new(vec![
            GeneralName::uri("http://x.tw/").unwrap(),
            GeneralName::dns_name("x.tw").unwrap(),
        ])
        .unwrap();
        let relative = RelativeDistinguishedName::single(AttributeTypeAndValue::new(
            "2.5.4.3".parse().unwrap(),
            DirectoryString::new("A").unwrap(),
        ));
        for (point, wire, display) in [
            (
                DistributionPointName::from(full),
                &b"\xa0\x14\x86\x0chttp://x.tw/\x82\x04x.tw"[..],
                "URI:http://x.tw/, DNS:x.tw",
            ),
            (
                DistributionPointName::from(relative),
                &b"\xa1\x0a\x30\x08\x06\x03\x55\x04\x03\x13\x01A"[..],
                "CN=A",
            ),
        ] {
            assert_eq!(point.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(point.to_string(), display);
            let options = DecodingOptions::default();
            assert_eq!(
                DistributionPointName::decode(wire, &options).unwrap(),
                (wire.len(), point.clone())
            );
            assert_eq!(
                DistributionPointName::decode_der(wire, &options).unwrap(),
                (wire.len(), point)
            );
        }
    }

    #[test]
    fn empty_alternatives_are_rejected() {
        for wire in [b"\xa0\x00", b"\xa1\x00"] {
            assert!(matches!(
                DistributionPointName::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn unknown_or_primitive_tags_and_explicit_wrappers_are_rejected() {
        for wire in [
            &b"\xa2\x00"[..],
            b"\x80\x00",
            b"\x81\x00",
            b"\x30\x00",
            b"\x31\x00",
            b"\xa0\x08\x30\x06\x82\x04x.tw",
            b"\xa1\x0c\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x13\x01A",
        ] {
            assert!(matches!(
                DistributionPointName::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            ));
        }
    }
}
