//! RFC 5280 §4.2.2 information access syntax, shared by the authority
//! information access and subject information access extensions.
//!
//! ```text
//! AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//! SubjectInfoAccessSyntax   ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//! ```
//!
//! The entries describe services and information available about either the
//! certificate issuer or subject, as selected by the surrounding extension
//! OID. The list is never empty. RFC 5280 requires both extensions to be
//! non-critical; that property belongs to the surrounding `Extension` and is
//! left to the certificate profile validator.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::ext::AccessDescription;

/// A non-empty list of ways to obtain information about a certificate's
/// issuer or subject.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{
///     ext::{AccessDescription, AccessMethod, InformationAccess},
///     name::GeneralName,
/// };
///
/// let access = InformationAccess::new(vec![AccessDescription::new(
///     AccessMethod::OCSP,
///     GeneralName::uri("http://ocsp.example.com")?,
/// )])?;
/// assert_eq!(access.to_string(), "OCSP: URI:http://ocsp.example.com");
///
/// let der = access.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = InformationAccess::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, access);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct InformationAccess {
    descriptions: Asn1SequenceOf<AccessDescription>,
}

impl InformationAccess {
    /// An empty list violates `SIZE (1..MAX)` and is `MalformedValue`.
    pub fn new(descriptions: Vec<AccessDescription>) -> Result<Self, Asn1Error> {
        if descriptions.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            descriptions: Asn1SequenceOf::new(descriptions),
        })
    }

    /// The access descriptions in wire order, never empty.
    pub fn descriptions(&self) -> &[AccessDescription] {
        self.descriptions.elements()
    }
}

/// The descriptions joined with `, `, each as [`AccessDescription`] prints it.
impl fmt::Display for InformationAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, description) in self.descriptions().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{description}")?;
        }
        Ok(())
    }
}

impl DecodeContent for InformationAccess {
    /// The descriptions back to back; none is `MalformedValue`.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let descriptions = Asn1SequenceOf::<AccessDescription>::decode_content(value, context)?;
        Self::new(descriptions.into_elements())
    }
}

impl DecodeInner for InformationAccess {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for InformationAccess {}

impl Tagged for InformationAccess {
    const TAG: &'static [u8] = Asn1SequenceOf::<AccessDescription>::TAG;
}

impl EncodeContent for InformationAccess {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.descriptions.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.descriptions.encode_content(rules, out)
    }
}

impl EncodeTagged for InformationAccess {}

impl Encode for InformationAccess {
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

    use super::InformationAccess;
    use crate::{
        ext::{AccessDescription, AccessMethod},
        name::GeneralName,
    };

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn description(method: tc_asn1::NamedOid, uri: &str) -> AccessDescription {
        AccessDescription::new(method, GeneralName::uri(uri).unwrap())
    }

    #[test]
    fn descriptions_round_trip_in_order_with_a_fixed_der_encoding() {
        let access = InformationAccess::new(Vec::from([
            description(AccessMethod::OCSP, "http://ocsp.x"),
            description(AccessMethod::CA_ISSUERS, "http://ca.x"),
        ]))
        .unwrap();
        let der = access.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            der,
            b"\x30\x34\x30\x19\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01\x86\x0dhttp://ocsp.x\x30\x17\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x02\x86\x0bhttp://ca.x"
        );
        let (used, back) = InformationAccess::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &access));
        assert_eq!(
            InformationAccess::decode_der(&der, &options()).unwrap().1,
            access
        );
        assert_eq!(
            back.to_string(),
            "OCSP: URI:http://ocsp.x, caIssuers: URI:http://ca.x"
        );
    }

    #[test]
    fn an_empty_list_is_rejected_when_built_or_decoded() {
        assert!(matches!(
            InformationAccess::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            InformationAccess::decode(b"\x30\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_bare_access_method_or_a_set_is_rejected() {
        assert!(matches!(
            InformationAccess::decode(
                b"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01",
                &options()
            ),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            InformationAccess::decode(
                b"\x31\x1b\x30\x19\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01\x86\x0dhttp://ocsp.x",
                &options()
            ),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
