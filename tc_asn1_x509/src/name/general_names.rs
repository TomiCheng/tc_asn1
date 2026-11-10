//! RFC 5280 §4.2.1.6 `GeneralNames`.
//!
//! ```text
//! GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
//! ```
//!
//! The value of subjectAltName and issuerAltName, and a field of
//! authorityKeyIdentifier and cRLDistributionPoints. Never empty; the
//! kinds may be mixed and repeated, in the order given.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::name::GeneralName;

/// A non-empty list of names.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::name::{GeneralName, GeneralNames};
///
/// // A subjectAltName covering two hosts and an address.
/// let names = GeneralNames::new(vec![
///     GeneralName::dns_name("example.com")?,
///     GeneralName::dns_name("www.example.com")?,
///     GeneralName::ip_address(&[192, 0, 2, 1]),
/// ])?;
/// assert_eq!(names.to_string(), "DNS:example.com, DNS:www.example.com, IP:192.0.2.1");
///
/// let der = names.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = GeneralNames::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.names().len(), 3);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GeneralNames {
    names: Asn1SequenceOf<GeneralName>,
}

impl GeneralNames {
    /// An empty list violates `SIZE (1..MAX)` and is `MalformedValue`.
    pub fn new(names: Vec<GeneralName>) -> Result<Self, Asn1Error> {
        if names.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            names: Asn1SequenceOf::new(names),
        })
    }

    /// The names in wire order, never empty.
    pub fn names(&self) -> &[GeneralName] {
        self.names.elements()
    }
}

/// The names joined with `, `, each as [`GeneralName`] prints it.
impl fmt::Display for GeneralNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, name) in self.names().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{name}")?;
        }
        Ok(())
    }
}

impl DecodeContent for GeneralNames {
    /// The names back to back, as under an IMPLICIT tag such as
    /// authorityKeyIdentifier's `[1]`; none is `MalformedValue`.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let names = Asn1SequenceOf::<GeneralName>::decode_content(value, context)?;
        Self::new(names.into_elements())
    }
}

impl DecodeInner for GeneralNames {
    /// An empty SEQUENCE is `MalformedValue`. Variable time: branches only
    /// on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for GeneralNames {}

impl Tagged for GeneralNames {
    const TAG: &'static [u8] = Asn1SequenceOf::<GeneralName>::TAG;
}

impl EncodeContent for GeneralNames {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.names.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.names.encode_content(rules, out)
    }
}

impl EncodeTagged for GeneralNames {}

impl Encode for GeneralNames {
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

    use super::GeneralNames;
    use crate::name::GeneralName;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn mixed_kinds_round_trip_in_order_and_print_joined() {
        let names = GeneralNames::new(Vec::from([
            GeneralName::dns_name("x.tw").unwrap(),
            GeneralName::rfc822_name("a@x.tw").unwrap(),
            GeneralName::ip_address(&[10, 0, 0, 1]),
        ]))
        .unwrap();
        let der = names.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            der,
            b"\x30\x14\x82\x04x.tw\x81\x06a@x.tw\x87\x04\x0a\x00\x00\x01"
        );
        let (used, back) = GeneralNames::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &names));
        assert_eq!(back.names()[1].to_string(), "email:a@x.tw");
        assert_eq!(names.to_string(), "DNS:x.tw, email:a@x.tw, IP:10.0.0.1");
        assert_eq!(GeneralNames::decode_der(&der, &options()).unwrap().1, names);
    }

    #[test]
    fn an_empty_list_is_rejected_when_built_or_decoded() {
        assert!(matches!(
            GeneralNames::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            GeneralNames::decode(b"\x30\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_universal_string_among_the_names_is_unexpected() {
        assert!(matches!(
            GeneralNames::decode(b"\x30\x06\x16\x04x.tw", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
