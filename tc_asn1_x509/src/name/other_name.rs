//! RFC 5280 §4.2.1.6 `OtherName`, the `[0]` alternative of `GeneralName`.
//!
//! ```text
//! OtherName ::= SEQUENCE {
//!     type-id  OBJECT IDENTIFIER,
//!     value    [0] EXPLICIT ANY DEFINED BY type-id }
//! ```
//!
//! A name of a kind the OID identifies, the value being whatever type that
//! kind uses: a UTF8String for a Microsoft user principal name or an XMPP
//! address, an IA5String for an SRVName, a SEQUENCE for a Kerberos
//! principal. The value is classified by its tag, as an X.500 attribute
//! value is; which kind a UTF8String is, the caller reads off the OID.
//! Inside a GeneralName the SEQUENCE tag is replaced by `A0`, on its own
//! it is `30`.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1Object, Asn1Oid, Asn1Ref, Asn1Utf8String, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Tagged, tag,
};

/// The value of an [`OtherName`], classified by its identifier.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum OtherNameValue {
    /// UTF8String: userPrincipalName, xmppAddr, SmtpUTF8Mailbox.
    Utf8String(Asn1Utf8String),
    /// IA5String: SRVName.
    Ia5String(Asn1Ia5String),
    /// Any other identifier, as an [`Asn1Object`]: the SEQUENCE of a
    /// KRB5PrincipalName or a hardwareModuleName, and whatever else.
    Other(Asn1Object),
}

impl From<Asn1Utf8String> for OtherNameValue {
    fn from(value: Asn1Utf8String) -> Self {
        Self::Utf8String(value)
    }
}

impl From<Asn1Ia5String> for OtherNameValue {
    fn from(value: Asn1Ia5String) -> Self {
        Self::Ia5String(value)
    }
}

impl From<Asn1Object> for OtherNameValue {
    fn from(value: Asn1Object) -> Self {
        Self::Other(value)
    }
}

impl DecodeInner for OtherNameValue {
    /// A UTF8String or IA5String by tag, anything else as an
    /// [`Asn1Object`]. Variable time: branches only on the encoding
    /// structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if element.tag() == Asn1Utf8String::TAG {
            let (used, value) = Asn1Utf8String::decode_inner(buff, context)?;
            Ok((used, Self::Utf8String(value)))
        } else if element.tag() == Asn1Ia5String::TAG {
            let (used, value) = Asn1Ia5String::decode_inner(buff, context)?;
            Ok((used, Self::Ia5String(value)))
        } else {
            let (used, value) = Asn1Object::decode_inner(buff, context)?;
            Ok((used, Self::Other(value)))
        }
    }
}

impl Decode for OtherNameValue {}

impl EncodeContent for OtherNameValue {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Utf8String(s) => s.content_len(rules),
            Self::Ia5String(s) => s.content_len(rules),
            Self::Other(object) => object.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Utf8String(s) => s.encode_content(rules, out),
            Self::Ia5String(s) => s.encode_content(rules, out),
            Self::Other(object) => object.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for OtherNameValue {}

/// Each alternative writes its own identifier.
impl Encode for OtherNameValue {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Utf8String(s) => s.encoded_len(rules),
            Self::Ia5String(s) => s.encoded_len(rules),
            Self::Other(object) => object.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Utf8String(s) => s.encode(rules, out),
            Self::Ia5String(s) => s.encode(rules, out),
            Self::Other(object) => object.encode(rules, out),
        }
    }
}

/// A type OID and a value of whatever type that OID says.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Oid, Asn1Utf8String, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::name::{OtherName, OtherNameValue};
///
/// // A Microsoft user principal name: the OID says the value is a UTF8String.
/// let upn = OtherName::new(
///     "1.3.6.1.4.1.311.20.2.3".parse::<Asn1Oid>()?,
///     Asn1Utf8String::new("alice@example.com"),
/// );
/// assert_eq!(upn.to_string(), "1.3.6.1.4.1.311.20.2.3:alice@example.com");
///
/// let der = upn.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = OtherName::decode(&der, &DecodingOptions::default())?;
/// let OtherNameValue::Utf8String(text) = back.value() else { panic!() };
/// assert_eq!(text.as_str(), "alice@example.com");
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherName {
    type_id: Asn1Oid,
    value: OtherNameValue,
}

impl OtherName {
    /// A name of the type `type_id` with its value.
    pub fn new(type_id: impl Into<Asn1Oid>, value: impl Into<OtherNameValue>) -> Self {
        Self {
            type_id: type_id.into(),
            value: value.into(),
        }
    }

    /// The OID of the name's type.
    pub fn type_id(&self) -> &Asn1Oid {
        &self.type_id
    }

    /// The value inside the `[0]` wrapper.
    pub fn value(&self) -> &OtherNameValue {
        &self.value
    }
}

/// `oid:text` for a string value, the OID alone for anything else.
impl fmt::Display for OtherName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_id)?;
        match &self.value {
            OtherNameValue::Utf8String(s) => write!(f, ":{s}"),
            OtherNameValue::Ia5String(s) => write!(f, ":{s}"),
            _ => Ok(()),
        }
    }
}

impl DecodeContent for OtherName {
    /// The two fields, as under `30` on its own or `A0` inside a
    /// GeneralName.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let type_id = fields.get()?;
        let value = fields.get_explicit([0xA0])?;
        fields.end()?;
        Ok(Self { type_id, value })
    }
}

impl DecodeInner for OtherName {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for OtherName {}

impl Tagged for OtherName {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for OtherName {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.type_id.encoded_len(rules) + Explicit::new(&[0xA0], &self.value).encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.type_id.encode(rules, out)?;
        at += Explicit::new(&[0xA0], &self.value).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for OtherName {}

impl Encode for OtherName {
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

    use tc_asn1::{
        Asn1Error, Asn1Ia5String, Asn1Object, Asn1Oid, Asn1Utf8String, Decode, DecodingOptions,
        Encode, EncodingOptions,
    };

    use super::{OtherName, OtherNameValue};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn upn() -> OtherName {
        OtherName::new(
            "1.3.6.1.4.1.311.20.2.3".parse::<Asn1Oid>().unwrap(),
            Asn1Utf8String::new("u@x"),
        )
    }

    #[test]
    fn the_value_sits_inside_an_explicit_zero_wrapper() {
        let upn = upn();
        let der = upn.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            der,
            b"\x30\x13\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03\xa0\x05\x0c\x03u@x"
        );
        let (used, back) = OtherName::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &upn));
        assert_eq!(back.type_id().to_string(), "1.3.6.1.4.1.311.20.2.3");
        assert_eq!(back.to_string(), "1.3.6.1.4.1.311.20.2.3:u@x");
        assert_eq!(OtherName::decode_der(&der, &options()).unwrap().1, upn);
    }

    #[test]
    fn the_value_is_classified_by_its_tag() {
        let srv = OtherName::new(
            "1.3.6.1.5.5.7.8.7".parse::<Asn1Oid>().unwrap(),
            Asn1Ia5String::new("_ldap.x").unwrap(),
        );
        let der = srv.encode_to_vec(&EncodingOptions::DER).unwrap();
        let (_, back) = OtherName::decode(&der, &options()).unwrap();
        assert!(matches!(back.value(), OtherNameValue::Ia5String(s) if s.as_str() == "_ldap.x"));
        assert_eq!(back.to_string(), "1.3.6.1.5.5.7.8.7:_ldap.x");

        // KRB5PrincipalName-shaped: a SEQUENCE lands in Other as a tree
        let krb = OtherName::new(
            "1.3.6.1.5.2.2".parse::<Asn1Oid>().unwrap(),
            Asn1Object::sequence(alloc::vec![Asn1Object::from(Asn1Utf8String::new("REALM"))]),
        );
        let der = krb.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(&der[der.len() - 11..], b"\xa0\x09\x30\x07\x0c\x05REALM");
        let (_, back) = OtherName::decode(&der, &options()).unwrap();
        assert!(matches!(
            back.value(),
            OtherNameValue::Other(Asn1Object::SequenceOf(_))
        ));
        assert_eq!(back.to_string(), "1.3.6.1.5.2.2");
        assert_eq!(back, krb);
    }

    #[test]
    fn a_value_outside_the_wrapper_or_a_second_one_inside_is_rejected() {
        assert!(matches!(
            OtherName::decode(
                b"\x30\x0f\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03\x0c\x01u",
                &options()
            ),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            OtherName::decode(
                b"\x30\x16\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03\xa0\x08\x0c\x01u\x0c\x01v\x05\x00",
                &options()
            ),
            Err(Asn1Error::TrailingData)
        ));
        assert!(matches!(
            OtherName::decode(b"\x30\x00", &options()),
            Err(Asn1Error::Truncated)
        ));
    }
}
