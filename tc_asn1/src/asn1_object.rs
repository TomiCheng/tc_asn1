//! A decoded tree for encodings without a schema.

use alloc::vec::Vec;

use crate::universal::*;
use crate::{
    Asn1Any, Asn1Constructed, Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions,
};

mod dump;

/// Any BER value as a tree: each universal type as its own variant, a
/// constructed value under any other tag as [`Constructed`](Self::Constructed)
/// and an uninterpreted primitive as [`Unknown`](Self::Unknown).
///
/// For looking at an encoding whose schema is not known or not implemented,
/// dumping it with `Display`, or building one by hand; a known structure
/// decodes straight into its own type instead. `From` is implemented for
/// every variant's type.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Null, Asn1Object, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// // AlgorithmIdentifier { rsaEncryption, NULL } read without its schema.
/// let der = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00];
/// let (_, tree) = Asn1Object::decode(&der, &DecodingOptions::default())?;
/// let Asn1Object::SequenceOf(fields) = &tree else { panic!() };
/// let Asn1Object::Oid(oid) = &fields.elements()[0] else { panic!() };
/// assert_eq!(oid.to_string(), "1.2.840.113549.1.1.1");
/// assert_eq!(tree.to_string(), "SEQUENCE\n  OBJECT IDENTIFIER 1.2.840.113549.1.1.1\n  NULL\n");
///
/// // The same tree built by hand encodes identically.
/// let built = Asn1Object::sequence(vec![
///     "1.2.840.113549.1.1.1".parse::<Asn1Oid>()?.into(),
///     Asn1Null.into(),
/// ]);
/// assert_eq!(built.encode_to_vec(&EncodingOptions::DER)?, der);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Asn1Object {
    Boolean(Asn1Boolean),
    Integer(Asn1Integer),
    BitString(Asn1BitString),
    OctetString(Asn1OctetString),
    Null(Asn1Null),
    Oid(Asn1Oid),
    Real(Asn1Real),
    Enumerated(Asn1Enumerated),
    Utf8String(Asn1Utf8String),
    RelativeOid(Asn1RelativeOid),
    Time(Asn1Time),
    NumericString(Asn1NumericString),
    PrintableString(Asn1PrintableString),
    Ia5String(Asn1Ia5String),
    UtcTime(Asn1UtcTime),
    GeneralizedTime(Asn1GeneralizedTime),
    VisibleString(Asn1VisibleString),
    UniversalString(Asn1UniversalString),
    BmpString(Asn1BmpString),
    Date(Asn1Date),
    TimeOfDay(Asn1TimeOfDay),
    DateTime(Asn1DateTime),
    Duration(Asn1Duration),
    OidIri(Asn1OidIri),
    RelativeOidIri(Asn1RelativeOidIri),
    /// A universal SEQUENCE (30).
    SequenceOf(Asn1SequenceOf<Asn1Object>),
    /// A universal SET (31): sorted under CER and DER like a SET OF.
    SetOf(Asn1SetOf<Asn1Object>),
    /// A constructed value under any tag but SEQUENCE and SET, its
    /// elements decoded.
    Constructed(Asn1Constructed<Asn1Object>),
    /// A primitive value whose tag this crate does not interpret, kept as
    /// its octets.
    Unknown(Asn1Any),
}

/// `Asn1Object::from(value)` for every variant, so mixed elements can be
/// written as `vec![oid.into(), Asn1Null.into()]`.
macro_rules! from_variant {
    ($($variant:ident: $ty:ty),* $(,)?) => {$(
        impl From<$ty> for Asn1Object {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    )*};
}
from_variant! {
    Boolean: Asn1Boolean,
    Integer: Asn1Integer,
    BitString: Asn1BitString,
    OctetString: Asn1OctetString,
    Null: Asn1Null,
    Oid: Asn1Oid,
    Real: Asn1Real,
    Enumerated: Asn1Enumerated,
    Utf8String: Asn1Utf8String,
    RelativeOid: Asn1RelativeOid,
    Time: Asn1Time,
    NumericString: Asn1NumericString,
    PrintableString: Asn1PrintableString,
    Ia5String: Asn1Ia5String,
    UtcTime: Asn1UtcTime,
    GeneralizedTime: Asn1GeneralizedTime,
    VisibleString: Asn1VisibleString,
    UniversalString: Asn1UniversalString,
    BmpString: Asn1BmpString,
    Date: Asn1Date,
    TimeOfDay: Asn1TimeOfDay,
    DateTime: Asn1DateTime,
    Duration: Asn1Duration,
    OidIri: Asn1OidIri,
    RelativeOidIri: Asn1RelativeOidIri,
    SequenceOf: Asn1SequenceOf<Asn1Object>,
    SetOf: Asn1SetOf<Asn1Object>,
    Constructed: Asn1Constructed<Asn1Object>,
    Unknown: Asn1Any,
}

impl Asn1Object {
    /// A SEQUENCE node; fixes the element type so `vec![a.into(), b.into()]` infers.
    pub fn sequence(elements: Vec<Asn1Object>) -> Self {
        Self::SequenceOf(Asn1SequenceOf::new(elements))
    }

    /// A SET node, sorted on CER and DER output.
    pub fn set(members: Vec<Asn1Object>) -> Self {
        Self::SetOf(Asn1SetOf::new(members))
    }

    /// Interprets one primitive element by its universal tag; anything else is
    /// kept as `Unknown`. Variable time: branches only on the identifier.
    fn primitive(
        tag: &[u8],
        value: &[u8],
        context: &mut DecodingContext,
    ) -> Result<Self, Asn1Error> {
        Ok(match tag {
            t if t == tag::BOOLEAN => Self::Boolean(Asn1Boolean::decode_content(value, context)?),
            t if t == tag::INTEGER => Self::Integer(Asn1Integer::decode_content(value, context)?),
            t if t == tag::BIT_STRING => {
                Self::BitString(Asn1BitString::decode_content(value, context)?)
            }
            t if t == tag::OCTET_STRING => {
                Self::OctetString(Asn1OctetString::decode_content(value, context)?)
            }
            t if t == tag::NULL => Self::Null(Asn1Null::decode_content(value, context)?),
            t if t == tag::OBJECT_IDENTIFIER => Self::Oid(Asn1Oid::decode_content(value, context)?),
            t if t == tag::REAL => Self::Real(Asn1Real::decode_content(value, context)?),
            t if t == tag::ENUMERATED => {
                Self::Enumerated(Asn1Enumerated::decode_content(value, context)?)
            }
            t if t == tag::UTF8_STRING => {
                Self::Utf8String(Asn1Utf8String::decode_content(value, context)?)
            }
            t if t == tag::RELATIVE_OID => {
                Self::RelativeOid(Asn1RelativeOid::decode_content(value, context)?)
            }
            t if t == tag::TIME => Self::Time(Asn1Time::decode_content(value, context)?),
            t if t == tag::NUMERIC_STRING => {
                Self::NumericString(Asn1NumericString::decode_content(value, context)?)
            }
            t if t == tag::PRINTABLE_STRING => {
                Self::PrintableString(Asn1PrintableString::decode_content(value, context)?)
            }
            t if t == tag::IA5_STRING => {
                Self::Ia5String(Asn1Ia5String::decode_content(value, context)?)
            }
            t if t == tag::UTC_TIME => Self::UtcTime(Asn1UtcTime::decode_content(value, context)?),
            t if t == tag::GENERALIZED_TIME => {
                Self::GeneralizedTime(Asn1GeneralizedTime::decode_content(value, context)?)
            }
            t if t == tag::VISIBLE_STRING => {
                Self::VisibleString(Asn1VisibleString::decode_content(value, context)?)
            }
            t if t == tag::UNIVERSAL_STRING => {
                Self::UniversalString(Asn1UniversalString::decode_content(value, context)?)
            }
            t if t == tag::BMP_STRING => {
                Self::BmpString(Asn1BmpString::decode_content(value, context)?)
            }
            t if t == tag::DATE => Self::Date(Asn1Date::decode_content(value, context)?),
            t if t == tag::TIME_OF_DAY => {
                Self::TimeOfDay(Asn1TimeOfDay::decode_content(value, context)?)
            }
            t if t == tag::DATE_TIME => {
                Self::DateTime(Asn1DateTime::decode_content(value, context)?)
            }
            t if t == tag::DURATION => {
                Self::Duration(Asn1Duration::decode_content(value, context)?)
            }
            t if t == tag::OID_IRI => Self::OidIri(Asn1OidIri::decode_content(value, context)?),
            t if t == tag::RELATIVE_OID_IRI => {
                Self::RelativeOidIri(Asn1RelativeOidIri::decode_content(value, context)?)
            }
            _ => return Ok(Self::Unknown(Asn1Any::primitive(tag, value))),
        })
    }
}

impl DecodeInner for Asn1Object {
    /// Constructed elements become [`Self::Constructed`] whatever their tag;
    /// primitive ones are interpreted by universal tag or kept as [`Self::Unknown`].
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if element.tag() == tag::SEQUENCE {
            let (used, inner) = Asn1SequenceOf::decode_inner(element.raw(), context)?;
            return Ok((used, Self::SequenceOf(inner)));
        }
        if element.tag() == tag::SET {
            let (used, inner) = Asn1SetOf::decode_inner(element.raw(), context)?;
            return Ok((used, Self::SetOf(inner)));
        }
        if element.is_constructed() {
            let (used, inner) = Asn1Constructed::decode_inner(element.raw(), context)?;
            return Ok((used, Self::Constructed(inner)));
        }
        let value = Self::primitive(element.tag(), element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Object {}

impl EncodeContent for Asn1Object {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(inner) => inner.content_len(rules),
            Self::Integer(inner) => inner.content_len(rules),
            Self::BitString(inner) => inner.content_len(rules),
            Self::OctetString(inner) => inner.content_len(rules),
            Self::Null(inner) => inner.content_len(rules),
            Self::Oid(inner) => inner.content_len(rules),
            Self::Real(inner) => inner.content_len(rules),
            Self::Enumerated(inner) => inner.content_len(rules),
            Self::Utf8String(inner) => inner.content_len(rules),
            Self::RelativeOid(inner) => inner.content_len(rules),
            Self::Time(inner) => inner.content_len(rules),
            Self::NumericString(inner) => inner.content_len(rules),
            Self::PrintableString(inner) => inner.content_len(rules),
            Self::Ia5String(inner) => inner.content_len(rules),
            Self::UtcTime(inner) => inner.content_len(rules),
            Self::GeneralizedTime(inner) => inner.content_len(rules),
            Self::VisibleString(inner) => inner.content_len(rules),
            Self::UniversalString(inner) => inner.content_len(rules),
            Self::BmpString(inner) => inner.content_len(rules),
            Self::Date(inner) => inner.content_len(rules),
            Self::TimeOfDay(inner) => inner.content_len(rules),
            Self::DateTime(inner) => inner.content_len(rules),
            Self::Duration(inner) => inner.content_len(rules),
            Self::OidIri(inner) => inner.content_len(rules),
            Self::RelativeOidIri(inner) => inner.content_len(rules),
            Self::SequenceOf(inner) => inner.content_len(rules),
            Self::SetOf(inner) => inner.content_len(rules),
            Self::Constructed(inner) => inner.content_len(rules),
            Self::Unknown(inner) => inner.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(inner) => inner.encode_content(rules, out),
            Self::Integer(inner) => inner.encode_content(rules, out),
            Self::BitString(inner) => inner.encode_content(rules, out),
            Self::OctetString(inner) => inner.encode_content(rules, out),
            Self::Null(inner) => inner.encode_content(rules, out),
            Self::Oid(inner) => inner.encode_content(rules, out),
            Self::Real(inner) => inner.encode_content(rules, out),
            Self::Enumerated(inner) => inner.encode_content(rules, out),
            Self::Utf8String(inner) => inner.encode_content(rules, out),
            Self::RelativeOid(inner) => inner.encode_content(rules, out),
            Self::Time(inner) => inner.encode_content(rules, out),
            Self::NumericString(inner) => inner.encode_content(rules, out),
            Self::PrintableString(inner) => inner.encode_content(rules, out),
            Self::Ia5String(inner) => inner.encode_content(rules, out),
            Self::UtcTime(inner) => inner.encode_content(rules, out),
            Self::GeneralizedTime(inner) => inner.encode_content(rules, out),
            Self::VisibleString(inner) => inner.encode_content(rules, out),
            Self::UniversalString(inner) => inner.encode_content(rules, out),
            Self::BmpString(inner) => inner.encode_content(rules, out),
            Self::Date(inner) => inner.encode_content(rules, out),
            Self::TimeOfDay(inner) => inner.encode_content(rules, out),
            Self::DateTime(inner) => inner.encode_content(rules, out),
            Self::Duration(inner) => inner.encode_content(rules, out),
            Self::OidIri(inner) => inner.encode_content(rules, out),
            Self::RelativeOidIri(inner) => inner.encode_content(rules, out),
            Self::SequenceOf(inner) => inner.encode_content(rules, out),
            Self::SetOf(inner) => inner.encode_content(rules, out),
            Self::Constructed(inner) => inner.encode_content(rules, out),
            Self::Unknown(inner) => inner.encode_content(rules, out),
        }
    }
}

/// Each variant writes its own header, so IMPLICIT re-tagging goes to the leaf.
impl EncodeTagged for Asn1Object {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Integer(inner) => inner.encoded_len_tagged(tag, rules),
            Self::BitString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::OctetString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Null(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Oid(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Real(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Enumerated(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Utf8String(inner) => inner.encoded_len_tagged(tag, rules),
            Self::RelativeOid(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Time(inner) => inner.encoded_len_tagged(tag, rules),
            Self::NumericString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::PrintableString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Ia5String(inner) => inner.encoded_len_tagged(tag, rules),
            Self::UtcTime(inner) => inner.encoded_len_tagged(tag, rules),
            Self::GeneralizedTime(inner) => inner.encoded_len_tagged(tag, rules),
            Self::VisibleString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::UniversalString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::BmpString(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Date(inner) => inner.encoded_len_tagged(tag, rules),
            Self::TimeOfDay(inner) => inner.encoded_len_tagged(tag, rules),
            Self::DateTime(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Duration(inner) => inner.encoded_len_tagged(tag, rules),
            Self::OidIri(inner) => inner.encoded_len_tagged(tag, rules),
            Self::RelativeOidIri(inner) => inner.encoded_len_tagged(tag, rules),
            Self::SequenceOf(inner) => inner.encoded_len_tagged(tag, rules),
            Self::SetOf(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Constructed(inner) => inner.encoded_len_tagged(tag, rules),
            Self::Unknown(inner) => inner.encoded_len_tagged(tag, rules),
        }
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(inner) => inner.encode_tagged(tag, rules, out),
            Self::Integer(inner) => inner.encode_tagged(tag, rules, out),
            Self::BitString(inner) => inner.encode_tagged(tag, rules, out),
            Self::OctetString(inner) => inner.encode_tagged(tag, rules, out),
            Self::Null(inner) => inner.encode_tagged(tag, rules, out),
            Self::Oid(inner) => inner.encode_tagged(tag, rules, out),
            Self::Real(inner) => inner.encode_tagged(tag, rules, out),
            Self::Enumerated(inner) => inner.encode_tagged(tag, rules, out),
            Self::Utf8String(inner) => inner.encode_tagged(tag, rules, out),
            Self::RelativeOid(inner) => inner.encode_tagged(tag, rules, out),
            Self::Time(inner) => inner.encode_tagged(tag, rules, out),
            Self::NumericString(inner) => inner.encode_tagged(tag, rules, out),
            Self::PrintableString(inner) => inner.encode_tagged(tag, rules, out),
            Self::Ia5String(inner) => inner.encode_tagged(tag, rules, out),
            Self::UtcTime(inner) => inner.encode_tagged(tag, rules, out),
            Self::GeneralizedTime(inner) => inner.encode_tagged(tag, rules, out),
            Self::VisibleString(inner) => inner.encode_tagged(tag, rules, out),
            Self::UniversalString(inner) => inner.encode_tagged(tag, rules, out),
            Self::BmpString(inner) => inner.encode_tagged(tag, rules, out),
            Self::Date(inner) => inner.encode_tagged(tag, rules, out),
            Self::TimeOfDay(inner) => inner.encode_tagged(tag, rules, out),
            Self::DateTime(inner) => inner.encode_tagged(tag, rules, out),
            Self::Duration(inner) => inner.encode_tagged(tag, rules, out),
            Self::OidIri(inner) => inner.encode_tagged(tag, rules, out),
            Self::RelativeOidIri(inner) => inner.encode_tagged(tag, rules, out),
            Self::SequenceOf(inner) => inner.encode_tagged(tag, rules, out),
            Self::SetOf(inner) => inner.encode_tagged(tag, rules, out),
            Self::Constructed(inner) => inner.encode_tagged(tag, rules, out),
            Self::Unknown(inner) => inner.encode_tagged(tag, rules, out),
        }
    }
}

/// Every variant knows its own identifier: the leaves their universal tag,
/// `Constructed` and `Unknown` the one they were read or built with.
impl Encode for Asn1Object {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Boolean(inner) => inner.encoded_len(rules),
            Self::Integer(inner) => inner.encoded_len(rules),
            Self::BitString(inner) => inner.encoded_len(rules),
            Self::OctetString(inner) => inner.encoded_len(rules),
            Self::Null(inner) => inner.encoded_len(rules),
            Self::Oid(inner) => inner.encoded_len(rules),
            Self::Real(inner) => inner.encoded_len(rules),
            Self::Enumerated(inner) => inner.encoded_len(rules),
            Self::Utf8String(inner) => inner.encoded_len(rules),
            Self::RelativeOid(inner) => inner.encoded_len(rules),
            Self::Time(inner) => inner.encoded_len(rules),
            Self::NumericString(inner) => inner.encoded_len(rules),
            Self::PrintableString(inner) => inner.encoded_len(rules),
            Self::Ia5String(inner) => inner.encoded_len(rules),
            Self::UtcTime(inner) => inner.encoded_len(rules),
            Self::GeneralizedTime(inner) => inner.encoded_len(rules),
            Self::VisibleString(inner) => inner.encoded_len(rules),
            Self::UniversalString(inner) => inner.encoded_len(rules),
            Self::BmpString(inner) => inner.encoded_len(rules),
            Self::Date(inner) => inner.encoded_len(rules),
            Self::TimeOfDay(inner) => inner.encoded_len(rules),
            Self::DateTime(inner) => inner.encoded_len(rules),
            Self::Duration(inner) => inner.encoded_len(rules),
            Self::OidIri(inner) => inner.encoded_len(rules),
            Self::RelativeOidIri(inner) => inner.encoded_len(rules),
            Self::SequenceOf(inner) => inner.encoded_len(rules),
            Self::SetOf(inner) => inner.encoded_len(rules),
            Self::Constructed(inner) => inner.encoded_len(rules),
            Self::Unknown(inner) => inner.encoded_len(rules),
        }
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Boolean(inner) => inner.encode(rules, out),
            Self::Integer(inner) => inner.encode(rules, out),
            Self::BitString(inner) => inner.encode(rules, out),
            Self::OctetString(inner) => inner.encode(rules, out),
            Self::Null(inner) => inner.encode(rules, out),
            Self::Oid(inner) => inner.encode(rules, out),
            Self::Real(inner) => inner.encode(rules, out),
            Self::Enumerated(inner) => inner.encode(rules, out),
            Self::Utf8String(inner) => inner.encode(rules, out),
            Self::RelativeOid(inner) => inner.encode(rules, out),
            Self::Time(inner) => inner.encode(rules, out),
            Self::NumericString(inner) => inner.encode(rules, out),
            Self::PrintableString(inner) => inner.encode(rules, out),
            Self::Ia5String(inner) => inner.encode(rules, out),
            Self::UtcTime(inner) => inner.encode(rules, out),
            Self::GeneralizedTime(inner) => inner.encode(rules, out),
            Self::VisibleString(inner) => inner.encode(rules, out),
            Self::UniversalString(inner) => inner.encode(rules, out),
            Self::BmpString(inner) => inner.encode(rules, out),
            Self::Date(inner) => inner.encode(rules, out),
            Self::TimeOfDay(inner) => inner.encode(rules, out),
            Self::DateTime(inner) => inner.encode(rules, out),
            Self::Duration(inner) => inner.encode(rules, out),
            Self::OidIri(inner) => inner.encode(rules, out),
            Self::RelativeOidIri(inner) => inner.encode(rules, out),
            Self::SequenceOf(inner) => inner.encode(rules, out),
            Self::SetOf(inner) => inner.encode(rules, out),
            Self::Constructed(inner) => inner.encode(rules, out),
            Self::Unknown(inner) => inner.encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::Asn1Object;
    use crate::{
        Asn1Any, Asn1Boolean, Asn1Error, Asn1Integer, Asn1Utf8String, Decode, DecodingOptions,
        Encode, EncodingOptions,
    };

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn every_element_lands_in_the_variant_of_its_tag() {
        // SEQUENCE { UTF8String "abc", [0] { INTEGER 5 }, TeletexString "x", SET { INTEGER 2, INTEGER 1 } }
        let wire = [
            0x30, 0x15, 0x0C, 0x03, 0x61, 0x62, 0x63, 0xA0, 0x03, 0x02, 0x01, 0x05, 0x14, 0x01,
            0x78, 0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
        ];
        let (used, tree) = Asn1Object::decode(&wire, &options()).unwrap();
        assert_eq!(used, wire.len());
        let Asn1Object::SequenceOf(fields) = &tree else {
            panic!("not a SEQUENCE")
        };
        let [text, tagged, unknown, set] = fields.elements() else {
            panic!("four elements")
        };
        assert_eq!(text, &Asn1Object::from(Asn1Utf8String::new("abc")));
        let Asn1Object::Constructed(tagged) = tagged else {
            panic!("not constructed")
        };
        assert_eq!(tagged.tag(), [0xA0]);
        assert_eq!(tagged.items(), [Asn1Object::from(Asn1Integer::from(5))]);
        assert_eq!(
            unknown,
            &Asn1Object::from(Asn1Any::primitive(&[0x14], b"x"))
        );
        let Asn1Object::SetOf(set) = set else {
            panic!("not a SET")
        };
        assert_eq!(set.members().len(), 2);

        assert_eq!(
            tree.to_string(),
            "SEQUENCE\n  UTF8String \"abc\"\n  [CONTEXT 0]\n    INTEGER 5\n  [UNIVERSAL 20] (1 bytes) 78\n  SET\n    INTEGER 2\n    INTEGER 1\n"
        );
    }

    #[test]
    fn re_encoding_under_der_sorts_the_sets_and_keeps_everything_else() {
        let (_, tree) = Asn1Object::decode(
            &[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01],
            &options(),
        )
        .unwrap();
        assert_eq!(
            tree.encode_to_vec(&der()).unwrap(),
            [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
        let built = Asn1Object::set(vec![
            Asn1Integer::from(2).into(),
            Asn1Integer::from(1).into(),
        ]);
        assert_eq!(built, tree);
    }

    #[test]
    fn the_contents_rules_of_each_type_apply_under_der() {
        let lenient_true = [0x01, 0x01, 0x01];
        assert_eq!(
            Asn1Object::decode(&lenient_true, &options()).unwrap().1,
            Asn1Object::from(Asn1Boolean::from(true))
        );
        assert!(matches!(
            Asn1Object::decode_der(&lenient_true, &options()),
            Err(Asn1Error::NotDer)
        ));
        assert!(matches!(
            Asn1Object::decode(&[0x02, 0x00], &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
