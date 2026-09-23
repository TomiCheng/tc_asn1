//! X.501 `RelativeDistinguishedName`, as profiled by RFC 5280 §4.1.2.4.
//!
//! ```text
//! RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
//! ```
//!
//! One level of a distinguished name. Nearly always a single attribute; a
//! multivalued RDN groups several attributes that identify the entry only
//! together. Order carries no meaning, so DER and CER write the members
//! sorted by their encodings. X.501 also wants the attribute types within
//! one RDN to be distinct; that is a profile check and is not enforced here.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SetOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::{AttributeType, AttributeTypeAndValue, AttributeValue};

/// A non-empty set of attributes making up one level of a name.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x500::{AttributeTypeAndValue, DirectoryString, RelativeDistinguishedName};
///
/// // The usual single-valued RDN, CN=Alice.
/// let rdn = RelativeDistinguishedName::single(AttributeTypeAndValue::new(
///     "2.5.4.3".parse()?,
///     DirectoryString::new("Alice")?,
/// ));
///
/// // Encode it as DER and read it back.
/// let der = rdn.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, decoded) = RelativeDistinguishedName::decode(&der, &DecodingOptions::default())?;
/// assert!(!decoded.is_multi_valued());
/// println!("{decoded}");   // CN=Alice
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RelativeDistinguishedName {
    attributes: Asn1SetOf<AttributeTypeAndValue>,
}

impl RelativeDistinguishedName {
    /// An empty set violates `SIZE (1..MAX)` and is `MalformedValue`.
    pub fn new(attributes: Vec<AttributeTypeAndValue>) -> Result<Self, Asn1Error> {
        if attributes.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            attributes: Asn1SetOf::new(attributes),
        })
    }

    /// The common case: one attribute.
    pub fn single(attribute: AttributeTypeAndValue) -> Self {
        Self {
            attributes: Asn1SetOf::new(Vec::from([attribute])),
        }
    }

    /// The attributes in construction or wire order, never empty.
    pub fn attributes(&self) -> &[AttributeTypeAndValue] {
        self.attributes.members()
    }

    /// Whether there is more than one attribute, as in `CN=Alice+UID=alice`.
    pub fn is_multi_valued(&self) -> bool {
        self.attributes.members().len() > 1
    }

    /// The same attributes under [`AttributeTypeAndValue::equivalent`], in
    /// any order, each paired with a different member of `other`. Variable
    /// time; for public values.
    pub fn equivalent(&self, other: &Self) -> bool {
        let (a, b) = (self.attributes(), other.attributes());
        if a.len() != b.len() {
            return false;
        }
        // Each member of `a` takes its match out of play. The first match
        // will do: `equivalent` is an equivalence relation, so no other
        // choice could leave a better pairing for the rest.
        let mut unmatched: Vec<&AttributeTypeAndValue> = b.iter().collect();
        a.iter()
            .all(|x| match unmatched.iter().position(|y| x.equivalent(y)) {
                Some(i) => {
                    unmatched.swap_remove(i);
                    true
                }
                None => false,
            })
    }
}

/// `type=value` pairs joined with `+`, in stored order, as in RFC 4514. A
/// type [`AttributeType`] knows is written by its short name and a text
/// value escaped as in §2.4. Anything else is written as `#` followed by the
/// hex of the value's DER, as §2.4 requires or allows: every value of a type
/// written as a dotted OID, a TeletexString, an empty DirectoryString, and
/// any value that is not a string. [`Name`](crate::Name) parses this form
/// back.
impl fmt::Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, attribute) in self.attributes().iter().enumerate() {
            if i > 0 {
                f.write_str("+")?;
            }
            let Some(known) = AttributeType::from_oid(attribute.attribute_type()) else {
                // §2.4: a type in dotted form always takes the `#` form.
                write!(f, "{}=", attribute.attribute_type())?;
                write_hex(f, attribute.value())?;
                continue;
            };
            write!(f, "{known}=")?;
            match attribute.value() {
                AttributeValue::DirectoryString(s) => match s.as_str() {
                    Some(text) if !text.is_empty() => write_escaped(f, text),
                    // A TeletexString has no text form, and an empty text
                    // would not parse back as a DirectoryString.
                    _ => write_hex(f, s),
                },
                AttributeValue::Ia5String(s) => write_escaped(f, s.as_str()),
                AttributeValue::Other(object) => write_hex(f, object),
            }?;
        }
        Ok(())
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, value: &impl Encode) -> fmt::Result {
    f.write_str("#")?;
    let der = value
        .encode_to_vec(&EncodingOptions::DER)
        .map_err(|_| fmt::Error)?;
    for byte in der {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// RFC 4514 §2.4: `"`, `+`, `,`, `;`, `<`, `>` and `\` are escaped anywhere,
/// `#` at the start, a space at the start or the end, NUL as `\00`.
fn write_escaped(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    let last = text.chars().count().saturating_sub(1);
    for (i, c) in text.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => write!(f, "\\{c}")?,
            '#' if i == 0 => f.write_str("\\#")?,
            ' ' if i == 0 || i == last => f.write_str("\\ ")?,
            '\0' => f.write_str("\\00")?,
            _ => write!(f, "{c}")?,
        }
    }
    Ok(())
}

impl DecodeContent for RelativeDistinguishedName {
    /// Reads the attributes of an IMPLICIT RDN, without the outer tag and length.
    /// An empty set returns [`Asn1Error::MalformedValue`]. Members are kept
    /// in wire order.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let attributes = Asn1SetOf::decode_content(value, context)?;
        if attributes.members().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { attributes })
    }
}

impl DecodeInner for RelativeDistinguishedName {
    /// An empty SET is `MalformedValue`. Variable time: branches only on the structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for RelativeDistinguishedName {}

impl Tagged for RelativeDistinguishedName {
    const TAG: &'static [u8] = Asn1SetOf::<AttributeTypeAndValue>::TAG;
}

impl EncodeContent for RelativeDistinguishedName {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.attributes.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.attributes.encode_content(rules, out)
    }
}

impl EncodeTagged for RelativeDistinguishedName {}

impl Encode for RelativeDistinguishedName {
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

    use tc_asn1::{
        Asn1Error, Asn1Integer, Asn1Object, Asn1Ref, Decode, DecodingContext, DecodingOptions,
        Encode, EncodingOptions, Implicit,
    };

    use super::RelativeDistinguishedName;
    use crate::{AttributeTypeAndValue, DirectoryString};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn cn(text: &str) -> AttributeTypeAndValue {
        AttributeTypeAndValue::new(
            "2.5.4.3".parse().unwrap(),
            DirectoryString::new(text).unwrap(),
        )
    }

    fn serial_number(text: &str) -> AttributeTypeAndValue {
        AttributeTypeAndValue::new(
            "2.5.4.5".parse().unwrap(),
            DirectoryString::new(text).unwrap(),
        )
    }

    /// { CN=Alice }
    const SINGLE: &[u8] = b"\x31\x0e\x30\x0c\x06\x03\x55\x04\x03\x13\x05Alice";
    /// { serialNumber=123 + CN=Alice }, in DER order (shorter encoding first).
    const MULTI: &[u8] =
        b"\x31\x1a\x30\x0a\x06\x03\x55\x04\x05\x13\x03123\x30\x0c\x06\x03\x55\x04\x03\x13\x05Alice";

    #[test]
    fn a_single_valued_rdn_round_trips() {
        let rdn = RelativeDistinguishedName::single(cn("Alice"));
        assert!(!rdn.is_multi_valued());
        assert_eq!(rdn.encode_to_vec(&der()).unwrap(), SINGLE);
        let (used, decoded) = RelativeDistinguishedName::decode(SINGLE, &options()).unwrap();
        assert_eq!((used, &decoded), (SINGLE.len(), &rdn));
        assert_eq!(decoded.attributes().len(), 1);
        assert_eq!(decoded.to_string(), "CN=Alice");
    }

    #[test]
    fn an_implicit_rdn_preserves_attributes_in_wire_order() {
        let rdn =
            RelativeDistinguishedName::new(Vec::from([cn("Alice"), serial_number("123")])).unwrap();
        for rules in [EncodingOptions::BER, EncodingOptions::DER] {
            let wire = Implicit::new(&[0xA1], &rdn).encode_to_vec(&rules).unwrap();
            assert_eq!(wire[0], 0xA1);
            let mut context = DecodingContext::new(options());
            let mut fields = tc_asn1::Children::from_contents(&wire, &mut context).unwrap();
            let decoded = fields
                .get_implicit::<RelativeDistinguishedName>([0xA1])
                .unwrap();
            assert_eq!(decoded, rdn);
            if rules == EncodingOptions::BER {
                assert_eq!(decoded.attributes()[0], cn("Alice"));
            } else {
                assert_eq!(decoded.attributes()[0], serial_number("123"));
            }
            fields.end().unwrap();
        }
    }

    #[test]
    fn an_empty_implicit_rdn_is_rejected() {
        let mut context = DecodingContext::new(options());
        let sequence = Asn1Ref::parse(b"\x30\x02\xa1\x00", &mut context).unwrap();
        let mut fields = sequence.children(&mut context).unwrap();
        assert!(matches!(
            fields.get_implicit::<RelativeDistinguishedName>([0xA1]),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_multi_valued_rdn_is_written_sorted_under_der_whatever_its_stored_order() {
        let a =
            RelativeDistinguishedName::new(Vec::from([cn("Alice"), serial_number("123")])).unwrap();
        let b =
            RelativeDistinguishedName::new(Vec::from([serial_number("123"), cn("Alice")])).unwrap();
        assert!(a.is_multi_valued());
        assert_eq!(a.encode_to_vec(&der()).unwrap(), MULTI);
        assert_eq!(b.encode_to_vec(&der()).unwrap(), MULTI);
        assert_eq!(a, b); // the same SET, whatever the stored order
        let ber = EncodingOptions::BER;
        assert_ne!(a.encode_to_vec(&ber).unwrap(), MULTI); // BER writes the stored order

        let (_, decoded) = RelativeDistinguishedName::decode(MULTI, &options()).unwrap();
        assert_eq!(decoded, a);
        assert_eq!(decoded.attributes()[0], serial_number("123")); // wire order is kept
        assert_eq!(decoded.to_string(), "serialNumber=123+CN=Alice");
    }

    #[test]
    fn equivalence_ignores_order_and_string_type() {
        let a =
            RelativeDistinguishedName::new(Vec::from([cn("Alice"), serial_number("123")])).unwrap();
        let b =
            RelativeDistinguishedName::new(Vec::from([serial_number("123"), cn("ALICE")])).unwrap();
        assert_ne!(a, b);
        assert!(a.equivalent(&b));
        assert!(!a.equivalent(&RelativeDistinguishedName::single(cn("Alice"))));
        assert!(
            !a.equivalent(
                &RelativeDistinguishedName::new(Vec::from([cn("Alice"), serial_number("124")]))
                    .unwrap()
            )
        );
    }

    #[test]
    fn equivalence_pairs_each_attribute_with_a_different_one_on_the_other_side() {
        // Both of `a`'s members match `b`'s CN; that must not cover for
        // `b`'s serialNumber, which nothing in `a` matches.
        let a = RelativeDistinguishedName::new(Vec::from([cn("alice"), cn("ALICE")])).unwrap();
        let b =
            RelativeDistinguishedName::new(Vec::from([cn("Alice"), serial_number("123")])).unwrap();
        assert!(!a.equivalent(&b));
        assert!(!b.equivalent(&a));
        let c = RelativeDistinguishedName::new(Vec::from([cn("Alice"), cn("alice")])).unwrap();
        assert!(a.equivalent(&c));
        assert!(c.equivalent(&a));
    }

    #[test]
    fn an_empty_set_is_rejected_when_built_or_decoded() {
        assert!(matches!(
            RelativeDistinguishedName::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            RelativeDistinguishedName::decode(b"\x31\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_sequence_in_place_of_the_set_is_rejected() {
        let mut as_sequence: Vec<u8> = SINGLE.to_vec();
        as_sequence[0] = 0x30;
        assert!(matches!(
            RelativeDistinguishedName::decode(&as_sequence, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn display_uses_short_names_escapes_special_characters_and_hex_encodes_other_values() {
        let rdn = RelativeDistinguishedName::single(cn(" a,b+c\\d# "));
        assert_eq!(rdn.to_string(), "CN=\\ a\\,b\\+c\\\\d#\\ ");
        let rdn = RelativeDistinguishedName::single(cn("#x"));
        assert_eq!(rdn.to_string(), "CN=\\#x");
        let rdn = RelativeDistinguishedName::single(AttributeTypeAndValue::new(
            "1.2.3.4".parse().unwrap(),
            Asn1Object::from(Asn1Integer::from(42)),
        ));
        assert_eq!(rdn.to_string(), "1.2.3.4=#02012a");
    }

    #[test]
    fn display_hex_encodes_every_value_of_an_unknown_type_and_empty_strings() {
        use tc_asn1::Asn1Utf8String;

        use crate::Name;

        let unknown = RelativeDistinguishedName::single(AttributeTypeAndValue::new(
            "1.2.3.4".parse().unwrap(),
            DirectoryString::Utf8String(Asn1Utf8String::new("foo")),
        ));
        let (_, empty) = RelativeDistinguishedName::decode(
            b"\x31\x09\x30\x07\x06\x03\x55\x04\x03\x13\x00",
            &options(),
        )
        .unwrap();
        for (rdn, text) in [(unknown, "1.2.3.4=#0c03666f6f"), (empty, "CN=#1300")] {
            assert_eq!(rdn.to_string(), text);
            // The # form keeps the string type, so the text parses back to
            // the same DER.
            let name: Name = text.parse().unwrap();
            assert_eq!(name.rdns(), [rdn]);
        }
    }
}
