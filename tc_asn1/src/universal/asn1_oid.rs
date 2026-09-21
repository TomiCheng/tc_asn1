//! X.690 §8.19 OBJECT IDENTIFIER, universal tag 6.
//!
//! The arcs are written as base-128 subidentifiers, seven bits per octet
//! with the high bit set on all but the last, the first two arcs merged
//! into one as `first * 40 + second`. There is one encoding per value, so
//! DER adds nothing.

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use super::base128::{is_base128, push_base128, validate_base128};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// An OBJECT IDENTIFIER, kept as its content octets.
///
/// Ordering and hashing are by those octets, which makes the type a map
/// key; the order is not the numeric order of the arcs.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let oid: Asn1Oid = "1.2.840.113549.1.1.1".parse()?;   // rsaEncryption
/// let der = oid.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]);
///
/// let (_, back) = Asn1Oid::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.to_string(), "1.2.840.113549.1.1.1");
/// assert_eq!(back.arcs().collect::<Vec<_>>(), [1, 2, 840, 113549, 1, 1, 1]);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1Oid {
    bytes: Vec<u8>,
}

impl Asn1Oid {
    /// The identifier octets, [`tag::OBJECT_IDENTIFIER`](crate::tag::OBJECT_IDENTIFIER).
    pub const TAG: &'static [u8] = super::tag::OBJECT_IDENTIFIER;

    /// From content octets: empty, a subidentifier starting with `80`, an
    /// incomplete one or one beyond `u64` is an error.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_base128(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// From arcs such as `[1, 2, 840, 113549, 1, 1, 1]`. At least two are
    /// needed; the first is 0, 1 or 2, and under 0 and 1 the second is
    /// below 40, else `MalformedValue`.
    pub fn from_arcs(arcs: &[u64]) -> Result<Self, Asn1Error> {
        let [first, second, rest @ ..] = arcs else {
            return Err(Asn1Error::MalformedValue);
        };
        if *first > 2 || (*first < 2 && *second >= 40) {
            return Err(Asn1Error::MalformedValue);
        }
        let head = first
            .checked_mul(40)
            .and_then(|v| v.checked_add(*second))
            .ok_or(Asn1Error::LengthOverflow)?;

        let mut bytes = Vec::new();
        push_base128(&mut bytes, head);
        for arc in rest {
            push_base128(&mut bytes, *arc);
        }
        Ok(Self { bytes })
    }

    /// The content octets: the base-128 subidentifiers.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The arcs, the first subidentifier split back into two.
    pub fn arcs(&self) -> Arcs<'_> {
        Arcs {
            rest: &self.bytes,
            pending: None,
            first: true,
        }
    }
}

/// The iterator from [`Asn1Oid::arcs`].
pub struct Arcs<'a> {
    rest: &'a [u8],
    pending: Option<u64>,
    first: bool,
}

impl Iterator for Arcs<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if let Some(second) = self.pending.take() {
            return Some(second);
        }
        if self.rest.is_empty() {
            return None;
        }

        let mut value: u64 = 0;
        let mut consumed = 0;
        for byte in self.rest {
            consumed += 1;
            value = (value << 7) | u64::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                break;
            }
        }
        let is_first = self.first;
        self.first = false;
        self.rest = &self.rest[consumed..];

        if is_first {
            let (first, second) = match value {
                0..=39 => (0, value),
                40..=79 => (1, value - 40),
                _ => (2, value - 80),
            };
            self.pending = Some(second);
            Some(first)
        } else {
            Some(value)
        }
    }
}

/// An OID fixed at compile time, with its dotted form and a name: the
/// building block of constant tables such as attribute types or key
/// purposes. Comparing one against a decoded [`Asn1Oid`] works on the DER
/// content octets and allocates nothing.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Oid, NamedOid};
///
/// struct KeyPurpose;
/// impl KeyPurpose {
///     pub const SERVER_AUTH: NamedOid =
///         NamedOid::new(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01], "1.3.6.1.5.5.7.3.1", "serverAuth");
///     pub const CLIENT_AUTH: NamedOid =
///         NamedOid::new(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02], "1.3.6.1.5.5.7.3.2", "clientAuth");
///     pub const ALL: &[NamedOid] = &[Self::SERVER_AUTH, Self::CLIENT_AUTH];
/// }
///
/// let decoded: Asn1Oid = "1.3.6.1.5.5.7.3.2".parse()?;
/// assert_eq!(NamedOid::find(KeyPurpose::ALL, &decoded), Some(KeyPurpose::CLIENT_AUTH));
/// assert!(KeyPurpose::CLIENT_AUTH == decoded);
/// assert_eq!(KeyPurpose::CLIENT_AUTH.to_string(), "clientAuth");
/// assert_eq!(KeyPurpose::SERVER_AUTH.oid().to_string(), "1.3.6.1.5.5.7.3.1");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NamedOid {
    der: &'static [u8],
    dotted: &'static str,
    name: &'static str,
}

impl NamedOid {
    /// `der` is the content octets of the OBJECT IDENTIFIER. Panics if they
    /// are not a valid encoding, which in a `const` is a compile error.
    /// The dotted form is not checked against them.
    pub const fn new(der: &'static [u8], dotted: &'static str, name: &'static str) -> Self {
        assert!(
            is_base128(der),
            "NamedOid: not the content octets of an OBJECT IDENTIFIER"
        );
        Self { der, dotted, name }
    }

    /// The OID as an owned [`Asn1Oid`].
    pub fn oid(&self) -> Asn1Oid {
        Asn1Oid {
            bytes: self.der.to_vec(),
        }
    }

    /// The DER content octets.
    pub const fn as_der(&self) -> &'static [u8] {
        self.der
    }

    /// The OID in dotted form.
    pub const fn dotted(&self) -> &'static str {
        self.dotted
    }

    /// The name, such as `rsaEncryption`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The entry of `table` with this OID, if any.
    /// Variable time; for public values.
    pub fn find(table: &[Self], oid: &Asn1Oid) -> Option<Self> {
        table
            .iter()
            .copied()
            .find(|entry| entry.der == oid.as_bytes())
    }

    /// The entry of `table` with this name, ASCII case ignored.
    /// Variable time; for public values.
    pub fn find_by_name(table: &[Self], name: &str) -> Option<Self> {
        table
            .iter()
            .copied()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
    }
}

impl PartialEq<Asn1Oid> for NamedOid {
    fn eq(&self, other: &Asn1Oid) -> bool {
        self.der == other.as_bytes()
    }
}

impl PartialEq<NamedOid> for Asn1Oid {
    fn eq(&self, other: &NamedOid) -> bool {
        other == self
    }
}

impl From<NamedOid> for Asn1Oid {
    fn from(value: NamedOid) -> Self {
        value.oid()
    }
}

/// The name.
impl fmt::Display for NamedOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

/// The dotted form, `1.2.840.113549.1.1.1`.
impl fmt::Display for Asn1Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, arc) in self.arcs().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl FromStr for Asn1Oid {
    type Err = Asn1Error;

    /// The dotted form; anything but decimal arcs separated by single dots
    /// is `MalformedValue`.
    fn from_str(s: &str) -> Result<Self, Asn1Error> {
        let mut arcs = Vec::new();
        for part in s.split('.') {
            // an empty part, a non-digit or a value over u64 is bad input
            let arc = part.parse::<u64>().map_err(|_| Asn1Error::MalformedValue)?;
            arcs.push(arc);
        }
        Self::from_arcs(&arcs)
    }
}

impl DecodeInner for Asn1Oid {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Oid {}
impl Tagged for Asn1Oid {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Oid {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl EncodeContent for Asn1Oid {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.bytes.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.bytes.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

impl EncodeTagged for Asn1Oid {}

impl Encode for Asn1Oid {
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

    use super::{Asn1Oid, NamedOid};
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_first_two_arcs_share_a_subidentifier() {
        for (text, contents) in [
            ("0.0", &[0x00][..]),
            ("1.39", &[0x4F]),
            ("2.5.4.3", &[0x55, 0x04, 0x03]),
            ("2.48", &[0x81, 0x00]),
            ("2.999", &[0x88, 0x37]),
            ("1.2.840.113549", &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]),
        ] {
            let oid: Asn1Oid = text.parse().unwrap();
            assert_eq!(oid.as_bytes(), contents, "{text}");
            assert_eq!(oid.to_string(), text);
            assert_eq!(Asn1Oid::from_der_bytes(contents).unwrap(), oid);
        }
    }

    #[test]
    fn arcs_outside_the_first_two_rules_are_rejected() {
        for arcs in [&[][..], &[1], &[3, 1], &[0, 40], &[1, 40]] {
            assert!(matches!(
                Asn1Oid::from_arcs(arcs),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(Asn1Oid::from_arcs(&[2, 40]).is_ok());
        assert!(matches!(
            Asn1Oid::from_arcs(&[2, u64::MAX]),
            Err(Asn1Error::LengthOverflow)
        ));
    }

    #[test]
    fn the_text_form_must_be_dotted_decimals() {
        for text in [
            "",
            "1",
            "1..2",
            "1.2.",
            "a.b",
            "1.2.99999999999999999999",
            "1. 2",
        ] {
            assert!(
                matches!(text.parse::<Asn1Oid>(), Err(Asn1Error::MalformedValue)),
                "{text:?}"
            );
        }
    }

    #[test]
    fn bad_subidentifiers_are_rejected_on_decode() {
        let wire = [0x06, 0x03, 0x55, 0x04, 0x03];
        let (used, oid) = Asn1Oid::decode(&wire, &options()).unwrap();
        assert_eq!((used, oid.to_string().as_str()), (5, "2.5.4.3"));
        assert_eq!(oid.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        for wire in [
            &[0x06, 0x00][..],         // no arcs
            &[0x06, 0x02, 0x80, 0x01], // a subidentifier starting with 80
            &[0x06, 0x02, 0x55, 0x84], // an incomplete subidentifier
        ] {
            assert!(matches!(
                Asn1Oid::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
        let mut huge = Vec::from([0x06, 0x0B, 0x55]);
        huge.extend_from_slice(&[0xFF; 9]);
        huge.push(0x7F); // ten octets: 70 bits
        assert!(matches!(
            Asn1Oid::decode(&huge, &options()),
            Err(Asn1Error::LengthOverflow)
        ));
        assert!(matches!(
            Asn1Oid::decode(&[0x0D, 0x01, 0x01], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    const CN: NamedOid = NamedOid::new(&[0x55, 0x04, 0x03], "2.5.4.3", "CN");
    const O: NamedOid = NamedOid::new(&[0x55, 0x04, 0x0A], "2.5.4.10", "O");
    const TABLE: &[NamedOid] = &[CN, O];

    #[test]
    fn a_named_oid_compares_with_a_decoded_one_and_is_found_by_either_key() {
        let decoded: Asn1Oid = "2.5.4.10".parse().unwrap();
        assert!(O == decoded);
        assert!(decoded == O);
        assert!(CN != decoded);
        assert_eq!(NamedOid::find(TABLE, &decoded), Some(O));
        assert_eq!(NamedOid::find(TABLE, &"2.5.4.4".parse().unwrap()), None);
        assert_eq!(NamedOid::find_by_name(TABLE, "cn"), Some(CN));
        assert_eq!(NamedOid::find_by_name(TABLE, "UID"), None);
        assert_eq!(Asn1Oid::from(CN), "2.5.4.3".parse::<Asn1Oid>().unwrap());
        assert_eq!(
            (CN.to_string(), CN.dotted(), CN.as_der()),
            ("CN".to_string(), "2.5.4.3", &[0x55, 0x04, 0x03][..])
        );
    }

    #[test]
    #[should_panic(expected = "not the content octets")]
    fn a_named_oid_with_bad_octets_panics_when_built() {
        NamedOid::new(&[0x80], "0.0", "bad");
    }
}
