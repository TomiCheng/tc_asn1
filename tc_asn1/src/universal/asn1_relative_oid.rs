//! X.690 §8.20 RELATIVE-OID, universal tag 13.
//!
//! The arcs of an OBJECT IDENTIFIER relative to some base, in the same
//! base-128 form but without the merging of the first two: every arc is
//! its own subidentifier and one arc is enough.

use alloc::vec::Vec;
use core::{fmt, str::FromStr};

use super::base128::{push_base128, validate_base128};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// A RELATIVE-OID, kept as its content octets.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1RelativeOid, Encode, EncodingOptions};
///
/// let relative: Asn1RelativeOid = "8571.3.2".parse()?;
/// let der = relative.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x0D, 0x04, 0xC2, 0x7B, 0x03, 0x02]);
/// assert_eq!(relative.arcs().collect::<Vec<_>>(), [8571, 3, 2]);
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1RelativeOid {
    bytes: Vec<u8>,
}

impl Asn1RelativeOid {
    pub const TAG: &'static [u8] = super::tag::RELATIVE_OID;

    /// From content octets, checked as for an OBJECT IDENTIFIER.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_base128(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// From arcs, at least one; none is `MalformedValue`.
    pub fn from_arcs(arcs: &[u64]) -> Result<Self, Asn1Error> {
        if arcs.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut bytes = Vec::new();
        for arc in arcs {
            push_base128(&mut bytes, *arc);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn arcs(&self) -> impl Iterator<Item = u64> + '_ {
        self.bytes
            .split_inclusive(|byte| byte & 0x80 == 0)
            .map(|bytes| {
                bytes
                    .iter()
                    .fold(0_u64, |n, b| (n << 7) | u64::from(b & 0x7F))
            })
    }
}
impl FromStr for Asn1RelativeOid {
    type Err = Asn1Error;

    /// The dotted form: an empty or non-decimal part is `MalformedValue`,
    /// an arc over `u64` is `LengthOverflow`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let arcs = text
            .split('.')
            .map(|part| {
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Asn1Error::MalformedValue);
                }
                part.parse::<u64>().map_err(|_| Asn1Error::LengthOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_arcs(&arcs)
    }
}
/// The dotted form.
impl fmt::Display for Asn1RelativeOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.arcs().enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}
impl DecodeInner for Asn1RelativeOid {
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
impl Decode for Asn1RelativeOid {}
impl Tagged for Asn1RelativeOid {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1RelativeOid {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl EncodeContent for Asn1RelativeOid {
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

impl EncodeTagged for Asn1RelativeOid {}

impl Encode for Asn1RelativeOid {
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

    use super::Asn1RelativeOid;
    use crate::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn every_arc_is_its_own_subidentifier_and_one_is_enough() {
        for (text, contents) in [
            ("0", &[0x00][..]),
            ("999", &[0x87, 0x67]),
            ("1.2.999", &[0x01, 0x02, 0x87, 0x67]),
            ("8571.3.2", &[0xC2, 0x7B, 0x03, 0x02]),
        ] {
            let relative: Asn1RelativeOid = text.parse().unwrap();
            assert_eq!(relative.as_bytes(), contents, "{text}");
            assert_eq!(relative.to_string(), text);
            assert_eq!(Asn1RelativeOid::from_der_bytes(contents).unwrap(), relative);
        }
    }

    #[test]
    fn it_round_trips_under_tag_0d_and_rejects_bad_contents() {
        let wire = [0x0D, 0x04, 0x01, 0x02, 0x87, 0x67];
        let (used, relative) = Asn1RelativeOid::decode(&wire, &options()).unwrap();
        assert_eq!((used, relative.to_string().as_str()), (6, "1.2.999"));
        assert_eq!(relative.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        for wire in [&[0x0D, 0x00][..], &[0x0D, 0x01, 0x80], &[0x0D, 0x01, 0x87]] {
            assert!(matches!(
                Asn1RelativeOid::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            Asn1RelativeOid::decode(&[0x06, 0x01, 0x01], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn the_text_form_needs_at_least_one_decimal_arc() {
        assert!(matches!(
            Asn1RelativeOid::from_arcs(&[]),
            Err(Asn1Error::MalformedValue)
        ));
        for text in ["", "1..2", "1.", "a"] {
            assert!(
                matches!(
                    text.parse::<Asn1RelativeOid>(),
                    Err(Asn1Error::MalformedValue)
                ),
                "{text:?}"
            );
        }
        assert!(matches!(
            "99999999999999999999".parse::<Asn1RelativeOid>(),
            Err(Asn1Error::LengthOverflow)
        ));
    }
}
