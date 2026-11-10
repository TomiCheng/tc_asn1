//! RFC 5280 §4.2.1.9 `BasicConstraints`, the value of extension 2.5.29.19.
//!
//! ```text
//! BasicConstraints ::= SEQUENCE {
//!     cA                 BOOLEAN DEFAULT FALSE,
//!     pathLenConstraint  INTEGER (0..MAX) OPTIONAL }
//! ```
//!
//! Whether the subject is a CA and, if so, how many CA certificates may
//! follow it in a path (0: it may only issue end-entity certificates). The
//! path length is meaningful only for a CA and RFC 5280 forbids it otherwise,
//! which is enforced when building and decoding.

use core::fmt;

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// CA or end entity, with the optional path length limit.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::BasicConstraints;
///
/// // An intermediate CA that may only issue end-entity certificates.
/// let bc = BasicConstraints::ca(Some(0));
/// assert!(bc.is_ca());
/// println!("{bc}");   // CA, pathLenConstraint 0
///
/// let der = bc.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = BasicConstraints::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.path_len_constraint(), Some(0));
///
/// // An end entity has neither flag nor path length.
/// let leaf = BasicConstraints::end_entity();
/// assert!(!leaf.is_ca());
/// assert_eq!(leaf.path_len_constraint(), None);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BasicConstraints {
    ca: bool,
    path_len_constraint: Option<u32>,
}

impl BasicConstraints {
    /// Not a CA; no path length.
    pub fn end_entity() -> Self {
        Self {
            ca: false,
            path_len_constraint: None,
        }
    }

    /// A CA, limited to `path_len_constraint` further CA certificates below
    /// it, or unlimited with `None`.
    pub fn ca(path_len_constraint: Option<u32>) -> Self {
        Self {
            ca: true,
            path_len_constraint,
        }
    }

    /// Whether the subject is a CA.
    pub fn is_ca(&self) -> bool {
        self.ca
    }

    /// Present only for a CA.
    pub fn path_len_constraint(&self) -> Option<u32> {
        self.path_len_constraint
    }
}

/// `end entity`, `CA` or `CA, pathLenConstraint N`.
impl fmt::Display for BasicConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.ca {
            return f.write_str("end entity");
        }
        f.write_str("CA")?;
        if let Some(n) = self.path_len_constraint {
            write!(f, ", pathLenConstraint {n}")?;
        }
        Ok(())
    }
}

impl DecodeInner for BasicConstraints {
    /// `cA` is taken only when a BOOLEAN comes next; an explicit FALSE is
    /// `NotDer` under DER. A path length on a non-CA, a negative one or one
    /// beyond `u32` is `MalformedValue`. Variable time: branches only on the
    /// encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let ca = children.get_default(Asn1Boolean::from(false))?.is_true();
        let path_len_constraint = children
            .get_opt::<Asn1Integer>()?
            .map(|n| u32::try_from(&n).map_err(|_| Asn1Error::MalformedValue))
            .transpose()?;
        children.end()?;
        if !ca && path_len_constraint.is_some() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((
            element.total_len(),
            Self {
                ca,
                path_len_constraint,
            },
        ))
    }
}

impl Decode for BasicConstraints {}

impl Tagged for BasicConstraints {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for BasicConstraints {
    /// `cA` is written only when TRUE: the DEFAULT is omitted under every
    /// rule set. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let ca = if self.ca {
            Asn1Boolean::from(true).encoded_len(rules)
        } else {
            0
        };
        ca + self
            .path_len_constraint
            .map_or(0, |n| Asn1Integer::from(n).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if self.ca {
            at += Asn1Boolean::from(true).encode(rules, out)?;
        }
        if let Some(n) = self.path_len_constraint {
            at += Asn1Integer::from(n).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for BasicConstraints {}

impl Encode for BasicConstraints {
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

    use tc_asn1::{Asn1Error, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};

    use super::BasicConstraints;
    use crate::ext::{Extension, ExtensionId};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn the_three_shapes_round_trip() {
        let cases: [(BasicConstraints, &[u8], &str); 4] = [
            (BasicConstraints::end_entity(), b"\x30\x00", "end entity"),
            (BasicConstraints::ca(None), b"\x30\x03\x01\x01\xff", "CA"),
            (
                BasicConstraints::ca(Some(0)),
                b"\x30\x06\x01\x01\xff\x02\x01\x00",
                "CA, pathLenConstraint 0",
            ),
            (
                BasicConstraints::ca(Some(300)),
                b"\x30\x07\x01\x01\xff\x02\x02\x01\x2c",
                "CA, pathLenConstraint 300",
            ),
        ];
        for (bc, wire, text) in cases {
            assert_eq!(bc.encode_to_vec(&der()).unwrap(), wire, "{text}");
            let (used, decoded) = BasicConstraints::decode(wire, &options()).unwrap();
            assert_eq!((used, decoded), (wire.len(), bc));
            assert_eq!(decoded.to_string(), text);
            assert_eq!(
                BasicConstraints::decode_der(wire, &options()).unwrap().1,
                bc
            );
        }
    }

    #[test]
    fn an_explicit_false_is_ber_only_and_a_ber_true_is_normalized() {
        let (_, bc) = BasicConstraints::decode(b"\x30\x03\x01\x01\x00", &options()).unwrap();
        assert_eq!(bc, BasicConstraints::end_entity());
        assert!(matches!(
            BasicConstraints::decode_der(b"\x30\x03\x01\x01\x00", &options()),
            Err(Asn1Error::NotDer)
        ));
        let (_, bc) = BasicConstraints::decode(b"\x30\x03\x01\x01\x01", &options()).unwrap();
        assert_eq!(bc, BasicConstraints::ca(None));
        assert_eq!(bc.encode_to_vec(&der()).unwrap(), b"\x30\x03\x01\x01\xff");
    }

    #[test]
    fn a_path_length_without_ca_negative_or_huge_is_rejected() {
        for wire in [
            &b"\x30\x03\x02\x01\x00"[..],        // pathLen on an end entity
            b"\x30\x06\x01\x01\x00\x02\x01\x00", // pathLen with explicit FALSE
            b"\x30\x06\x01\x01\xff\x02\x01\xff", // -1
            b"\x30\x0a\x01\x01\xff\x02\x05\x01\x00\x00\x00\x00", // 2^32
        ] {
            assert!(matches!(
                BasicConstraints::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn wrong_or_extra_fields_are_rejected() {
        for wire in [
            &b"\x30\x05\x01\x01\xff\x05\x00"[..], // NULL where nothing may follow
            b"\x30\x09\x01\x01\xff\x02\x01\x00\x02\x01\x01", // two path lengths
        ] {
            assert!(matches!(
                BasicConstraints::decode(wire, &options()),
                Err(Asn1Error::TrailingData)
            ));
        }
        assert!(matches!(
            BasicConstraints::decode(b"\x31\x00", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn it_travels_inside_a_critical_extension() {
        let bc = BasicConstraints::ca(Some(1));
        let extension = Extension::new(
            ExtensionId::BASIC_CONSTRAINTS,
            true,
            &bc.encode_to_vec(&der()).unwrap(),
        );
        assert_eq!(extension.extn_id().to_string(), "2.5.29.19");
        let (_, back) =
            Extension::decode(&extension.encode_to_vec(&der()).unwrap(), &options()).unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            back.extn_value_as::<BasicConstraints>(&mut context)
                .unwrap(),
            bc
        );
    }
}
