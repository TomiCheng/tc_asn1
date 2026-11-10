//! RFC 5280 §4.2.1.13 and §4.2.1.15 CRL distribution point lists.
//!
//! ```text
//! CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//! ```
//!
//! The cRLDistributionPoints and freshestCRL extensions share this syntax.
//! The surrounding extension OID determines whether the locations provide
//! complete CRLs or delta CRLs.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::crl::DistributionPoint;

/// A non-empty list of CRL distribution points, kept in wire order.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{
///     crl::{CrlDistributionPoints, DistributionPoint},
///     name::{GeneralName, GeneralNames},
/// };
///
/// let names = GeneralNames::new(vec![GeneralName::uri("http://example.com/ca.crl")?])?;
/// let points = CrlDistributionPoints::new(vec![
///     DistributionPoint::new(Some(names.into()), None, None)?,
/// ])?;
/// let der = points.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(CrlDistributionPoints::decode_der(&der, &DecodingOptions::default())?.1, points);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlDistributionPoints {
    points: Asn1SequenceOf<DistributionPoint>,
}

impl CrlDistributionPoints {
    /// Creates a list. An empty list returns [`Asn1Error::MalformedValue`].
    pub fn new(points: Vec<DistributionPoint>) -> Result<Self, Asn1Error> {
        if points.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            points: Asn1SequenceOf::new(points),
        })
    }

    /// Returns the distribution points in wire order, never empty.
    pub fn points(&self) -> &[DistributionPoint] {
        self.points.elements()
    }
}

/// Displays the points separated by `, `.
impl fmt::Display for CrlDistributionPoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, point) in self.points().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{point}")?;
        }
        Ok(())
    }
}

impl DecodeContent for CrlDistributionPoints {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let points = Asn1SequenceOf::<DistributionPoint>::decode_content(value, context)?;
        Self::new(points.into_elements())
    }
}

impl DecodeInner for CrlDistributionPoints {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for CrlDistributionPoints {}

impl Tagged for CrlDistributionPoints {
    const TAG: &'static [u8] = Asn1SequenceOf::<DistributionPoint>::TAG;
}

impl EncodeContent for CrlDistributionPoints {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.points.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.points.encode_content(rules, out)
    }
}

impl EncodeTagged for CrlDistributionPoints {}

impl Encode for CrlDistributionPoints {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::CrlDistributionPoints;
    use crate::{
        crl::DistributionPoint,
        name::{GeneralName, GeneralNames},
    };

    fn point(dns: &str) -> DistributionPoint {
        DistributionPoint::new(
            Some(
                GeneralNames::new(vec![GeneralName::dns_name(dns).unwrap()])
                    .unwrap()
                    .into(),
            ),
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn points_round_trip_in_order_with_a_fixed_der_encoding() {
        let points = CrlDistributionPoints::new(vec![point("a"), point("b")]).unwrap();
        let wire = b"\x30\x12\x30\x07\xa0\x05\xa0\x03\x82\x01a\x30\x07\xa0\x05\xa0\x03\x82\x01b";
        assert_eq!(points.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(points.points(), &[point("a"), point("b")]);
        assert_eq!(
            CrlDistributionPoints::decode(wire, &DecodingOptions::default()).unwrap(),
            (wire.len(), points.clone())
        );
        assert_eq!(
            CrlDistributionPoints::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            points
        );
        assert_eq!(
            points.to_string(),
            "distributionPoint: DNS:a, distributionPoint: DNS:b"
        );
    }

    #[test]
    fn empty_lists_and_invalid_members_are_rejected() {
        assert!(matches!(
            CrlDistributionPoints::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        for wire in [&b"\x30\x00"[..], b"\x30\x02\x30\x00"] {
            assert!(matches!(
                CrlDistributionPoints::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            ));
        }
        for wire in [&b"\x31\x00"[..], b"\x30\x05\xa0\x03\x82\x01a"] {
            assert!(matches!(
                CrlDistributionPoints::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            ));
        }
    }
}
