//! RFC 5280 §4.2.1.13 `DistributionPoint`: a CRL distribution point,
//! its optional reason coverage and CRL issuer.
//!
//! ```text
//! DistributionPoint ::= SEQUENCE {
//!     distributionPoint [0] DistributionPointName OPTIONAL,
//!     reasons           [1] ReasonFlags OPTIONAL,
//!     cRLIssuer         [2] GeneralNames OPTIONAL }
//! ```
//!
//! The CHOICE-valued distribution point name is EXPLICIT; the other fields
//! are IMPLICIT. A point must include a name or a CRL issuer, or both.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Implicit, Tagged, tag,
};

use crate::{
    crl::{DistributionPointName, ReasonFlags},
    name::GeneralNames,
};

/// Describes where to obtain a CRL and which reasons and issuer it covers.
///
/// An absent `reasons` field places no restriction on reason coverage.
/// An absent `crl_issuer` identifies the certificate issuer as the CRL issuer.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{crl::DistributionPoint, name::{GeneralName, GeneralNames}};
///
/// let names = GeneralNames::new(vec![GeneralName::uri("http://example.com/ca.crl")?])?;
/// let point = DistributionPoint::new(Some(names.into()), None, None)?;
/// let der = point.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(DistributionPoint::decode_der(&der, &DecodingOptions::default())?.1, point);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DistributionPoint {
    distribution_point: Option<DistributionPointName>,
    reasons: Option<ReasonFlags>,
    crl_issuer: Option<GeneralNames>,
}

impl DistributionPoint {
    /// Creates a point with a name, a CRL issuer, or both.
    /// Returns [`Asn1Error::MalformedValue`] when both are absent, including
    /// when only `reasons` is supplied.
    pub fn new(
        distribution_point: Option<DistributionPointName>,
        reasons: Option<ReasonFlags>,
        crl_issuer: Option<GeneralNames>,
    ) -> Result<Self, Asn1Error> {
        if distribution_point.is_none() && crl_issuer.is_none() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            distribution_point,
            reasons,
            crl_issuer,
        })
    }

    /// Returns the distribution point's full or issuer-relative name, if present.
    pub fn distribution_point(&self) -> Option<&DistributionPointName> {
        self.distribution_point.as_ref()
    }

    /// Returns the reason restriction, or `None` for unrestricted coverage.
    pub fn reasons(&self) -> Option<ReasonFlags> {
        self.reasons
    }

    /// Returns the CRL issuer names, if explicitly supplied.
    pub fn crl_issuer(&self) -> Option<&GeneralNames> {
        self.crl_issuer.as_ref()
    }
}

/// Lists the present fields in schema order, separated by commas.
impl fmt::Display for DistributionPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separator = "";
        if let Some(value) = &self.distribution_point {
            write!(f, "distributionPoint: {value}")?;
            separator = ", ";
        }
        if let Some(value) = &self.reasons {
            write!(f, "{separator}reasons: {value}")?;
            separator = ", ";
        }
        if let Some(value) = &self.crl_issuer {
            write!(f, "{separator}cRLIssuer: {value}")?;
        }
        Ok(())
    }
}

impl DecodeInner for DistributionPoint {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let point = fields.get_explicit_opt::<DistributionPointName>([0xA0])?;
        let reasons = fields.get_implicit_opt::<ReasonFlags>([0x81])?;
        let issuer = fields.get_implicit_opt::<GeneralNames>([0xA2])?;
        fields.end()?;
        Ok((element.total_len(), Self::new(point, reasons, issuer)?))
    }
}

impl Decode for DistributionPoint {}

impl Tagged for DistributionPoint {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for DistributionPoint {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.distribution_point
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xA0], v).encoded_len(rules))
            + self
                .reasons
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x81], v).encoded_len(rules))
            + self
                .crl_issuer
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xA2], v).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.distribution_point {
            at += Explicit::new(&[0xA0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.reasons {
            at += Implicit::new(&[0x81], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.crl_issuer {
            at += Implicit::new(&[0xA2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for DistributionPoint {}

impl Encode for DistributionPoint {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::DistributionPoint;
    use crate::{
        crl::ReasonFlags,
        name::{GeneralName, GeneralNames},
    };

    fn names() -> GeneralNames {
        GeneralNames::new(vec![GeneralName::dns_name("x.tw").unwrap()]).unwrap()
    }

    #[test]
    fn every_valid_optional_field_combination_round_trips() {
        for has_point in [false, true] {
            for has_issuer in [false, true] {
                if !has_point && !has_issuer {
                    continue;
                }
                for reasons in [None, Some(ReasonFlags::KEY_COMPROMISE)] {
                    let point = DistributionPoint::new(
                        has_point.then(|| names().into()),
                        reasons,
                        has_issuer.then(names),
                    )
                    .unwrap();
                    let wire = point.encode_to_vec(&EncodingOptions::DER).unwrap();
                    assert_eq!(
                        DistributionPoint::decode_der(&wire, &DecodingOptions::default()).unwrap(),
                        (wire.len(), point.clone())
                    );
                    assert_eq!(point.distribution_point().is_some(), has_point);
                    assert_eq!(point.crl_issuer().is_some(), has_issuer);
                    assert_eq!(point.reasons(), reasons);
                }
            }
        }
    }

    #[test]
    fn the_name_is_explicit_and_reasons_and_issuer_are_implicit() {
        let point = DistributionPoint::new(
            Some(names().into()),
            Some(ReasonFlags::KEY_COMPROMISE),
            Some(names()),
        )
        .unwrap();
        assert_eq!(
            point.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x30\x16\xa0\x08\xa0\x06\x82\x04x.tw\x81\x02\x06\x40\xa2\x06\x82\x04x.tw"
        );
        assert_eq!(
            point.to_string(),
            "distributionPoint: DNS:x.tw, reasons: keyCompromise, cRLIssuer: DNS:x.tw"
        );
    }

    #[test]
    fn neither_a_name_nor_an_issuer_is_rejected_with_or_without_reasons() {
        for reasons in [None, Some(ReasonFlags::KEY_COMPROMISE)] {
            assert!(matches!(
                DistributionPoint::new(None, reasons, None),
                Err(Asn1Error::MalformedValue)
            ));
        }
        for wire in [&b"\x30\x00"[..], b"\x30\x04\x81\x02\x06\x40"] {
            assert!(matches!(
                DistributionPoint::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn wrong_wrappers_repeated_and_out_of_order_fields_are_rejected() {
        for wire in [
            &b"\x30\x08\xa0\x06\x82\x04x.tw"[..],
            b"\x30\x0a\xa2\x08\x30\x06\x82\x04x.tw",
        ] {
            assert!(matches!(
                DistributionPoint::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            ));
        }
        for wire in [
            &b"\x30\x10\xa2\x06\x82\x04x.tw\xa2\x06\x82\x04x.tw"[..],
            b"\x30\x0c\xa2\x06\x82\x04x.tw\x81\x02\x06\x40",
        ] {
            assert!(matches!(
                DistributionPoint::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::TrailingData)
            ));
        }
    }
}
