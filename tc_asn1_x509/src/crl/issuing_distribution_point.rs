//! RFC 5280 §5.2.5 issuing distribution point and CRL scope.
//!
//! ```text
//! IssuingDistributionPoint ::= SEQUENCE {
//!     distributionPoint          [0] DistributionPointName OPTIONAL,
//!     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
//!     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
//!     onlySomeReasons            [3] ReasonFlags OPTIONAL,
//!     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
//!     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
//! ```
//!
//! The name has an EXPLICIT wrapper; the remaining fields are IMPLICIT.
//! Certificate scope flags are mutually exclusive. An empty scope is accepted
//! as ASN.1, although RFC 5280 forbids issuers from emitting an empty extension.

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Explicit, Implicit, Tagged, tag,
};

use crate::crl::{DistributionPointName, ReasonFlags};

/// The scope of certificates and reasons covered by a CRL.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::crl::IssuingDistributionPoint;
///
/// let scope = IssuingDistributionPoint::new(None, false, true, None, false, false)?;
/// assert!(scope.only_contains_ca_certs());
/// assert_eq!(scope.encode_to_vec(&EncodingOptions::DER)?, [0x30, 3, 0x82, 1, 0xff]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IssuingDistributionPoint {
    distribution_point: Option<DistributionPointName>,
    only_contains_user_certs: bool,
    only_contains_ca_certs: bool,
    only_some_reasons: Option<ReasonFlags>,
    indirect_crl: bool,
    only_contains_attribute_certs: bool,
}

impl IssuingDistributionPoint {
    /// Creates a scope; two or more certificate scope flags yield `MalformedValue`.
    /// Criticality and applicability to a particular CRL are checked by the validator.
    pub fn new(
        distribution_point: Option<DistributionPointName>,
        only_contains_user_certs: bool,
        only_contains_ca_certs: bool,
        only_some_reasons: Option<ReasonFlags>,
        indirect_crl: bool,
        only_contains_attribute_certs: bool,
    ) -> Result<Self, Asn1Error> {
        if u8::from(only_contains_user_certs)
            + u8::from(only_contains_ca_certs)
            + u8::from(only_contains_attribute_certs)
            > 1
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            distribution_point,
            only_contains_user_certs,
            only_contains_ca_certs,
            only_some_reasons,
            indirect_crl,
            only_contains_attribute_certs,
        })
    }

    /// Returns the full or issuer-relative distribution point name.
    pub fn distribution_point(&self) -> Option<&DistributionPointName> {
        self.distribution_point.as_ref()
    }

    /// Whether this CRL covers only end-entity certificates.
    pub fn only_contains_user_certs(&self) -> bool {
        self.only_contains_user_certs
    }

    /// Whether this CRL covers only CA certificates.
    pub fn only_contains_ca_certs(&self) -> bool {
        self.only_contains_ca_certs
    }

    /// Returns the reason restriction, or `None` for all reasons.
    pub fn only_some_reasons(&self) -> Option<ReasonFlags> {
        self.only_some_reasons
    }

    /// Whether entries may name certificate issuers other than the CRL issuer.
    pub fn indirect_crl(&self) -> bool {
        self.indirect_crl
    }

    /// Whether this CRL covers only attribute certificates.
    pub fn only_contains_attribute_certs(&self) -> bool {
        self.only_contains_attribute_certs
    }
}

impl DecodeInner for IssuingDistributionPoint {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let point = fields.get_explicit_opt::<DistributionPointName>([0xa0])?;
        let user = fields
            .get_implicit_default([0x81], Asn1Boolean::from(false))?
            .is_true();
        let ca = fields
            .get_implicit_default([0x82], Asn1Boolean::from(false))?
            .is_true();
        let reasons = fields.get_implicit_opt::<ReasonFlags>([0x83])?;
        let indirect = fields
            .get_implicit_default([0x84], Asn1Boolean::from(false))?
            .is_true();
        let attribute = fields
            .get_implicit_default([0x85], Asn1Boolean::from(false))?
            .is_true();
        fields.end()?;
        Ok((
            element.total_len(),
            Self::new(point, user, ca, reasons, indirect, attribute)?,
        ))
    }
}

impl EncodeContent for IssuingDistributionPoint {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.distribution_point
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .only_some_reasons
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x83], v).encoded_len(rules))
            + [
                self.only_contains_user_certs,
                self.only_contains_ca_certs,
                self.indirect_crl,
                self.only_contains_attribute_certs,
            ]
            .into_iter()
            .filter(|v| *v)
            .count()
                * Implicit::new(&[0x81], &Asn1Boolean::from(true)).encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(value) = &self.distribution_point {
            at += Explicit::new(&[0xa0], value).encode(rules, &mut out[at..])?;
        }
        for (tag, present) in [
            (0x81, self.only_contains_user_certs),
            (0x82, self.only_contains_ca_certs),
        ] {
            if present {
                at += Implicit::new(&[tag], &Asn1Boolean::from(true))
                    .encode(rules, &mut out[at..])?;
            }
        }
        if let Some(value) = &self.only_some_reasons {
            at += Implicit::new(&[0x83], value).encode(rules, &mut out[at..])?;
        }
        for (tag, present) in [
            (0x84, self.indirect_crl),
            (0x85, self.only_contains_attribute_certs),
        ] {
            if present {
                at += Implicit::new(&[tag], &Asn1Boolean::from(true))
                    .encode(rules, &mut out[at..])?;
            }
        }
        Ok(at)
    }
}

impl Decode for IssuingDistributionPoint {}

impl Tagged for IssuingDistributionPoint {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for IssuingDistributionPoint {}

impl Encode for IssuingDistributionPoint {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::IssuingDistributionPoint;
    use crate::{
        crl::ReasonFlags,
        name::{GeneralName, GeneralNames},
    };

    #[test]
    fn the_name_is_explicit_while_reasons_and_boolean_flags_are_implicit() {
        let name = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let value = IssuingDistributionPoint::new(
            Some(name.into()),
            true,
            false,
            Some(ReasonFlags::KEY_COMPROMISE),
            true,
            false,
        )
        .unwrap();
        let wire = [
            0x30, 17, 0xa0, 5, 0xa0, 3, 0x82, 1, b'a', 0x81, 1, 0xff, 0x83, 2, 6, 0x40, 0x84, 1,
            0xff,
        ];
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            IssuingDistributionPoint::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn each_certificate_scope_uses_its_own_implicit_boolean_tag() {
        for (tag, user, ca, attribute) in [
            (0x81, true, false, false),
            (0x82, false, true, false),
            (0x85, false, false, true),
        ] {
            let value =
                IssuingDistributionPoint::new(None, user, ca, None, false, attribute).unwrap();
            let wire = [0x30, 3, tag, 1, 0xff];
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                IssuingDistributionPoint::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn certificate_scope_flags_are_mutually_exclusive_in_construction_and_decoding() {
        for (user, ca, attribute) in [
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert_eq!(
                IssuingDistributionPoint::new(None, user, ca, None, false, attribute),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            IssuingDistributionPoint::decode_der(
                b"\x30\x06\x81\x01\xff\x85\x01\xff",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue),
        );
    }

    #[test]
    fn false_defaults_are_omitted_and_explicit_false_is_ber_only() {
        let value = IssuingDistributionPoint::new(None, false, false, None, false, false).unwrap();
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\x30\x00"
        );
        for tag in [0x81, 0x82, 0x84, 0x85] {
            let wire = [0x30, 3, tag, 1, 0];
            assert_eq!(
                IssuingDistributionPoint::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
            assert_eq!(
                IssuingDistributionPoint::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::NotDer)
            );
        }
    }

    #[test]
    fn missing_choice_wrappers_and_repeated_or_unordered_fields_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x05\xa0\x03\x82\x01a"[..], Asn1Error::UnexpectedTag),
            (
                &b"\x30\x06\x84\x01\xff\x84\x01\xff"[..],
                Asn1Error::TrailingData,
            ),
            (
                &b"\x30\x06\x84\x01\xff\x81\x01\xff"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                IssuingDistributionPoint::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
