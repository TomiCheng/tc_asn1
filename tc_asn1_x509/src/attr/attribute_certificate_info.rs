//! RFC 5755 §4.1 attribute certificate fields covered by the signature.
//!
//! ```text
//! AttributeCertificateInfo ::= SEQUENCE {
//!     version                AttCertVersion, -- v2(1)
//!     holder                 Holder,
//!     issuer                 AttCertIssuer,
//!     signature              AlgorithmIdentifier,
//!     serialNumber           CertificateSerialNumber,
//!     attrCertValidityPeriod AttCertValidityPeriod,
//!     attributes             SEQUENCE OF Attribute,
//!     issuerUniqueID         UniqueIdentifier OPTIONAL,
//!     extensions             Extensions OPTIONAL }
//!
//! AttCertVersion ::= INTEGER { v2(1) }
//! ```
//!
//! The version is always v2. Attributes are non-empty and their type OIDs are
//! unique (RFC 5755 §4.2.7). Serial-number limits, name forms, digest policy,
//! issuer authorization and extension semantics are checked by the validator.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Decode, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Attribute;

use crate::{
    alg::AlgorithmIdentifier,
    attr::{AttCertIssuer, AttCertValidityPeriod, Holder},
    ext::Extensions,
};

/// The fields signed by an attribute authority.
///
/// ```
/// use tc_asn1::{Asn1GeneralizedTime, Asn1Oid};
/// use tc_asn1_x500::{Attribute, DirectoryString};
/// use tc_asn1_x509::{
///     alg::AlgorithmIdentifier,
///     attr::{AttCertValidityPeriod, AttributeCertificateInfo, Holder, V2Form},
///     name::{GeneralName, GeneralNames},
/// };
///
/// let names = GeneralNames::new(vec![GeneralName::DirectoryName("CN=Example".parse()?)])?;
/// let start = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0)?;
/// let end = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0)?;
/// let info = AttributeCertificateInfo::new(
///     Holder::new(None, Some(names.clone()), None)?,
///     V2Form::new(Some(names), None, None)?.into(),
///     AlgorithmIdentifier::new("1.3.101.112".parse()?), 1.into(),
///     AttCertValidityPeriod::new(start, end)?,
///     vec![Attribute::new(
///         "1.2.3".parse::<Asn1Oid>()?, vec![DirectoryString::new("role")?.into()],
///     )?],
/// )?;
/// assert_eq!(info.attributes().len(), 1);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttributeCertificateInfo {
    holder: Holder,
    issuer: AttCertIssuer,
    signature: AlgorithmIdentifier,
    serial_number: Asn1Integer,
    attr_cert_validity_period: AttCertValidityPeriod,
    attributes: Asn1SequenceOf<Attribute>,
    issuer_unique_id: Option<Asn1BitString>,
    extensions: Option<Extensions>,
}

impl AttributeCertificateInfo {
    /// Creates v2 signed fields without optional fields.
    /// Empty attributes or duplicate attribute type OIDs return `MalformedValue`.
    pub fn new(
        holder: Holder,
        issuer: AttCertIssuer,
        signature: AlgorithmIdentifier,
        serial_number: Asn1Integer,
        attr_cert_validity_period: AttCertValidityPeriod,
        attributes: Vec<Attribute>,
    ) -> Result<Self, Asn1Error> {
        if attributes.is_empty()
            || attributes.iter().enumerate().any(|(i, a)| {
                attributes[..i]
                    .iter()
                    .any(|b| a.attribute_type() == b.attribute_type())
            })
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            holder,
            issuer,
            signature,
            serial_number,
            attr_cert_validity_period,
            attributes: Asn1SequenceOf::new(attributes),
            issuer_unique_id: None,
            extensions: None,
        })
    }

    /// Adds an issuer unique identifier without checking the issuer's certificate.
    pub fn with_issuer_unique_id(mut self, value: Asn1BitString) -> Self {
        self.issuer_unique_id = Some(value);
        self
    }

    /// Adds attribute-certificate extensions.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Returns the holder identification.
    pub fn holder(&self) -> &Holder {
        &self.holder
    }

    /// Returns the attribute authority identification.
    pub fn issuer(&self) -> &AttCertIssuer {
        &self.issuer
    }

    /// Returns the signing algorithm.
    pub fn signature(&self) -> &AlgorithmIdentifier {
        &self.signature
    }

    /// Returns the arbitrary-precision serial number.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }

    /// Returns the validity bounds.
    pub fn attr_cert_validity_period(&self) -> &AttCertValidityPeriod {
        &self.attr_cert_validity_period
    }

    /// Returns the non-empty attributes in wire order.
    pub fn attributes(&self) -> &[Attribute] {
        self.attributes.elements()
    }

    /// Returns the optional issuer unique identifier.
    pub fn issuer_unique_id(&self) -> Option<&Asn1BitString> {
        self.issuer_unique_id.as_ref()
    }

    /// Returns the optional extensions.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeInner for AttributeCertificateInfo {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        if fields.get::<Asn1Integer>()? != Asn1Integer::from(1) {
            return Err(Asn1Error::MalformedValue);
        }
        let holder = fields.get()?;
        let issuer = fields.get()?;
        let signature = fields.get()?;
        let serial_number = fields.get()?;
        let attr_cert_validity_period = fields.get()?;
        let attributes = fields.get::<Asn1SequenceOf<Attribute>>()?;
        let issuer_unique_id = fields.get_opt()?;
        let extensions = fields.get_opt()?;
        fields.end()?;
        let mut value = Self::new(
            holder,
            issuer,
            signature,
            serial_number,
            attr_cert_validity_period,
            attributes.into_elements(),
        )?;
        value.issuer_unique_id = issuer_unique_id;
        value.extensions = extensions;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for AttributeCertificateInfo {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        Asn1Integer::from(1).encoded_len(rules)
            + self.holder.encoded_len(rules)
            + self.issuer.encoded_len(rules)
            + self.signature.encoded_len(rules)
            + self.serial_number.encoded_len(rules)
            + self.attr_cert_validity_period.encoded_len(rules)
            + self.attributes.encoded_len(rules)
            + self
                .issuer_unique_id
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self.extensions.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = Asn1Integer::from(1).encode(rules, out)?;
        at += self.holder.encode(rules, &mut out[at..])?;
        at += self.issuer.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        at += self.serial_number.encode(rules, &mut out[at..])?;
        at += self
            .attr_cert_validity_period
            .encode(rules, &mut out[at..])?;
        at += self.attributes.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.issuer_unique_id {
            at += value.encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.extensions {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for AttributeCertificateInfo {}

impl Tagged for AttributeCertificateInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AttributeCertificateInfo {}

impl Encode for AttributeCertificateInfo {
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

    use tc_asn1::{
        Asn1BitString, Asn1Error, Asn1GeneralizedTime, Asn1Oid, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };
    use tc_asn1_x500::{Attribute, DirectoryString};

    use super::AttributeCertificateInfo;
    use crate::{
        alg::AlgorithmIdentifier,
        attr::{AttCertValidityPeriod, Holder, V2Form},
        ext::{Extension, Extensions},
        name::{GeneralName, GeneralNames},
    };

    fn sample() -> AttributeCertificateInfo {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let start = Asn1GeneralizedTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let end = Asn1GeneralizedTime::new(2027, 1, 1, 0, 0, 0).unwrap();
        AttributeCertificateInfo::new(
            Holder::new(None, Some(names.clone()), None).unwrap(),
            V2Form::new(Some(names), None, None).unwrap().into(),
            AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
            1.into(),
            AttCertValidityPeriod::new(start, end).unwrap(),
            vec![
                Attribute::new(
                    "1.2.3".parse::<Asn1Oid>().unwrap(),
                    vec![DirectoryString::new("x").unwrap().into()],
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn attribute_info_writes_v2_and_attributes_as_a_sequence_not_a_set() {
        let value = sample();
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        let expected = [
            0x30, 0x4b, 2, 1, 1, 0x30, 5, 0xa1, 3, 0x82, 1, b'a', 0xa0, 5, 0x30, 3, 0x82, 1, b'a',
            0x30, 4, 6, 2, 0x2a, 3, 2, 1, 1, 0x30, 34, 0x18, 15, b'2', b'0', b'2', b'6', b'0',
            b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x18, 15, b'2', b'0', b'2',
            b'7', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x30, 11, 0x30,
            9, 6, 2, 0x2a, 3, 0x31, 3, 0x13, 1, b'x',
        ];
        assert_eq!(wire, expected);
        assert_eq!(
            AttributeCertificateInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn issuer_unique_ids_and_extensions_round_trip_in_all_optional_combinations() {
        for uid in [false, true] {
            for ext in [false, true] {
                let mut value = sample();
                if uid {
                    value = value.with_issuer_unique_id(Asn1BitString::from_bytes(&[0xaa]));
                }
                if ext {
                    value = value.with_extensions(
                        Extensions::new(vec![Extension::new(
                            "1.2.3".parse::<Asn1Oid>().unwrap(),
                            false,
                            b"\x05\x00",
                        )])
                        .unwrap(),
                    );
                }
                let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
                assert_eq!(
                    AttributeCertificateInfo::decode_der(&wire, &DecodingOptions::default())
                        .unwrap()
                        .1,
                    value
                );
            }
        }
    }

    #[test]
    fn absent_or_repeated_attribute_types_are_rejected_in_construction_and_decoding() {
        let value = sample();
        for attributes in [
            vec![],
            vec![value.attributes()[0].clone(), value.attributes()[0].clone()],
        ] {
            assert_eq!(
                AttributeCertificateInfo::new(
                    value.holder().clone(),
                    value.issuer().clone(),
                    value.signature().clone(),
                    1.into(),
                    *value.attr_cert_validity_period(),
                    attributes
                ),
                Err(Asn1Error::MalformedValue),
            );
        }
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        let attr_start = wire.len() - 13;
        let mut empty = wire[..attr_start].to_vec();
        empty.extend_from_slice(&[0x30, 0]);
        empty[1] -= 11;
        assert_eq!(
            AttributeCertificateInfo::decode_der(&empty, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
        let mut duplicate = wire.clone();
        duplicate.extend_from_slice(&wire[attr_start + 2..]);
        duplicate[1] += 11;
        duplicate[attr_start + 1] += 11;
        assert_eq!(
            AttributeCertificateInfo::decode_der(&duplicate, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn wrong_versions_missing_holders_and_trailing_fields_are_rejected() {
        for number in [0, 2, 0xff] {
            let mut wire = sample().encode_to_vec(&EncodingOptions::DER).unwrap();
            wire[4] = number;
            assert_eq!(
                AttributeCertificateInfo::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            AttributeCertificateInfo::decode_der(
                b"\x30\x03\x02\x01\x01",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::Truncated)
        );
        let mut wire = sample().encode_to_vec(&EncodingOptions::DER).unwrap();
        wire.extend_from_slice(&[5, 0]);
        wire[1] += 2;
        assert_eq!(
            AttributeCertificateInfo::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
