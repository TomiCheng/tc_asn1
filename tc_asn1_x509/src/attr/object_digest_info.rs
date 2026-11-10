//! RFC 5755 §4.1 digest-based identification of a holder or issuer.
//!
//! ```text
//! ObjectDigestInfo ::= SEQUENCE {
//!     digestedObjectType ENUMERATED {
//!         publicKey(0), publicKeyCert(1), otherObjectTypes(2) },
//!     otherObjectTypeID OBJECT IDENTIFIER OPTIONAL,
//!     digestAlgorithm   AlgorithmIdentifier,
//!     objectDigest      BIT STRING }
//! ```
//!
//! The object type OID is present exactly for `otherObjectTypes`. Digest
//! algorithms and lengths are not interpreted. RFC 5755 profile restrictions,
//! including its exclusion of other object types, belong to the validator.

use tc_asn1::{
    Asn1BitString, Asn1Enumerated, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
    tag,
};

use crate::alg::AlgorithmIdentifier;

/// Selects the object whose encoding was digested.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DigestedObjectType {
    /// The public key.
    PublicKey = 0,
    /// The public-key certificate.
    PublicKeyCert = 1,
    /// An object identified by `otherObjectTypeID`.
    OtherObjectTypes = 2,
}

impl DigestedObjectType {
    /// Returns the ASN.1 enumeration value.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Rejects unassigned enumeration values with `MalformedValue`.
    pub fn from_number(number: u8) -> Result<Self, Asn1Error> {
        match number {
            0 => Ok(Self::PublicKey),
            1 => Ok(Self::PublicKeyCert),
            2 => Ok(Self::OtherObjectTypes),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

/// Identifies an object by its digest rather than by a name.
///
/// ```
/// use tc_asn1::Asn1BitString;
/// use tc_asn1_x509::{alg::AlgorithmIdentifier, attr::{DigestedObjectType, ObjectDigestInfo}};
///
/// let info = ObjectDigestInfo::new(
///     DigestedObjectType::PublicKey, None,
///     AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse()?),
///     Asn1BitString::from_bytes(&[0x11; 32]),
/// )?;
/// assert!(info.other_object_type_id().is_none());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ObjectDigestInfo {
    digested_object_type: DigestedObjectType,
    other_object_type_id: Option<Asn1Oid>,
    digest_algorithm: AlgorithmIdentifier,
    object_digest: Asn1BitString,
}

impl ObjectDigestInfo {
    /// Creates a digest identifier. An OID is required exactly for other object
    /// types; a mismatch returns `MalformedValue`.
    pub fn new(
        digested_object_type: DigestedObjectType,
        other_object_type_id: Option<Asn1Oid>,
        digest_algorithm: AlgorithmIdentifier,
        object_digest: Asn1BitString,
    ) -> Result<Self, Asn1Error> {
        if (digested_object_type == DigestedObjectType::OtherObjectTypes)
            != other_object_type_id.is_some()
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            digested_object_type,
            other_object_type_id,
            digest_algorithm,
            object_digest,
        })
    }

    /// Returns the kind of digested object.
    pub fn digested_object_type(&self) -> DigestedObjectType {
        self.digested_object_type
    }

    /// Returns the OID identifying an other object type, if selected.
    pub fn other_object_type_id(&self) -> Option<&Asn1Oid> {
        self.other_object_type_id.as_ref()
    }

    /// Returns the digest algorithm and its parameters.
    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        &self.digest_algorithm
    }

    /// Returns the digest bits without algorithm-specific interpretation.
    pub fn object_digest(&self) -> &Asn1BitString {
        &self.object_digest
    }
}

impl DecodeContent for ObjectDigestInfo {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let number = u64::try_from(&fields.get::<Asn1Enumerated>()?)
            .map_err(|_| Asn1Error::MalformedValue)?;
        let kind = DigestedObjectType::from_number(
            u8::try_from(number).map_err(|_| Asn1Error::MalformedValue)?,
        )?;
        let oid = fields.get_opt()?;
        let algorithm = fields.get()?;
        let digest = fields.get()?;
        fields.end()?;
        Self::new(kind, oid, algorithm, digest)
    }
}

impl DecodeInner for ObjectDigestInfo {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        Ok((
            element.total_len(),
            Self::decode_content(element.value(), context)?,
        ))
    }
}

impl EncodeContent for ObjectDigestInfo {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        3 + self
            .other_object_type_id
            .as_ref()
            .map_or(0, |v| v.encoded_len(rules))
            + self.digest_algorithm.encoded_len(rules)
            + self.object_digest.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        // Values 0..=2 use the same primitive, one-octet ENUMERATED under all rules.
        out.get_mut(..3)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&[0x0a, 1, self.digested_object_type.number()]);
        let mut at = 3;
        if let Some(value) = &self.other_object_type_id {
            at += value.encode(rules, &mut out[at..])?;
        }
        at += self.digest_algorithm.encode(rules, &mut out[at..])?;
        at += self.object_digest.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ObjectDigestInfo {}

impl Tagged for ObjectDigestInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ObjectDigestInfo {}

impl Encode for ObjectDigestInfo {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{
        Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodeContent, EncodingOptions,
    };

    use super::{DigestedObjectType, ObjectDigestInfo};
    use crate::alg::AlgorithmIdentifier;

    #[test]
    fn the_digest_kind_uses_one_content_octet_under_every_rule_and_checks_short_buffers() {
        let value = ObjectDigestInfo::new(
            DigestedObjectType::PublicKeyCert,
            None,
            AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
            Asn1BitString::from_bytes(&[0xaa]),
        )
        .unwrap();
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::CER,
            EncodingOptions::DER,
        ] {
            let mut content = [0u8; 64];
            let used = value.encode_content(&rules, &mut content).unwrap();
            assert_eq!(&content[..3], &[0x0a, 1, 1]);
            assert_eq!(used, value.content_len(&rules));
            for size in 0..3 {
                assert_eq!(
                    value.encode_content(&rules, &mut content[..size]),
                    Err(Asn1Error::BufferTooSmall)
                );
            }
        }
    }

    #[test]
    fn every_digest_object_kind_round_trips_with_its_required_oid_shape() {
        for kind in [
            DigestedObjectType::PublicKey,
            DigestedObjectType::PublicKeyCert,
            DigestedObjectType::OtherObjectTypes,
        ] {
            let oid =
                (kind == DigestedObjectType::OtherObjectTypes).then(|| "1.2.3".parse().unwrap());
            let value = ObjectDigestInfo::new(
                kind,
                oid,
                AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
                Asn1BitString::from_bytes(&[0xaa]),
            )
            .unwrap();
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                ObjectDigestInfo::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        let wire = b"\x30\x0d\x0a\x01\x00\x30\x04\x06\x02\x2a\x03\x03\x02\x00\xaa";
        let value = ObjectDigestInfo::decode_der(wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(value.digested_object_type(), DigestedObjectType::PublicKey);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
    }

    #[test]
    fn other_object_type_identifiers_must_match_the_enumerated_kind() {
        for (kind, oid) in [
            (
                DigestedObjectType::PublicKey,
                Some("1.2.3".parse().unwrap()),
            ),
            (
                DigestedObjectType::PublicKeyCert,
                Some("1.2.3".parse().unwrap()),
            ),
            (DigestedObjectType::OtherObjectTypes, None),
        ] {
            assert_eq!(
                ObjectDigestInfo::new(
                    kind,
                    oid,
                    AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
                    Asn1BitString::from_bytes(&[])
                ),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            ObjectDigestInfo::decode_der(
                b"\x30\x0d\x0a\x01\x02\x30\x04\x06\x02\x2a\x03\x03\x02\x00\xaa",
                &DecodingOptions::default()
            ),
            Err(Asn1Error::MalformedValue),
        );
    }

    #[test]
    fn digest_kinds_are_not_narrowed_and_extra_digest_fields_are_rejected() {
        assert_eq!(
            ObjectDigestInfo::decode_der(b"\x30\x04\x0a\x02\x01\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue),
        );
        let extra = [
            0x30, 15, 0x0a, 1, 0, 0x30, 4, 6, 2, 0x2a, 3, 3, 2, 0, 0xaa, 5, 0,
        ];
        assert_eq!(
            ObjectDigestInfo::decode_der(&extra, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
        let misplaced_oid = [
            0x30, 17, 0x0a, 1, 0, 6, 2, 0x2a, 3, 0x30, 4, 6, 2, 0x2a, 3, 3, 2, 0, 0xaa,
        ];
        assert_eq!(
            ObjectDigestInfo::decode_der(&misplaced_oid, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn invalid_digest_enumerations_and_missing_digest_fields_are_rejected() {
        for number in [3, 0xff] {
            let wire = [0x30, 3, 0x0a, 1, number];
            assert_eq!(
                ObjectDigestInfo::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            ObjectDigestInfo::decode_der(b"\x30\x03\x0a\x01\x00", &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
        assert_eq!(
            ObjectDigestInfo::decode_der(b"\x30\x03\x02\x01\x00", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
