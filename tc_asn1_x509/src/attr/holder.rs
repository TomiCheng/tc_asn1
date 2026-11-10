//! RFC 5755 §4.1 attribute certificate holder identification.
//!
//! ```text
//! Holder ::= SEQUENCE {
//!     baseCertificateID [0] IssuerSerial OPTIONAL,
//!     entityName [1] GeneralNames OPTIONAL,
//!     objectDigestInfo [2] ObjectDigestInfo OPTIONAL }
//! ```
//!
//! Context-specific fields use IMPLICIT tags. At least one identifier is required,
//! as a structural invariant shared with other identifying containers in this crate.
//! Name forms and remaining RFC 5755 profile requirements belong to the validator.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};

use crate::{
    attr::{IssuerSerial, ObjectDigestInfo},
    name::GeneralNames,
};

/// The certificate, names or digest identifying an attribute certificate holder.
///
/// ```
/// use tc_asn1_x509::{attr::Holder, name::{GeneralName, GeneralNames}};
///
/// let names = GeneralNames::new(vec![GeneralName::DirectoryName("CN=Example".parse()?)])?;
/// let value = Holder::new(None, Some(names), None)?;
/// assert!(value.entity_name().is_some());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Holder {
    base_certificate_id: Option<IssuerSerial>,
    entity_name: Option<GeneralNames>,
    object_digest_info: Option<ObjectDigestInfo>,
}

impl Holder {
    /// Creates an identifier; all fields absent returns `MalformedValue`.
    /// Name forms and other application-specific profile restrictions are not checked.
    pub fn new(
        base_certificate_id: Option<IssuerSerial>,
        entity_name: Option<GeneralNames>,
        object_digest_info: Option<ObjectDigestInfo>,
    ) -> Result<Self, Asn1Error> {
        if base_certificate_id.is_none() && entity_name.is_none() && object_digest_info.is_none() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            base_certificate_id,
            entity_name,
            object_digest_info,
        })
    }

    /// Returns `baseCertificateID`, if supplied.
    pub fn base_certificate_id(&self) -> Option<&IssuerSerial> {
        self.base_certificate_id.as_ref()
    }

    /// Returns `entityName`, if supplied.
    pub fn entity_name(&self) -> Option<&GeneralNames> {
        self.entity_name.as_ref()
    }

    /// Returns `objectDigestInfo`, if supplied.
    pub fn object_digest_info(&self) -> Option<&ObjectDigestInfo> {
        self.object_digest_info.as_ref()
    }
}

impl DecodeContent for Holder {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let base_certificate_id = fields.get_implicit_opt::<IssuerSerial>([0xa0])?;
        let entity_name = fields.get_implicit_opt::<GeneralNames>([0xa1])?;
        let object_digest_info = fields.get_implicit_opt::<ObjectDigestInfo>([0xa2])?;
        fields.end()?;
        Self::new(base_certificate_id, entity_name, object_digest_info)
    }
}

impl DecodeInner for Holder {
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

impl EncodeContent for Holder {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.base_certificate_id
            .as_ref()
            .map_or(0, |value| Implicit::new(&[0xa0], value).encoded_len(rules))
            + self
                .entity_name
                .as_ref()
                .map_or(0, |value| Implicit::new(&[0xa1], value).encoded_len(rules))
            + self
                .object_digest_info
                .as_ref()
                .map_or(0, |value| Implicit::new(&[0xa2], value).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(value) = &self.base_certificate_id {
            at += Implicit::new(&[0xa0], value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.entity_name {
            at += Implicit::new(&[0xa1], value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.object_digest_info {
            at += Implicit::new(&[0xa2], value).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Holder {}

impl Tagged for Holder {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Holder {}

impl Encode for Holder {
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

    use tc_asn1::{Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::Holder;
    use crate::{
        alg::AlgorithmIdentifier,
        attr::{DigestedObjectType, IssuerSerial, ObjectDigestInfo},
        name::{GeneralName, GeneralNames},
    };

    #[test]
    fn an_empty_holder_is_rejected_when_constructed_or_decoded() {
        assert_eq!(
            Holder::new(None, None, None),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Holder::decode_der(b"\x30\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn holder_optional_identifiers_round_trip_in_every_nonempty_combination() {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let reference = IssuerSerial::new(names.clone(), 1.into());
        let digest = ObjectDigestInfo::new(
            DigestedObjectType::PublicKey,
            None,
            AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
            Asn1BitString::from_bytes(&[0xaa]),
        )
        .unwrap();
        for a in [false, true] {
            for b in [false, true] {
                for c in [false, true] {
                    if !a && !b && !c {
                        continue;
                    }
                    let value = Holder::new(
                        a.then(|| reference.clone()),
                        b.then(|| names.clone()),
                        c.then(|| digest.clone()),
                    )
                    .unwrap();
                    let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
                    assert_eq!(
                        Holder::decode_der(&wire, &DecodingOptions::default())
                            .unwrap()
                            .1,
                        value
                    );
                }
            }
        }
    }

    #[test]
    fn holder_names_replace_the_sequence_tag_with_a1() {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let value = Holder::new(None, Some(names), None).unwrap();
        let wire = b"\x30\x05\xa1\x03\x82\x01a";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            Holder::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn holder_certificate_and_digest_fields_use_a0_and_a2_without_inner_sequences() {
        let wire = [
            0x30, 25, 0xa0, 8, 0x30, 3, 0x82, 1, b'a', 2, 1, 1, 0xa2, 13, 0x0a, 1, 0, 0x30, 4, 6,
            2, 0x2a, 3, 3, 2, 0, 0xaa,
        ];
        let value = Holder::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(value.base_certificate_id().unwrap().serial(), &1.into());
        assert!(value.entity_name().is_none());
        assert_eq!(
            value
                .object_digest_info()
                .unwrap()
                .object_digest()
                .as_bytes(),
            &[0xaa]
        );
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        let mut reversed = vec![0x30, 25];
        reversed.extend_from_slice(&wire[12..]);
        reversed.extend_from_slice(&wire[2..12]);
        assert_eq!(
            Holder::decode_der(&reversed, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }

    #[test]
    fn holder_rejects_explicit_wrappers_and_duplicate_identifiers() {
        let wrapped = b"\x30\x07\xa1\x05\x30\x03\x82\x01a";
        assert_eq!(
            Holder::decode_der(wrapped, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let duplicate = b"\x30\x0a\xa1\x03\x82\x01a\xa1\x03\x82\x01b";
        assert_eq!(
            Holder::decode_der(duplicate, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
