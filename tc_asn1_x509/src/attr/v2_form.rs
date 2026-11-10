//! RFC 5755 §4.1 version-two attribute certificate issuer identification.
//!
//! ```text
//! V2Form ::= SEQUENCE {
//!     issuerName GeneralNames OPTIONAL,
//!     baseCertificateID [0] IssuerSerial OPTIONAL,
//!     objectDigestInfo [1] ObjectDigestInfo OPTIONAL }
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

/// The names, certificate or digest identifying a version-two issuer.
///
/// ```
/// use tc_asn1_x509::{attr::V2Form, name::{GeneralName, GeneralNames}};
///
/// let names = GeneralNames::new(vec![GeneralName::DirectoryName("CN=Example".parse()?)])?;
/// let value = V2Form::new(Some(names), None, None)?;
/// assert!(value.issuer_name().is_some());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct V2Form {
    issuer_name: Option<GeneralNames>,
    base_certificate_id: Option<IssuerSerial>,
    object_digest_info: Option<ObjectDigestInfo>,
}

impl V2Form {
    /// Creates an identifier; all fields absent returns `MalformedValue`.
    /// Name forms and other application-specific profile restrictions are not checked.
    pub fn new(
        issuer_name: Option<GeneralNames>,
        base_certificate_id: Option<IssuerSerial>,
        object_digest_info: Option<ObjectDigestInfo>,
    ) -> Result<Self, Asn1Error> {
        if issuer_name.is_none() && base_certificate_id.is_none() && object_digest_info.is_none() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            issuer_name,
            base_certificate_id,
            object_digest_info,
        })
    }

    /// Returns `issuerName`, if supplied.
    pub fn issuer_name(&self) -> Option<&GeneralNames> {
        self.issuer_name.as_ref()
    }

    /// Returns `baseCertificateID`, if supplied.
    pub fn base_certificate_id(&self) -> Option<&IssuerSerial> {
        self.base_certificate_id.as_ref()
    }

    /// Returns `objectDigestInfo`, if supplied.
    pub fn object_digest_info(&self) -> Option<&ObjectDigestInfo> {
        self.object_digest_info.as_ref()
    }
}

impl DecodeContent for V2Form {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let issuer_name = fields.get_opt::<GeneralNames>()?;
        let base_certificate_id = fields.get_implicit_opt::<IssuerSerial>([0xa0])?;
        let object_digest_info = fields.get_implicit_opt::<ObjectDigestInfo>([0xa1])?;
        fields.end()?;
        Self::new(issuer_name, base_certificate_id, object_digest_info)
    }
}

impl DecodeInner for V2Form {
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

impl EncodeContent for V2Form {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.issuer_name
            .as_ref()
            .map_or(0, |value| value.encoded_len(rules))
            + self
                .base_certificate_id
                .as_ref()
                .map_or(0, |value| Implicit::new(&[0xa0], value).encoded_len(rules))
            + self
                .object_digest_info
                .as_ref()
                .map_or(0, |value| Implicit::new(&[0xa1], value).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(value) = &self.issuer_name {
            at += value.encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.base_certificate_id {
            at += Implicit::new(&[0xa0], value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.object_digest_info {
            at += Implicit::new(&[0xa1], value).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for V2Form {}

impl Tagged for V2Form {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for V2Form {}

impl Encode for V2Form {
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

    use super::V2Form;
    use crate::{
        alg::AlgorithmIdentifier,
        attr::{DigestedObjectType, IssuerSerial, ObjectDigestInfo},
        name::{GeneralName, GeneralNames},
    };

    #[test]
    fn an_empty_v2_form_is_rejected_when_constructed_or_decoded() {
        assert_eq!(
            V2Form::new(None, None, None),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            V2Form::decode_der(b"\x30\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn v2_form_optional_identifiers_round_trip_in_every_nonempty_combination() {
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
                    let value = V2Form::new(
                        a.then(|| names.clone()),
                        b.then(|| reference.clone()),
                        c.then(|| digest.clone()),
                    )
                    .unwrap();
                    let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
                    assert_eq!(
                        V2Form::decode_der(&wire, &DecodingOptions::default())
                            .unwrap()
                            .1,
                        value
                    );
                }
            }
        }
    }

    #[test]
    fn v2_form_issuer_names_retain_their_sequence_tag() {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let value = V2Form::new(Some(names), None, None).unwrap();
        let wire = b"\x30\x05\x30\x03\x82\x01a";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            V2Form::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn v2_form_certificate_and_digest_fields_use_a0_and_a1_without_inner_sequences() {
        let wire = [
            0x30, 25, 0xa0, 8, 0x30, 3, 0x82, 1, b'a', 2, 1, 1, 0xa1, 13, 0x0a, 1, 0, 0x30, 4, 6,
            2, 0x2a, 3, 3, 2, 0, 0xaa,
        ];
        let value = V2Form::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(value.base_certificate_id().unwrap().serial(), &1.into());
        assert!(value.issuer_name().is_none());
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
            V2Form::decode_der(&reversed, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }

    #[test]
    fn v2_form_rejects_explicit_wrappers_and_duplicate_identifiers() {
        let wrapped = b"\x30\x0c\xa0\x0a\x30\x08\x30\x03\x82\x01a\x02\x01\x01";
        assert_eq!(
            V2Form::decode_der(wrapped, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let duplicate = b"\x30\x0a\x30\x03\x82\x01a\x30\x03\x82\x01b";
        assert_eq!(
            V2Form::decode_der(duplicate, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
