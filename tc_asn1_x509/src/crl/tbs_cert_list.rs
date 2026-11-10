//! RFC 5280 §5.1.2 CRL fields covered by the signature.
//!
//! ```text
//! TBSCertList ::= SEQUENCE {
//!     version             Version OPTIONAL, -- if present, v2(1)
//!     signature           AlgorithmIdentifier,
//!     issuer              Name,
//!     thisUpdate          Time,
//!     nextUpdate          Time OPTIONAL,
//!     revokedCertificates SEQUENCE OF RevokedCertificate OPTIONAL,
//!     crlExtensions       [0] EXPLICIT Extensions OPTIONAL }
//! ```
//!
//! Entry and CRL extensions require v2. An empty revoked list is omitted;
//! a present empty list is rejected. Freshness, issuer authorization and
//! extension semantics belong to the validator. In particular, `nextUpdate`
//! remains optional as in ASN.1, although the RFC profile requires it.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x500::Name;

use crate::{
    alg::AlgorithmIdentifier,
    cert::{Time, Version},
    crl::RevokedCertificate,
    ext::Extensions,
};

/// The signed portion of a v1 or v2 CRL.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::{alg::AlgorithmIdentifier, cert::{Time, Version}, crl::TbsCertList};
///
/// let tbs = TbsCertList::new(
///     Version::V2, AlgorithmIdentifier::new("1.3.101.112".parse()?),
///     "CN=Example CA".parse()?, Time::new(2026, 1, 1, 0, 0, 0)?,
/// )?.with_next_update(Time::new(2026, 1, 8, 0, 0, 0)?);
/// let signed_bytes = tbs.encode_to_vec(&EncodingOptions::DER)?;
/// assert!(!signed_bytes.is_empty());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TbsCertList {
    version: Version,
    signature: AlgorithmIdentifier,
    issuer: Name,
    this_update: Time,
    next_update: Option<Time>,
    revoked_certificates: Asn1SequenceOf<RevokedCertificate>,
    extensions: Option<Extensions>,
}

impl TbsCertList {
    /// Creates a CRL without optional fields; v3 is rejected with `MalformedValue`.
    pub fn new(
        version: Version,
        signature: AlgorithmIdentifier,
        issuer: Name,
        this_update: Time,
    ) -> Result<Self, Asn1Error> {
        if version == Version::V3 {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            version,
            signature,
            issuer,
            this_update,
            next_update: None,
            revoked_certificates: Asn1SequenceOf::new(Vec::new()),
            extensions: None,
        })
    }

    /// Sets the next scheduled update. Freshness and time ordering are validator policy.
    pub fn with_next_update(mut self, next_update: Time) -> Self {
        self.next_update = Some(next_update);
        self
    }

    /// Sets entries in wire order. Entry extensions on v1 yield `MalformedValue`.
    /// An empty list is encoded by omitting the optional field.
    pub fn with_revoked_certificates(
        mut self,
        entries: Vec<RevokedCertificate>,
    ) -> Result<Self, Asn1Error> {
        if self.version != Version::V2 && entries.iter().any(|entry| entry.extensions().is_some()) {
            return Err(Asn1Error::MalformedValue);
        }
        self.revoked_certificates = Asn1SequenceOf::new(entries);
        Ok(self)
    }

    /// Attaches CRL extensions; v1 yields `MalformedValue`.
    pub fn with_extensions(mut self, extensions: Extensions) -> Result<Self, Asn1Error> {
        if self.version != Version::V2 {
            return Err(Asn1Error::MalformedValue);
        }
        self.extensions = Some(extensions);
        Ok(self)
    }

    /// Returns v1 when the version field is absent, otherwise v2.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the algorithm used to sign this CRL.
    pub fn signature(&self) -> &AlgorithmIdentifier {
        &self.signature
    }

    /// Returns the CRL issuer name.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// Returns the issue time.
    pub fn this_update(&self) -> &Time {
        &self.this_update
    }

    /// Returns the next scheduled issue time, if supplied.
    pub fn next_update(&self) -> Option<&Time> {
        self.next_update.as_ref()
    }

    /// Returns revoked entries in wire order.
    pub fn revoked_certificates(&self) -> &[RevokedCertificate] {
        self.revoked_certificates.elements()
    }

    /// Returns CRL-wide extensions, if supplied.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeInner for TbsCertList {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let version = match fields.get_opt::<Asn1Integer>()? {
            None => Version::V1,
            Some(value) if value == Asn1Integer::from(1) => Version::V2,
            Some(_) => return Err(Asn1Error::MalformedValue),
        };
        let signature = fields.get()?;
        let issuer = fields.get()?;
        let this_update = fields.get()?;
        let next_update = match fields.peek() {
            Some(Ok(value))
                if value.tag() == tag::UTC_TIME || value.tag() == tag::GENERALIZED_TIME =>
            {
                Some(fields.get()?)
            }
            Some(Err(error)) => return Err(error),
            _ => None,
        };
        let entries = fields.get_opt::<Asn1SequenceOf<RevokedCertificate>>()?;
        let extensions = fields.get_explicit_opt::<Extensions>([0xa0])?;
        fields.end()?;
        let mut value = Self::new(version, signature, issuer, this_update)?;
        value.next_update = next_update;
        if let Some(entries) = entries {
            if entries.elements().is_empty() {
                return Err(Asn1Error::MalformedValue);
            }
            value = value.with_revoked_certificates(entries.into_elements())?;
        }
        if let Some(extensions) = extensions {
            value = value.with_extensions(extensions)?;
        }
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for TbsCertList {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let version = if self.version == Version::V2 {
            Asn1Integer::from(1).encoded_len(rules)
        } else {
            0
        };
        version
            + self.signature.encoded_len(rules)
            + self.issuer.encoded_len(rules)
            + self.this_update.encoded_len(rules)
            + self
                .next_update
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + if self.revoked_certificates().is_empty() {
                0
            } else {
                self.revoked_certificates.encoded_len(rules)
            }
            + self
                .extensions
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if self.version == Version::V2 {
            at += Asn1Integer::from(1).encode(rules, &mut out[at..])?;
        }
        at += self.signature.encode(rules, &mut out[at..])?;
        at += self.issuer.encode(rules, &mut out[at..])?;
        at += self.this_update.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.next_update {
            at += value.encode(rules, &mut out[at..])?;
        }
        if !self.revoked_certificates().is_empty() {
            at += self.revoked_certificates.encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.extensions {
            at += Explicit::new(&[0xa0], value).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for TbsCertList {}

impl Tagged for TbsCertList {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TbsCertList {}

impl Encode for TbsCertList {
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

    use super::TbsCertList;
    use crate::{
        alg::AlgorithmIdentifier,
        cert::{Time, Version},
        crl::{CrlReason, RevokedCertificate},
        ext::{Extension, ExtensionId, Extensions},
    };

    fn minimal(version: Version) -> TbsCertList {
        TbsCertList::new(
            version,
            AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
            "".parse().unwrap(),
            Time::new(2026, 1, 1, 0, 0, 0).unwrap(),
        )
        .unwrap()
    }

    fn extensions() -> Extensions {
        Extensions::new(vec![
            Extension::with_value(ExtensionId::CRL_REASONS, false, &CrlReason::KeyCompromise)
                .unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn a_v1_crl_omits_version_next_update_and_an_empty_revoked_list() {
        let value = minimal(Version::V1);
        let wire = b"\x30\x18\x30\x05\x06\x03\x2b\x65\x70\x30\x00\x17\x0d260101000000Z";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            TbsCertList::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn optional_next_update_does_not_consume_the_revoked_list_or_extensions() {
        for next in [false, true] {
            for entries in [false, true] {
                for extension in [false, true] {
                    let mut value = minimal(Version::V2);
                    if next {
                        value = value.with_next_update(Time::new(2051, 1, 1, 0, 0, 0).unwrap());
                    }
                    if entries {
                        let date = *value.this_update();
                        value = value
                            .with_revoked_certificates(vec![
                                RevokedCertificate::new(1.into(), date)
                                    .with_extensions(extensions()),
                            ])
                            .unwrap();
                    }
                    if extension {
                        value = value.with_extensions(extensions()).unwrap();
                    }
                    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
                    assert_eq!(
                        TbsCertList::decode_der(&der, &DecodingOptions::default())
                            .unwrap()
                            .1,
                        value
                    );
                }
            }
        }
    }

    #[test]
    fn v1_cannot_carry_either_entry_extensions_or_crl_extensions() {
        assert_eq!(
            minimal(Version::V1).with_extensions(extensions()),
            Err(Asn1Error::MalformedValue)
        );
        let entry = RevokedCertificate::new(1.into(), *minimal(Version::V1).this_update())
            .with_extensions(extensions());
        assert_eq!(
            minimal(Version::V1).with_revoked_certificates(vec![entry.clone()]),
            Err(Asn1Error::MalformedValue)
        );
        for value in [
            minimal(Version::V2).with_extensions(extensions()).unwrap(),
            minimal(Version::V2)
                .with_revoked_certificates(vec![entry])
                .unwrap(),
        ] {
            let mut wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            wire.drain(2..5);
            wire[1] -= 3;
            assert_eq!(
                TbsCertList::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn missing_update_times_and_unexpected_or_repeated_fields_are_rejected() {
        let mut missing = minimal(Version::V1)
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        missing.truncate(11);
        missing[1] = 9;
        assert_eq!(
            TbsCertList::decode_der(&missing, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
        let mut wrong = minimal(Version::V1)
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        wrong[11] = 4;
        assert_eq!(
            TbsCertList::decode_der(&wrong, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let mut repeated = minimal(Version::V1)
            .with_next_update(Time::new(2026, 1, 8, 0, 0, 0).unwrap())
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        repeated.extend_from_slice(b"\x17\x0d260109000000Z");
        repeated[1] += 15;
        assert_eq!(
            TbsCertList::decode_der(&repeated, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
        assert_eq!(
            TbsCertList::new(
                Version::V3,
                AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
                "".parse().unwrap(),
                Time::new(2026, 1, 1, 0, 0, 0).unwrap(),
            ),
            Err(Asn1Error::MalformedValue),
        );
    }

    #[test]
    fn present_versions_other_than_v2_and_present_empty_revoked_lists_are_rejected() {
        for number in [0, 2, 0xff] {
            let mut wire = minimal(Version::V2)
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap();
            wire[4] = number;
            assert_eq!(
                TbsCertList::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        let mut wire = minimal(Version::V1)
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        wire.extend_from_slice(&[0x30, 0]);
        wire[1] += 2;
        assert_eq!(
            TbsCertList::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }
}
