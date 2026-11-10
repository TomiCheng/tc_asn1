//! A policy qualifier whose identifier determines its value type.
//!
//! ```text
//! PolicyQualifierInfo ::= SEQUENCE {
//!     policyQualifierId OBJECT IDENTIFIER,
//!     qualifier         ANY DEFINED BY policyQualifierId }
//! ```

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1Object, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};

use crate::ext::UserNotice;

/// An unrecognized qualifier OID and its value. Construct with
/// [`PolicyQualifierInfo::other`] to exclude the two recognized OIDs.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnknownPolicyQualifier {
    qualifier_id: Asn1Oid,
    qualifier: Asn1Object,
}

impl UnknownPolicyQualifier {
    /// Returns the unrecognized identifier.
    pub fn qualifier_id(&self) -> &Asn1Oid {
        &self.qualifier_id
    }

    /// Returns the preserved ASN.1 value.
    pub fn qualifier(&self) -> &Asn1Object {
        &self.qualifier
    }
}

/// A CPS URI, a user notice, or an unknown qualifier. Known OIDs are derived
/// from the variant so their value types cannot be mismatched.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::PolicyQualifierInfo;
///
/// let qualifier = PolicyQualifierInfo::cps("https://example.com/cps")?;
/// let der = qualifier.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(PolicyQualifierInfo::decode_der(&der, &DecodingOptions::default())?.1, qualifier);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum PolicyQualifierInfo {
    /// `id-qt-cps`: the URI of the certification practice statement.
    Cps(Asn1Ia5String),
    /// `id-qt-unotice`: a notice to show the user.
    UserNotice(UserNotice),
    /// Any other qualifier, kept as decoded.
    Other(UnknownPolicyQualifier),
}

impl PolicyQualifierInfo {
    /// The CPS pointer qualifier identifier.
    pub const CPS: NamedOid = NamedOid::new(
        &[0x2b, 6, 1, 5, 5, 7, 2, 1],
        "1.3.6.1.5.5.7.2.1",
        "id-qt-cps",
    );
    /// The user notice qualifier identifier.
    pub const UNOTICE: NamedOid = NamedOid::new(
        &[0x2b, 6, 1, 5, 5, 7, 2, 2],
        "1.3.6.1.5.5.7.2.2",
        "id-qt-unotice",
    );

    /// Creates a CPS pointer. Non-IA5 characters return `MalformedValue`.
    pub fn cps(uri: &str) -> Result<Self, Asn1Error> {
        Ok(Self::Cps(Asn1Ia5String::new(uri)?))
    }

    /// Preserves an unknown qualifier. Recognized OIDs return `MalformedValue`;
    /// use their typed variants instead.
    pub fn other(
        qualifier_id: impl Into<Asn1Oid>,
        qualifier: Asn1Object,
    ) -> Result<Self, Asn1Error> {
        let qualifier_id = qualifier_id.into();
        if Self::CPS == qualifier_id || Self::UNOTICE == qualifier_id {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self::Other(UnknownPolicyQualifier {
            qualifier_id,
            qualifier,
        }))
    }

    /// Returns the identifier selected by this variant.
    pub fn qualifier_id(&self) -> Asn1Oid {
        match self {
            Self::Cps(_) => Self::CPS.into(),
            Self::UserNotice(_) => Self::UNOTICE.into(),
            Self::Other(v) => v.qualifier_id.clone(),
        }
    }
}

impl fmt::Display for PolicyQualifierInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cps(v) => write!(f, "CPS: {v}"),
            Self::UserNotice(v) => write!(f, "userNotice: {v}"),
            Self::Other(v) => write!(f, "{}", v.qualifier_id),
        }
    }
}

impl DecodeInner for PolicyQualifierInfo {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let oid = fields.get::<Asn1Oid>()?;
        let value = if Self::CPS == oid {
            Self::Cps(fields.get::<Asn1Ia5String>()?)
        } else if Self::UNOTICE == oid {
            Self::UserNotice(fields.get::<UserNotice>()?)
        } else {
            Self::other(oid, fields.get::<Asn1Object>()?)?
        };
        fields.end()?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for PolicyQualifierInfo {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.qualifier_id().encoded_len(rules)
            + match self {
                Self::Cps(v) => v.encoded_len(rules),
                Self::UserNotice(v) => v.encoded_len(rules),
                Self::Other(v) => v.qualifier.encoded_len(rules),
            }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.qualifier_id().encode(rules, out)?;
        Ok(at
            + match self {
                Self::Cps(v) => v.encode(rules, &mut out[at..])?,
                Self::UserNotice(v) => v.encode(rules, &mut out[at..])?,
                Self::Other(v) => v.qualifier.encode(rules, &mut out[at..])?,
            })
    }
}

impl Decode for PolicyQualifierInfo {}

impl Tagged for PolicyQualifierInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PolicyQualifierInfo {}

impl Encode for PolicyQualifierInfo {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyQualifierInfo;
    use crate::ext::UserNotice;
    use tc_asn1::{
        Asn1Error, Asn1Integer, Asn1Object, Asn1Oid, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };

    #[test]
    fn known_and_unknown_qualifiers_preserve_their_typed_values() {
        for value in [
            PolicyQualifierInfo::cps("https://x").unwrap(),
            PolicyQualifierInfo::UserNotice(UserNotice::new(None, None)),
            PolicyQualifierInfo::other(
                "1.2.3".parse::<Asn1Oid>().unwrap(),
                Asn1Object::from(Asn1Integer::from(42)),
            )
            .unwrap(),
        ] {
            let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                PolicyQualifierInfo::decode_der(&der, &DecodingOptions::default()).unwrap(),
                (der.len(), value)
            );
        }
        assert_eq!(
            PolicyQualifierInfo::cps("x")
                .unwrap()
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            b"\x30\x0d\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01\x16\x01x"
        );
    }

    #[test]
    fn known_oids_require_their_own_value_types_and_cannot_be_unknown() {
        for wire in [
            &b"\x30\x0c\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01\x30\x00"[..],
            b"\x30\x0d\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x02\x16\x01x",
        ] {
            assert!(matches!(
                PolicyQualifierInfo::decode(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            ));
        }
        for oid in [PolicyQualifierInfo::CPS, PolicyQualifierInfo::UNOTICE] {
            assert!(matches!(
                PolicyQualifierInfo::other(oid, Asn1Object::from(Asn1Integer::from(1))),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            PolicyQualifierInfo::cps("界"),
            Err(Asn1Error::MalformedValue)
        ));
    }
}
