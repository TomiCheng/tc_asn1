//! RFC 3739 §3.2.2 type of biometric data.
//!
//! ```text
//! TypeOfBiometricData ::= CHOICE {
//!     predefinedBiometricType PredefinedBiometricType,
//!     biometricDataOid        OBJECT IDENTIFIER }
//!
//! PredefinedBiometricType ::= INTEGER {
//!     picture(0), handwritten-signature(1) }
//!     (picture|handwritten-signature)
//! ```
//!
//! A predefined type outside the two values is `MalformedValue`.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions,
};

const PICTURE: u8 = 0;
const HANDWRITTEN_SIGNATURE: u8 = 1;

/// One of the predefined biometric types, or one named by an OID.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::qualified::TypeOfBiometricData;
///
/// let picture = TypeOfBiometricData::Picture;
/// assert_eq!(picture.encode_to_vec(&EncodingOptions::DER)?, b"\x02\x01\x00");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum TypeOfBiometricData {
    /// `picture(0)`, a picture of the subject.
    Picture,
    /// `handwritten-signature(1)`.
    HandwrittenSignature,
    /// `biometricDataOid`, a type named by an OID.
    Oid(Asn1Oid),
}

impl TypeOfBiometricData {
    /// Runs `f` on the alternative as written: an INTEGER for the predefined types.
    fn with_alternative<R>(&self, f: impl FnOnce(&dyn Encode) -> R) -> R {
        match self {
            Self::Picture => f(&Asn1Integer::from(PICTURE)),
            Self::HandwrittenSignature => f(&Asn1Integer::from(HANDWRITTEN_SIGNATURE)),
            Self::Oid(oid) => f(oid),
        }
    }
}

impl DecodeInner for TypeOfBiometricData {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let tag = Asn1Ref::parse(buff, context)?.tag();
        if tag == Asn1Integer::TAG {
            let (used, value) = Asn1Integer::decode_inner(buff, context)?;
            let value = match u8::try_from(&value) {
                Ok(PICTURE) => Self::Picture,
                Ok(HANDWRITTEN_SIGNATURE) => Self::HandwrittenSignature,
                _ => return Err(Asn1Error::MalformedValue),
            };
            Ok((used, value))
        } else if tag == Asn1Oid::TAG {
            let (used, value) = Asn1Oid::decode_inner(buff, context)?;
            Ok((used, Self::Oid(value)))
        } else {
            Err(Asn1Error::UnexpectedTag)
        }
    }
}

impl Decode for TypeOfBiometricData {}

impl EncodeContent for TypeOfBiometricData {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.with_alternative(|value| value.content_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.with_alternative(|value| value.encode_content(rules, out))
    }
}

impl EncodeTagged for TypeOfBiometricData {}

// Each alternative writes its own tag.
impl Encode for TypeOfBiometricData {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.with_alternative(|value| value.encoded_len(rules))
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.with_alternative(|value| value.encode(rules, out))
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::TypeOfBiometricData;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn every_alternative_round_trips_under_its_own_tag() {
        for (value, wire) in [
            (TypeOfBiometricData::Picture, &b"\x02\x01\x00"[..]),
            (TypeOfBiometricData::HandwrittenSignature, b"\x02\x01\x01"),
            (
                TypeOfBiometricData::Oid("1.2.3".parse().unwrap()),
                b"\x06\x02\x2a\x03",
            ),
        ] {
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                TypeOfBiometricData::decode_der(wire, &options()).unwrap().1,
                value
            );
        }
    }

    #[test]
    fn other_predefined_values_and_other_types_are_rejected() {
        for wire in [&b"\x02\x01\x02"[..], b"\x02\x01\xff", b"\x02\x02\x01\x00"] {
            assert_eq!(
                TypeOfBiometricData::decode_der(wire, &options()),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            TypeOfBiometricData::decode_der(b"\x0a\x01\x00", &options()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
