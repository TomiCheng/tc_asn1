//! RFC 5280 §4.1.1.2 `AlgorithmIdentifier`.
//!
//! ```text
//! AlgorithmIdentifier ::= SEQUENCE {
//!     algorithm   OBJECT IDENTIFIER,
//!     parameters  ANY DEFINED BY algorithm OPTIONAL }
//! ```
//!
//! Names an algorithm and carries whatever parameters it takes: nothing for
//! Ed25519 (RFC 8410), NULL for the RSA PKCS#1 v1.5 family (RFC 3279 wants
//! it written), a curve OID for EC keys (RFC 5480), a whole SEQUENCE for
//! RSA-PSS. The parameters are kept as a decoded [`Asn1Object`] and are not
//! interpreted here; which shape an algorithm requires is checked by the
//! code that uses it.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Null, Asn1Object, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
    tag,
};

/// An algorithm OID with its optional parameters.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// // sha256WithRSAEncryption: RFC 3279 wants an explicit NULL.
/// let rsa = AlgorithmIdentifier::with_null("1.2.840.113549.1.1.11".parse()?);
/// let der = rsa.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = AlgorithmIdentifier::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, rsa);
/// assert!(matches!(back.parameters(), Some(Asn1Object::Null(_))));
///
/// // ecPublicKey with the curve as parameters.
/// let ec = AlgorithmIdentifier::with_parameters(
///     "1.2.840.10045.2.1".parse()?,
///     "1.2.840.10045.3.1.7".parse::<tc_asn1::Asn1Oid>()?,
/// );
/// if let Some(Asn1Object::Oid(curve)) = ec.parameters() {
///     println!("curve {curve}");   // curve 1.2.840.10045.3.1.7
/// }
///
/// // Ed25519 takes none.
/// let ed = AlgorithmIdentifier::new("1.3.101.112".parse()?);
/// assert!(ed.parameters().is_none());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AlgorithmIdentifier {
    algorithm: Asn1Oid,
    parameters: Option<Asn1Object>,
}

impl AlgorithmIdentifier {
    /// No parameters: the field is absent.
    pub fn new(algorithm: Asn1Oid) -> Self {
        Self {
            algorithm,
            parameters: None,
        }
    }

    /// NULL parameters, as the RSA algorithms of RFC 3279 require.
    pub fn with_null(algorithm: Asn1Oid) -> Self {
        Self {
            algorithm,
            parameters: Some(Asn1Null.into()),
        }
    }

    /// Any parameters; every `tc_asn1` value type converts into
    /// [`Asn1Object`].
    pub fn with_parameters(algorithm: Asn1Oid, parameters: impl Into<Asn1Object>) -> Self {
        Self {
            algorithm,
            parameters: Some(parameters.into()),
        }
    }

    /// The algorithm's OID.
    pub fn algorithm(&self) -> &Asn1Oid {
        &self.algorithm
    }

    /// The parameters as decoded, `None` when the field is absent. An
    /// explicit NULL is `Some(Asn1Object::Null(_))`, which RFC 5280 keeps
    /// distinct from absent.
    pub fn parameters(&self) -> Option<&Asn1Object> {
        self.parameters.as_ref()
    }
}

/// The algorithm OID, followed by ` NULL` or ` (with parameters)`.
impl fmt::Display for AlgorithmIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.algorithm)?;
        match &self.parameters {
            None => Ok(()),
            Some(Asn1Object::Null(_)) => f.write_str(" NULL"),
            Some(_) => f.write_str(" (with parameters)"),
        }
    }
}

impl DecodeContent for AlgorithmIdentifier {
    /// Whatever follows the OID, if anything, is the parameters; as under
    /// `30` on its own or under an IMPLICIT tag. Variable time: branches only
    /// on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut children = Children::from_contents(value, context)?;
        let algorithm: Asn1Oid = children.get()?;
        let parameters = children.get_any_opt()?;
        children.end()?;
        Ok(Self {
            algorithm,
            parameters,
        })
    }
}

impl DecodeInner for AlgorithmIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for AlgorithmIdentifier {}

impl Tagged for AlgorithmIdentifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for AlgorithmIdentifier {
    /// The fields' TLVs back to back. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.algorithm.encoded_len(rules)
            + self.parameters.as_ref().map_or(0, |p| p.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.algorithm.encode(rules, out)?;
        if let Some(parameters) = &self.parameters {
            at += parameters.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for AlgorithmIdentifier {}

impl Encode for AlgorithmIdentifier {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1Error, Asn1Object, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::AlgorithmIdentifier;

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    /// sha256WithRSAEncryption with NULL, as in nearly every RSA certificate.
    const RSA_SHA256: &[u8] = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00";
    /// Ed25519, no parameters.
    const ED25519: &[u8] = b"\x30\x05\x06\x03\x2b\x65\x70";
    /// ecPublicKey with prime256v1.
    const EC_P256: &[u8] =
        b"\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

    #[test]
    fn the_three_parameter_shapes_round_trip() {
        let cases: [(AlgorithmIdentifier, &[u8], &str); 3] = [
            (
                AlgorithmIdentifier::with_null("1.2.840.113549.1.1.11".parse().unwrap()),
                RSA_SHA256,
                "1.2.840.113549.1.1.11 NULL",
            ),
            (
                AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
                ED25519,
                "1.3.101.112",
            ),
            (
                AlgorithmIdentifier::with_parameters(
                    "1.2.840.10045.2.1".parse().unwrap(),
                    "1.2.840.10045.3.1.7".parse::<Asn1Oid>().unwrap(),
                ),
                EC_P256,
                "1.2.840.10045.2.1 (with parameters)",
            ),
        ];
        for (id, wire, text) in cases {
            assert_eq!(id.encode_to_vec(&der()).unwrap(), wire, "{text}");
            let (used, decoded) = AlgorithmIdentifier::decode(wire, &options()).unwrap();
            assert_eq!((used, &decoded), (wire.len(), &id));
            assert_eq!(decoded.to_string(), text);
            assert_eq!(
                AlgorithmIdentifier::decode_der(wire, &options()).unwrap().1,
                id
            );
        }
    }

    #[test]
    fn absent_and_null_parameters_are_different_values() {
        let absent = AlgorithmIdentifier::new("1.2.840.113549.1.1.11".parse().unwrap());
        let null = AlgorithmIdentifier::with_null("1.2.840.113549.1.1.11".parse().unwrap());
        assert_ne!(absent, null);
        assert!(absent.parameters().is_none());
        assert!(matches!(null.parameters(), Some(Asn1Object::Null(_))));
        assert_ne!(
            absent.encode_to_vec(&der()).unwrap(),
            null.encode_to_vec(&der()).unwrap()
        );
    }

    #[test]
    fn structured_parameters_are_kept_as_a_tree() {
        // A made-up SEQUENCE { INTEGER 1, OCTET STRING 'ab' } as parameters.
        let wire = b"\x30\x0e\x06\x03\x2a\x03\x04\x30\x07\x02\x01\x01\x04\x02ab";
        let (_, id) = AlgorithmIdentifier::decode(wire, &options()).unwrap();
        assert_eq!(id.algorithm().to_string(), "1.2.3.4");
        assert!(matches!(
            id.parameters(),
            Some(Asn1Object::SequenceOf(seq)) if seq.elements().len() == 2
        ));
        assert_eq!(id.encode_to_vec(&der()).unwrap(), wire);
    }

    #[test]
    fn ber_parameters_are_accepted_and_normalized_but_not_der() {
        // The NULL parameters inside an indefinite-length SEQUENCE.
        let indefinite = b"\x30\x80\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x00\x00";
        let (used, id) = AlgorithmIdentifier::decode(indefinite, &options()).unwrap();
        assert_eq!(used, indefinite.len());
        assert_eq!(id.encode_to_vec(&der()).unwrap(), RSA_SHA256);
        assert!(matches!(
            AlgorithmIdentifier::decode_der(indefinite, &options()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn missing_oid_and_extra_fields_are_rejected() {
        assert!(matches!(
            AlgorithmIdentifier::decode(b"\x30\x00", &options()),
            Err(Asn1Error::Truncated)
        ));
        assert!(matches!(
            AlgorithmIdentifier::decode(b"\x30\x02\x05\x00", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        let mut extra: Vec<u8> = RSA_SHA256.to_vec();
        extra.extend_from_slice(b"\x05\x00");
        extra[1] += 2;
        assert!(matches!(
            AlgorithmIdentifier::decode(&extra, &options()),
            Err(Asn1Error::TrailingData)
        ));
        assert!(matches!(
            AlgorithmIdentifier::decode(&RSA_SHA256[..6], &options()),
            Err(Asn1Error::Truncated)
        ));
    }
}
