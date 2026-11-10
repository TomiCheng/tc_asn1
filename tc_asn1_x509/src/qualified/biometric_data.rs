//! RFC 3739 §3.2.2 biometric data, one entry of the biometricInfo extension.
//!
//! ```text
//! BiometricData ::= SEQUENCE {
//!     typeOfBiometricData TypeOfBiometricData,
//!     hashAlgorithm       AlgorithmIdentifier,
//!     biometricDataHash   OCTET STRING,
//!     sourceDataUri       IA5String OPTIONAL }
//! ```
//!
//! The extension value is `SEQUENCE OF BiometricData`, read as
//! `Asn1SequenceOf<BiometricData>`. Whether the hash matches the source data
//! belongs to the verifier.

use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged,
    tag,
};

use crate::{alg::AlgorithmIdentifier, qualified::TypeOfBiometricData};

/// A hash of biometric data of some type, with where to fetch the data.
///
/// ```
/// use tc_asn1::{Asn1Ia5String, Asn1OctetString};
/// use tc_asn1_x509::{alg::AlgorithmIdentifier, qualified::{BiometricData, TypeOfBiometricData}};
///
/// // id-sha256
/// let sha256 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse()?);
/// let picture = BiometricData::new(
///     TypeOfBiometricData::Picture,
///     sha256,
///     Asn1OctetString::new(&[0; 32]),
/// )
/// .with_source_data_uri(Asn1Ia5String::new("https://example.com/photo.jpg")?);
/// assert_eq!(picture.type_of_biometric_data(), &TypeOfBiometricData::Picture);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct BiometricData {
    type_of_biometric_data: TypeOfBiometricData,
    hash_algorithm: AlgorithmIdentifier,
    biometric_data_hash: Asn1OctetString,
    source_data_uri: Option<Asn1Ia5String>,
}

impl BiometricData {
    /// Creates the entry without `sourceDataUri`.
    pub fn new(
        type_of_biometric_data: TypeOfBiometricData,
        hash_algorithm: AlgorithmIdentifier,
        biometric_data_hash: Asn1OctetString,
    ) -> Self {
        Self {
            type_of_biometric_data,
            hash_algorithm,
            biometric_data_hash,
            source_data_uri: None,
        }
    }

    /// Sets `sourceDataUri`.
    pub fn with_source_data_uri(mut self, source_data_uri: Asn1Ia5String) -> Self {
        self.source_data_uri = Some(source_data_uri);
        self
    }

    /// Returns `typeOfBiometricData`.
    pub fn type_of_biometric_data(&self) -> &TypeOfBiometricData {
        &self.type_of_biometric_data
    }

    /// Returns `hashAlgorithm`.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns `biometricDataHash`.
    pub fn biometric_data_hash(&self) -> &Asn1OctetString {
        &self.biometric_data_hash
    }

    /// Returns `sourceDataUri`, if present.
    pub fn source_data_uri(&self) -> Option<&Asn1Ia5String> {
        self.source_data_uri.as_ref()
    }
}

impl DecodeContent for BiometricData {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let type_of_biometric_data = fields.get()?;
        let hash_algorithm = fields.get()?;
        let biometric_data_hash = fields.get()?;
        let source_data_uri = fields.get_opt()?;
        fields.end()?;
        Ok(Self {
            type_of_biometric_data,
            hash_algorithm,
            biometric_data_hash,
            source_data_uri,
        })
    }
}

impl DecodeInner for BiometricData {
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

impl EncodeContent for BiometricData {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.type_of_biometric_data.encoded_len(rules)
            + self.hash_algorithm.encoded_len(rules)
            + self.biometric_data_hash.encoded_len(rules)
            + self
                .source_data_uri
                .as_ref()
                .map_or(0, |value| value.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.type_of_biometric_data.encode(rules, out)?;
        at += self.hash_algorithm.encode(rules, &mut out[at..])?;
        at += self.biometric_data_hash.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.source_data_uri {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for BiometricData {}

impl Tagged for BiometricData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for BiometricData {}

impl Encode for BiometricData {
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
        Asn1Ia5String, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::BiometricData;
    use crate::{alg::AlgorithmIdentifier, qualified::TypeOfBiometricData};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn entry() -> BiometricData {
        BiometricData::new(
            TypeOfBiometricData::HandwrittenSignature,
            AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
            Asn1OctetString::new(&[0xab]),
        )
    }

    #[test]
    fn the_entry_round_trips_without_a_source_uri() {
        let wire = b"\x30\x0c\x02\x01\x01\x30\x04\x06\x02\x2a\x03\x04\x01\xab";
        assert_eq!(entry().encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        let back = BiometricData::decode_der(wire, &options()).unwrap().1;
        assert_eq!(back, entry());
        assert!(back.source_data_uri().is_none());
    }

    #[test]
    fn the_source_uri_follows_the_hash() {
        let value = entry().with_source_data_uri(Asn1Ia5String::new("u").unwrap());
        let wire = b"\x30\x0f\x02\x01\x01\x30\x04\x06\x02\x2a\x03\x04\x01\xab\x16\x01u";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        let back = BiometricData::decode_der(wire, &options()).unwrap().1;
        assert_eq!(back.source_data_uri().map(Asn1Ia5String::as_str), Some("u"));
    }

    #[test]
    fn a_missing_hash_or_a_trailing_field_is_rejected() {
        assert!(
            BiometricData::decode_der(b"\x30\x09\x02\x01\x01\x30\x04\x06\x02\x2a\x03", &options())
                .is_err()
        );
        assert!(
            BiometricData::decode_der(
                b"\x30\x0e\x02\x01\x01\x30\x04\x06\x02\x2a\x03\x04\x01\xab\x05\x00",
                &options()
            )
            .is_err()
        );
    }
}
