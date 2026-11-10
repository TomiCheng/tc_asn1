//! `SignedPublicKeyAndChallenge` (SPKAC), the certificate request of the
//! Netscape and Mozilla `<keygen>` element.
//!
//! ```text
//! SignedPublicKeyAndChallenge ::= SEQUENCE {
//!     publicKeyAndChallenge PublicKeyAndChallenge,
//!     signatureAlgorithm    AlgorithmIdentifier,
//!     signature             BIT STRING }
//! ```

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::alg::AlgorithmIdentifier;
use crate::netscape::PublicKeyAndChallenge;

/// The public key and challenge, signed with the matching private key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedPublicKeyAndChallenge {
    public_key_and_challenge: PublicKeyAndChallenge,
    signature_algorithm: AlgorithmIdentifier,
    signature: Asn1BitString,
}

impl SignedPublicKeyAndChallenge {
    /// The signed content, the algorithm and the signature.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        public_key_and_challenge: PublicKeyAndChallenge,
        signature_algorithm: AlgorithmIdentifier,
        signature: Asn1BitString,
    ) -> Self {
        Self {
            public_key_and_challenge,
            signature_algorithm,
            signature,
        }
    }

    /// Returns what was signed.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key_and_challenge(&self) -> &PublicKeyAndChallenge {
        &self.public_key_and_challenge
    }

    /// Returns the signature algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature over the DER `PublicKeyAndChallenge`.
    /// Variable time: branches only on the encoding structure.
    pub fn signature(&self) -> &Asn1BitString {
        &self.signature
    }
}

impl DecodeContent for SignedPublicKeyAndChallenge {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let public_key_and_challenge = fields.get()?;
        let signature_algorithm = fields.get()?;
        let signature = fields.get()?;
        fields.end()?;
        let value = Self {
            public_key_and_challenge,
            signature_algorithm,
            signature,
        };
        Ok(value)
    }
}

impl DecodeInner for SignedPublicKeyAndChallenge {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for SignedPublicKeyAndChallenge {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.public_key_and_challenge.encoded_len(rules)
            + self.signature_algorithm.encoded_len(rules)
            + self.signature.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.public_key_and_challenge.encode(rules, out)?;
        at += self.signature_algorithm.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for SignedPublicKeyAndChallenge {}

impl Tagged for SignedPublicKeyAndChallenge {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SignedPublicKeyAndChallenge {}

impl Encode for SignedPublicKeyAndChallenge {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};

    use crate::netscape::SignedPublicKeyAndChallenge;

    const SPKAC: &[u8] = include_bytes!("../../tests/data/spkac.der");

    #[test]
    fn bc_spkac_round_trips_byte_for_byte() {
        let (len, spkac) =
            SignedPublicKeyAndChallenge::decode_der(SPKAC, &DecodingOptions::default()).unwrap();
        assert_eq!(len, SPKAC.len());
        assert_eq!(spkac.encode_to_vec(&EncodingOptions::DER).unwrap(), SPKAC);
        assert_eq!(spkac.public_key_and_challenge().challenge().as_str(), "");
    }
}
