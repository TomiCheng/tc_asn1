//! `PublicKeyAndChallenge`, what the browser signs in an SPKAC.
//!
//! ```text
//! PublicKeyAndChallenge ::= SEQUENCE {
//!     spki      SubjectPublicKeyInfo,
//!     challenge IA5STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::cert::SubjectPublicKeyInfo;

/// The new public key and the challenge the server sent.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKeyAndChallenge {
    spki: SubjectPublicKeyInfo,
    challenge: Asn1Ia5String,
}

impl PublicKeyAndChallenge {
    /// The public key and the challenge.
    /// Variable time: branches only on the encoding structure.
    pub fn new(spki: SubjectPublicKeyInfo, challenge: Asn1Ia5String) -> Self {
        Self { spki, challenge }
    }

    /// Returns the public key.
    /// Variable time: branches only on the encoding structure.
    pub fn spki(&self) -> &SubjectPublicKeyInfo {
        &self.spki
    }

    /// Returns the challenge.
    /// Variable time: branches only on the encoding structure.
    pub fn challenge(&self) -> &Asn1Ia5String {
        &self.challenge
    }
}

impl DecodeContent for PublicKeyAndChallenge {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let spki = fields.get()?;
        let challenge = fields.get()?;
        fields.end()?;
        let value = Self { spki, challenge };
        Ok(value)
    }
}

impl DecodeInner for PublicKeyAndChallenge {
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

impl EncodeContent for PublicKeyAndChallenge {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.spki.encoded_len(rules) + self.challenge.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.spki.encode(rules, out)?;
        at += self.challenge.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for PublicKeyAndChallenge {}

impl Tagged for PublicKeyAndChallenge {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PublicKeyAndChallenge {}

impl Encode for PublicKeyAndChallenge {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
