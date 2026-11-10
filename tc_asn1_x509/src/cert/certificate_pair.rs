//! X.509 §11.2.3 cross-certificate pair, the value of the `crossCertificatePair` attribute.
//!
//! ```text
//! CertificatePair ::= SEQUENCE {
//!     forward [0] Certificate OPTIONAL,
//!     reverse [1] Certificate OPTIONAL
//!     -- at least one of the pair shall be present -- }
//! ```
//!
//! Both fields use EXPLICIT tags, as Bouncy Castle reads them. `forward` holds a
//! certificate issued to this CA and `reverse` one issued by it to another CA.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::cert::Certificate;

const FORWARD: &[u8] = &[0xa0];
const REVERSE: &[u8] = &[0xa1];

/// A forward certificate, a reverse certificate, or both.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions};
/// use tc_asn1_x509::cert::{Certificate, CertificatePair};
///
/// # let der = include_bytes!("../../tests/data/rfc8410.der");
/// let (_, certificate) = Certificate::decode(der, &DecodingOptions::default())?;
/// let pair = CertificatePair::new(Some(certificate), None)?;
/// assert!(pair.reverse().is_none());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificatePair {
    forward: Option<Certificate>,
    reverse: Option<Certificate>,
}

impl CertificatePair {
    /// Creates a pair; both halves absent returns `MalformedValue`.
    pub fn new(
        forward: Option<Certificate>,
        reverse: Option<Certificate>,
    ) -> Result<Self, Asn1Error> {
        if forward.is_none() && reverse.is_none() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { forward, reverse })
    }

    /// Returns the certificate issued to this CA, if present.
    pub fn forward(&self) -> Option<&Certificate> {
        self.forward.as_ref()
    }

    /// Returns the certificate issued by this CA to another CA, if present.
    pub fn reverse(&self) -> Option<&Certificate> {
        self.reverse.as_ref()
    }
}

impl DecodeContent for CertificatePair {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let forward = fields.get_explicit_opt::<Certificate>(FORWARD)?;
        let reverse = fields.get_explicit_opt::<Certificate>(REVERSE)?;
        fields.end()?;
        Self::new(forward, reverse)
    }
}

impl DecodeInner for CertificatePair {
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

impl EncodeContent for CertificatePair {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.forward
            .as_ref()
            .map_or(0, |value| Explicit::new(FORWARD, value).encoded_len(rules))
            + self
                .reverse
                .as_ref()
                .map_or(0, |value| Explicit::new(REVERSE, value).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(value) = &self.forward {
            at += Explicit::new(FORWARD, value).encode(rules, &mut out[at..])?;
        }
        if let Some(value) = &self.reverse {
            at += Explicit::new(REVERSE, value).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertificatePair {}

impl Tagged for CertificatePair {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertificatePair {}

impl Encode for CertificatePair {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::CertificatePair;
    use crate::cert::Certificate;

    /// RFC 8410's example certificate; see `tests/data/README.md`.
    const RFC_8410: &[u8] = include_bytes!("../../tests/data/rfc8410.der");

    fn certificate() -> Certificate {
        Certificate::decode(RFC_8410, &DecodingOptions::default())
            .unwrap()
            .1
    }

    #[test]
    fn each_half_and_both_round_trip_under_explicit_tags() {
        for (forward, reverse) in [(true, false), (false, true), (true, true)] {
            let pair =
                CertificatePair::new(forward.then(certificate), reverse.then(certificate)).unwrap();
            let wire = pair.encode_to_vec(&EncodingOptions::DER).unwrap();
            // the first field is [0] or [1] wrapping the certificate's own SEQUENCE
            assert_eq!(wire[4], if forward { 0xa0 } else { 0xa1 });
            assert_eq!(wire[8], 0x30);
            let (used, back) = CertificatePair::decode(&wire, &DecodingOptions::default()).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(back, pair);
        }
    }

    #[test]
    fn an_empty_pair_is_rejected_when_constructed_or_decoded() {
        assert_eq!(
            CertificatePair::new(None, None),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            CertificatePair::decode_der(b"\x30\x00", &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn halves_out_of_order_are_rejected() {
        let pair = CertificatePair::new(Some(certificate()), Some(certificate())).unwrap();
        let mut wire = pair.encode_to_vec(&EncodingOptions::DER).unwrap();
        // swap the two context tags so reverse comes first
        let second = 4 + (wire.len() - 4) / 2;
        wire[4] = 0xa1;
        wire[second] = 0xa0;
        assert!(CertificatePair::decode(&wire, &DecodingOptions::default()).is_err());
    }
}
