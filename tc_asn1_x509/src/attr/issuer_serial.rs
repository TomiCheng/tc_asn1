//! RFC 5755 §4.1 issuer names, serial number and optional issuer identifier.
//!
//! ```text
//! IssuerSerial ::= SEQUENCE {
//!     issuer    GeneralNames,
//!     serial    CertificateSerialNumber,
//!     issuerUID UniqueIdentifier OPTIONAL }
//! ```
//!
//! Serial numbers and issuer identifiers are retained without profile checks.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::name::GeneralNames;

/// Identifies a certificate by its issuer and serial number.
///
/// ```
/// use tc_asn1_x509::{attr::IssuerSerial, name::{GeneralName, GeneralNames}};
///
/// let issuer = GeneralNames::new(vec![GeneralName::DirectoryName("CN=CA".parse()?)])?;
/// let reference = IssuerSerial::new(issuer, 42.into());
/// assert_eq!(reference.serial(), &42.into());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IssuerSerial {
    issuer: GeneralNames,
    serial: Asn1Integer,
    issuer_uid: Option<Asn1BitString>,
}

impl IssuerSerial {
    /// Creates a certificate reference without an issuer unique identifier.
    pub fn new(issuer: GeneralNames, serial: Asn1Integer) -> Self {
        Self {
            issuer,
            serial,
            issuer_uid: None,
        }
    }

    /// Sets the issuer unique identifier without interpreting its bits.
    pub fn with_issuer_uid(mut self, issuer_uid: Asn1BitString) -> Self {
        self.issuer_uid = Some(issuer_uid);
        self
    }

    /// Returns the issuer names in wire order.
    pub fn issuer(&self) -> &GeneralNames {
        &self.issuer
    }

    /// Returns the full, arbitrary-precision serial number.
    pub fn serial(&self) -> &Asn1Integer {
        &self.serial
    }

    /// Returns the optional issuer unique identifier.
    pub fn issuer_uid(&self) -> Option<&Asn1BitString> {
        self.issuer_uid.as_ref()
    }
}

impl DecodeContent for IssuerSerial {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let issuer = fields.get()?;
        let serial = fields.get()?;
        let issuer_uid = fields.get_opt()?;
        fields.end()?;
        Ok(Self {
            issuer,
            serial,
            issuer_uid,
        })
    }
}

impl DecodeInner for IssuerSerial {
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

impl EncodeContent for IssuerSerial {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.issuer.encoded_len(rules)
            + self.serial.encoded_len(rules)
            + self.issuer_uid.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.issuer.encode(rules, out)?;
        at += self.serial.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.issuer_uid {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for IssuerSerial {}

impl Tagged for IssuerSerial {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for IssuerSerial {}

impl Encode for IssuerSerial {
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

    use super::IssuerSerial;
    use crate::name::{GeneralName, GeneralNames};

    #[test]
    fn issuer_names_and_serial_have_no_extra_context_wrappers() {
        let value = IssuerSerial::new(
            GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap(),
            42.into(),
        );
        let wire = b"\x30\x08\x30\x03\x82\x01a\x02\x01\x2a";
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            IssuerSerial::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn issuer_identifiers_and_serials_larger_than_u32_round_trip() {
        let value = IssuerSerial::new(
            GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap(),
            (1u64 << 40).into(),
        )
        .with_issuer_uid(Asn1BitString::from_bytes(&[0xab]));
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            IssuerSerial::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn absent_serials_wrong_issuer_tags_and_extra_fields_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x05\x30\x03\x82\x01a"[..], Asn1Error::Truncated),
            (&b"\x30\x02\x05\x00"[..], Asn1Error::UnexpectedTag),
            (
                &b"\x30\x0a\x30\x03\x82\x01a\x02\x01\x01\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                IssuerSerial::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
