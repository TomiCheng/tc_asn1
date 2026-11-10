//! RFC 5280 §5.1.2.6 revoked certificate entry.
//!
//! ```text
//! RevokedCertificate ::= SEQUENCE {
//!     userCertificate    CertificateSerialNumber,
//!     revocationDate     Time,
//!     crlEntryExtensions Extensions OPTIONAL }
//! ```
//!
//! Serial numbers are retained without imposing a machine-integer size limit.
//! The enclosing CRL checks that entry extensions are used only with v2.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{cert::Time, ext::Extensions};

/// A revoked certificate's serial number, revocation time and optional extensions.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{cert::Time, crl::RevokedCertificate};
///
/// let entry = RevokedCertificate::new(42.into(), Time::new(2026, 1, 1, 0, 0, 0)?);
/// let der = entry.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(RevokedCertificate::decode_der(&der, &DecodingOptions::default())?.1, entry);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RevokedCertificate {
    user_certificate: Asn1Integer,
    revocation_date: Time,
    extensions: Option<Extensions>,
}

impl RevokedCertificate {
    /// Creates an entry without extensions. Serial numbers are kept as supplied.
    pub fn new(user_certificate: Asn1Integer, revocation_date: Time) -> Self {
        Self {
            user_certificate,
            revocation_date,
            extensions: None,
        }
    }

    /// Attaches entry extensions; the enclosing CRL must use version v2.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Returns the revoked certificate's serial number.
    pub fn user_certificate(&self) -> &Asn1Integer {
        &self.user_certificate
    }

    /// Returns the revocation time.
    pub fn revocation_date(&self) -> &Time {
        &self.revocation_date
    }

    /// Returns entry extensions, if present.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeInner for RevokedCertificate {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let user_certificate = fields.get()?;
        let revocation_date = fields.get()?;
        let extensions = fields.get_opt()?;
        fields.end()?;
        Ok((
            element.total_len(),
            Self {
                user_certificate,
                revocation_date,
                extensions,
            },
        ))
    }
}

impl EncodeContent for RevokedCertificate {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.user_certificate.encoded_len(rules)
            + self.revocation_date.encoded_len(rules)
            + self.extensions.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.user_certificate.encode(rules, out)?;
        at += self.revocation_date.encode(rules, &mut out[at..])?;
        if let Some(value) = &self.extensions {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RevokedCertificate {}

impl Tagged for RevokedCertificate {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RevokedCertificate {}

impl Encode for RevokedCertificate {
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

    use super::RevokedCertificate;
    use crate::{
        cert::Time,
        crl::CrlReason,
        ext::{Extension, ExtensionId, Extensions},
    };

    #[test]
    fn a_revoked_serial_and_utc_date_have_the_expected_sequence_encoding() {
        let entry = RevokedCertificate::new(42.into(), Time::new(2026, 1, 1, 0, 0, 0).unwrap());
        let wire = b"\x30\x12\x02\x01\x2a\x17\x0d260101000000Z";
        assert_eq!(entry.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            RevokedCertificate::decode_der(wire, &DecodingOptions::default())
                .unwrap()
                .1,
            entry
        );
    }

    #[test]
    fn entry_extensions_and_generalized_revocation_dates_round_trip() {
        let extensions = Extensions::new(vec![
            Extension::with_value(ExtensionId::CRL_REASONS, false, &CrlReason::CertificateHold)
                .unwrap(),
        ])
        .unwrap();
        let entry = RevokedCertificate::new(1.into(), Time::new(2051, 1, 1, 0, 0, 0).unwrap())
            .with_extensions(extensions);
        let der = entry.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            RevokedCertificate::decode_der(&der, &DecodingOptions::default())
                .unwrap()
                .1,
            entry
        );
    }

    #[test]
    fn missing_dates_wrong_serial_tags_and_extra_fields_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x03\x02\x01\x01"[..], Asn1Error::Truncated),
            (&b"\x30\x03\x0a\x01\x01"[..], Asn1Error::UnexpectedTag),
            (
                &b"\x30\x14\x02\x01\x01\x17\x0d260101000000Z\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                RevokedCertificate::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
