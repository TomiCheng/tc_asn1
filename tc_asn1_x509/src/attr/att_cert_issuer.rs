//! RFC 5755 §4.1 attribute certificate issuer CHOICE.
//!
//! ```text
//! AttCertIssuer ::= CHOICE {
//!     v1Form     GeneralNames,
//!     v2Form [0] V2Form }
//! ```
//!
//! The v2 form is IMPLICIT. Both forms are retained; RFC 5755 requires
//! the v2 form in conforming certificates, a policy for the validator.

use alloc::boxed::Box;

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

use crate::{attr::V2Form, name::GeneralNames};

/// Identifies an attribute authority by names or a version-two form.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::{attr::{AttCertIssuer, V2Form}, name::{GeneralName, GeneralNames}};
///
/// let names = GeneralNames::new(vec![GeneralName::DirectoryName("CN=AA".parse()?)])?;
/// let issuer = AttCertIssuer::from(V2Form::new(Some(names), None, None)?);
/// assert_eq!(issuer.encode_to_vec(&EncodingOptions::DER)?[0], 0xa0);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AttCertIssuer {
    /// Issuer names; not used by the RFC 5755 profile.
    V1Form(GeneralNames),
    /// A version-two issuer, encoded with an IMPLICIT `[0]` tag.
    V2Form(Box<V2Form>),
}

impl From<GeneralNames> for AttCertIssuer {
    fn from(value: GeneralNames) -> Self {
        Self::V1Form(value)
    }
}

impl From<V2Form> for AttCertIssuer {
    fn from(value: V2Form) -> Self {
        Self::V2Form(Box::new(value))
    }
}

impl AttCertIssuer {
    /// Borrows the version-two issuer without exposing its storage wrapper.
    /// Returns `None` for the version-one form.
    pub fn v2_form(&self) -> Option<&V2Form> {
        match self {
            Self::V1Form(_) => None,
            Self::V2Form(value) => Some(value),
        }
    }

    fn tag(&self) -> &'static [u8] {
        match self {
            Self::V1Form(_) => &[0x30],
            Self::V2Form(_) => &[0xa0],
        }
    }
}

impl DecodeInner for AttCertIssuer {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x30] => Self::V1Form(GeneralNames::decode_content(element.value(), context)?),
            [0xa0] => Self::from(V2Form::decode_content(element.value(), context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for AttCertIssuer {}

impl EncodeContent for AttCertIssuer {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::V1Form(value) => value.content_len(rules),
            Self::V2Form(value) => value.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::V1Form(value) => value.encode_content(rules, out),
            Self::V2Form(value) => value.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for AttCertIssuer {}

impl Encode for AttCertIssuer {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag(), rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag(), rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::AttCertIssuer;
    use crate::{
        attr::V2Form,
        name::{GeneralName, GeneralNames},
    };

    #[test]
    fn the_v2_accessor_borrows_the_form_and_returns_none_for_v1() {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        let form = V2Form::new(Some(names.clone()), None, None).unwrap();
        let v2 = AttCertIssuer::from(form.clone());
        assert_eq!(v2.v2_form(), Some(&form));
        assert_eq!(AttCertIssuer::from(names).v2_form(), None);
    }

    #[test]
    fn issuer_choices_use_sequence_for_v1_and_implicit_a0_for_v2() {
        let names = GeneralNames::new(vec![GeneralName::dns_name("a").unwrap()]).unwrap();
        for (value, wire) in [
            (
                AttCertIssuer::from(names.clone()),
                &b"\x30\x03\x82\x01a"[..],
            ),
            (
                AttCertIssuer::from(V2Form::new(Some(names), None, None).unwrap()),
                &b"\xa0\x05\x30\x03\x82\x01a"[..],
            ),
        ] {
            assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
            assert_eq!(
                AttCertIssuer::decode_der(wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn issuer_choice_rejects_unknown_tags_and_an_explicit_v2_wrapper() {
        for wire in [&b"\xa1\x00"[..], &b"\xa0\x07\x30\x05\x30\x03\x82\x01a"[..]] {
            assert_eq!(
                AttCertIssuer::decode_der(wire, &DecodingOptions::default()),
                Err(Asn1Error::UnexpectedTag)
            );
        }
    }

    #[test]
    fn ber_indefinite_v2_issuers_decode_through_the_shared_context() {
        let wire = b"\xa0\x80\x30\x03\x82\x01a\x00\x00";
        let value = AttCertIssuer::decode(wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            b"\xa0\x05\x30\x03\x82\x01a"
        );
        assert_eq!(
            AttCertIssuer::decode_der(wire, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
    }
}
