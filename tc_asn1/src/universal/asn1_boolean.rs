//! X.690 §8.2 BOOLEAN, universal tag 1.
//!
//! One contents octet: `00` is FALSE and anything else is TRUE. DER (§11.1)
//! writes TRUE as `FF` only; this crate always writes `FF`, and rejects the
//! other nonzero octets when the DER rules are on.

use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodingOptions, Tagged,
};

/// A `bool` with the BOOLEAN encoding.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
///
/// let der = EncodingOptions::DER;
/// let options = DecodingOptions::default();
///
/// assert_eq!(Asn1Boolean::from(true).encode_to_vec(&der)?, [0x01, 0x01, 0xFF]);
/// assert_eq!(Asn1Boolean::from(false).encode_to_vec(&der)?, [0x01, 0x01, 0x00]);
///
/// // BER takes any nonzero octet as TRUE; DER insists on FF.
/// let (_, lenient) = Asn1Boolean::decode(&[0x01, 0x01, 0x01], &options)?;
/// assert!(lenient.is_true());
/// assert!(matches!(
///     Asn1Boolean::decode_der(&[0x01, 0x01, 0x01], &options),
///     Err(Asn1Error::NotDer)
/// ));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Boolean(bool);

impl Asn1Boolean {
    pub const TAG: &'static [u8] = super::tag::BOOLEAN;

    pub const fn is_true(&self) -> bool {
        self.0
    }

    pub const fn is_false(&self) -> bool {
        !self.0
    }
}

impl From<bool> for Asn1Boolean {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

/// `TRUE` or `FALSE`, as ASN.1 writes them.
impl core::fmt::Display for Asn1Boolean {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.pad(if self.0 { "TRUE" } else { "FALSE" })
    }
}

impl DecodeInner for Asn1Boolean {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}
impl Decode for Asn1Boolean {}

impl Tagged for Asn1Boolean {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Boolean {
    /// Anything but exactly one octet is `MalformedValue`; a nonzero octet
    /// other than `FF` is `NotDer` under DER. Variable time: branches on
    /// the octet, which is a public value.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        match value {
            // BER accepts any nonzero octet as TRUE; DER writes TRUE as FF only
            // (X.690 §11.1). Re-encoding normalizes to FF either way.
            [octet] => {
                if context.is_der() && !matches!(octet, 0x00 | 0xFF) {
                    return Err(Asn1Error::NotDer);
                }
                Ok(Asn1Boolean(*octet != 0))
            }
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl crate::EncodeContent for Asn1Boolean {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        1
    }

    /// `FF` or `00` under every rule set. Constant time in the value.
    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let octet = out.first_mut().ok_or(Asn1Error::BufferTooSmall)?;
        *octet = u8::from(self.0).wrapping_neg();
        Ok(1)
    }
}

impl crate::EncodeTagged for Asn1Boolean {}

impl Encode for Asn1Boolean {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::Asn1Boolean;
    use crate::{
        Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions, EncodingType, LengthForm,
    };

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn true_is_ff_and_false_is_00_under_every_rule_set() {
        for rules in [
            EncodingType::Ber(LengthForm::Definite),
            EncodingType::Ber(LengthForm::Indefinite),
            EncodingType::Cer,
            EncodingType::Der,
        ] {
            let rules = EncodingOptions::new(rules);
            assert_eq!(
                Asn1Boolean::from(true).encode_to_vec(&rules).unwrap(),
                [0x01, 0x01, 0xFF]
            );
            assert_eq!(
                Asn1Boolean::from(false).encode_to_vec(&rules).unwrap(),
                [0x01, 0x01, 0x00]
            );
        }
    }

    #[test]
    fn any_nonzero_octet_is_true_under_ber_but_only_ff_under_der() {
        for octet in [0x01, 0x7F, 0x80, 0xFF] {
            let wire = [0x01, 0x01, octet];
            let (used, value) = Asn1Boolean::decode(&wire, &options()).unwrap();
            assert_eq!((used, value.is_true()), (3, true));
            let strict = Asn1Boolean::decode_der(&wire, &options());
            if octet == 0xFF {
                assert!(strict.unwrap().1.is_true());
            } else {
                assert!(matches!(strict, Err(Asn1Error::NotDer)));
            }
        }
        let (_, value) = Asn1Boolean::decode_der(&[0x01, 0x01, 0x00], &options()).unwrap();
        assert!(value.is_false());
    }

    #[test]
    fn a_lenient_true_re_encodes_as_ff() {
        let (_, value) = Asn1Boolean::decode(&[0x01, 0x01, 0x01], &options()).unwrap();
        assert_eq!(
            value.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0x01, 0x01, 0xFF]
        );
    }

    #[test]
    fn a_contents_length_other_than_one_is_malformed() {
        for wire in [&[0x01, 0x00][..], &[0x01, 0x02, 0x00, 0x00]] {
            assert!(matches!(
                Asn1Boolean::decode(wire, &options()),
                Err(Asn1Error::MalformedValue)
            ));
        }
    }

    #[test]
    fn another_tag_is_unexpected() {
        assert!(matches!(
            Asn1Boolean::decode(&[0x02, 0x01, 0x01], &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn it_converts_from_bool_and_displays_in_asn1_notation() {
        let value = Asn1Boolean::from(true);
        assert!(value.is_true());
        assert!(!value.is_false());
        assert_eq!(value.to_string(), "TRUE");
        assert_eq!(Asn1Boolean::from(false).to_string(), "FALSE");
        assert_eq!(alloc::format!("{value:>6}|"), "  TRUE|");
    }
}
