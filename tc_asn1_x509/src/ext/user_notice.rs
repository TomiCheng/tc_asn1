//! A certificate policy notice with an optional reference and explicit text.
//!
//! ```text
//! UserNotice ::= SEQUENCE {
//!     noticeRef    NoticeReference OPTIONAL,
//!     explicitText DisplayText OPTIONAL }
//! ```

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Tagged, tag,
};

use crate::ext::{DisplayText, NoticeReference};

/// Either or both forms of a user notice. An entirely empty notice is valid.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::{DisplayText, UserNotice};
///
/// let notice = UserNotice::new(None, Some(DisplayText::new("For authorized use only")?));
/// assert_eq!(notice.explicit_text().unwrap().as_str(), "For authorized use only");
/// let der = notice.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(UserNotice::decode_der(&der, &DecodingOptions::default())?.1, notice);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UserNotice {
    notice_ref: Option<NoticeReference>,
    explicit_text: Option<DisplayText>,
}

impl UserNotice {
    /// Creates a notice; both arguments may be absent.
    pub fn new(notice_ref: Option<NoticeReference>, explicit_text: Option<DisplayText>) -> Self {
        Self {
            notice_ref,
            explicit_text,
        }
    }

    /// Returns the reference, if present.
    pub fn notice_ref(&self) -> Option<&NoticeReference> {
        self.notice_ref.as_ref()
    }

    /// Returns the explicit text, if present.
    pub fn explicit_text(&self) -> Option<&DisplayText> {
        self.explicit_text.as_ref()
    }
}

impl fmt::Display for UserNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(v) = &self.notice_ref {
            write!(f, "{v}")?;
        }
        if let Some(v) = &self.explicit_text {
            if self.notice_ref.is_some() {
                f.write_str(", ")?;
            }
            write!(f, "{v}")?;
        }
        Ok(())
    }
}

impl DecodeInner for UserNotice {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let notice_ref = fields.get_opt::<NoticeReference>()?;
        let explicit_text = fields.get_any_opt::<DisplayText>()?;
        fields.end()?;
        Ok((element.total_len(), Self::new(notice_ref, explicit_text)))
    }
}

impl EncodeContent for UserNotice {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.notice_ref.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self
                .explicit_text
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.notice_ref {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.explicit_text {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for UserNotice {}

impl Tagged for UserNotice {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for UserNotice {}

impl Encode for UserNotice {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::UserNotice;
    use crate::ext::{DisplayText, NoticeReference};
    use alloc::vec;
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    #[test]
    fn all_four_optional_field_combinations_round_trip() {
        for reference in [false, true] {
            for text in [false, true] {
                let value = UserNotice::new(
                    reference.then(|| NoticeReference::new(DisplayText::new("O").unwrap(), vec![])),
                    text.then(|| DisplayText::new("Notice").unwrap()),
                );
                let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
                assert_eq!(
                    UserNotice::decode_der(&der, &DecodingOptions::default()).unwrap(),
                    (der.len(), value)
                );
            }
        }
        assert_eq!(
            UserNotice::new(None, None)
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            b"\x30\x00"
        );
    }

    #[test]
    fn extra_text_and_wrong_text_tags_are_rejected() {
        assert!(matches!(
            UserNotice::decode(b"\x30\x06\x0c\x01a\x0c\x01b", &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        ));
        assert!(matches!(
            UserNotice::decode(b"\x30\x03\x13\x01a", &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
