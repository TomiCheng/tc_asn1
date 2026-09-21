use alloc::vec::Vec;

use crate::Asn1Error;
use crate::{EncodingOptions, EncodingType};

/// Writes the contents octets: the value without its tag and length.
///
/// The one layer every type must supply itself. `content_len` and
/// `encode_content` must agree exactly, since the header is written from
/// the former before the latter runs; the provided methods assert this in
/// debug builds. The `rules` decide the form where BER, CER and DER differ,
/// such as whether a SET OF is sorted.
pub trait EncodeContent {
    /// The contents on their own, sized by `content_len`.
    fn encode_content_to_vec(&self, rules: &EncodingOptions) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.content_len(rules)];
        let written = self.encode_content(rules, &mut out)?;
        debug_assert_eq!(
            written,
            out.len(),
            "content_len and encode_content disagree"
        );
        Ok(out)
    }

    /// The number of octets `encode_content` will write under `rules`.
    fn content_len(&self, rules: &EncodingOptions) -> usize;

    /// Writes the contents at the start of `out` and returns the count;
    /// `out` shorter than `content_len` is [`Asn1Error::BufferTooSmall`].
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error>;
}

/// Writes a complete TLV under a tag the caller chooses.
///
/// This is the layer IMPLICIT tagging works at: the tagged-field helpers pass
/// a context-specific tag in place of the type's own. The defaults write an
/// ordinary header (definite length, or indefinite under CER and indefinite
/// BER when the tag is constructed) followed by the contents, and most types
/// take them as they are: `impl EncodeTagged for T {}`. The overrides are the
/// constructed types, which force the constructed bit on whatever tag they
/// are given, and the string types, which refuse a value over 1000 octets
/// under CER with [`Asn1Error::PrimitiveTooLong`] because CER requires the
/// constructed form there.
pub trait EncodeTagged: EncodeContent {
    /// The total TLV length under `tag`.
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        default_encoded_len(self, tag, rules)
    }

    /// Writes the TLV at the start of `out` and returns the count.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        default_encode(self, tag, rules, out)
    }
}

/// Writes a complete TLV under the type's own tag: the method a SEQUENCE
/// calls for each of its fields and the one callers use directly.
///
/// The two required methods are one-liners forwarding to [`EncodeTagged`]
/// with [`Tagged::TAG`](crate::Tagged::TAG); they are not provided because
/// a CHOICE has no single tag and picks one per variant.
pub trait Encode: EncodeTagged {
    /// The whole TLV, sized by `encoded_len`.
    fn encode_to_vec(&self, rules: &EncodingOptions) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.encoded_len(rules)];
        let written = self.encode(rules, &mut out)?;
        debug_assert_eq!(written, out.len(), "encoded_len and encode disagree");
        Ok(out)
    }

    /// The total TLV length under `rules`.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize;

    /// Writes the TLV at the start of `out` and returns the count; `out`
    /// shorter than `encoded_len` is [`Asn1Error::BufferTooSmall`].
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error>;
}

/// Length of an ordinary TLV. Variable time: branches only on the encoding structure.
pub(crate) fn default_encoded_len<T: EncodeContent + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: &EncodingOptions,
) -> usize {
    let len = value.content_len(rules);
    tag.len()
        + if uses_indefinite(tag, rules) {
            1 + len + 2
        } else {
            len_octets(len) + len
        }
}

const fn uses_indefinite(tag: &[u8], rules: &EncodingOptions) -> bool {
    matches!(
        rules.encoding_type(),
        EncodingType::Cer | EncodingType::Ber(crate::LengthForm::Indefinite)
    ) && tag[0] & 0x20 != 0
}

/// Writes an ordinary TLV. Variable time: branches only on the encoding structure.
pub(crate) fn default_encode<T: EncodeContent + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: &EncodingOptions,
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    let content_len = value.content_len(rules);
    let indefinite = uses_indefinite(tag, rules);
    let total = tag.len()
        + if indefinite {
            1 + content_len + 2
        } else {
            len_octets(content_len) + content_len
        };
    let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
    out[..tag.len()].copy_from_slice(tag);
    let mut at = tag.len();
    if indefinite {
        out[at] = 0x80;
        at += 1;
    } else {
        at += write_len(content_len, &mut out[at..]);
    }
    let written = value.encode_content(rules, &mut out[at..at + content_len])?;
    debug_assert_eq!(
        written, content_len,
        "content_len and encode_content disagree"
    );
    if indefinite {
        out[at + content_len..].fill(0);
    }
    Ok(total)
}

pub(crate) const fn len_octets(length: usize) -> usize {
    if length < 0x80 {
        1
    } else {
        1 + (usize::BITS - length.leading_zeros()).div_ceil(8) as usize
    }
}

pub(crate) fn write_len(length: usize, out: &mut [u8]) -> usize {
    if length < 0x80 {
        out[0] = length as u8;
        return 1;
    }
    let count = len_octets(length) - 1;
    out[0] = 0x80 | count as u8;
    for (index, slot) in out[1..=count].iter_mut().enumerate() {
        *slot = (length >> (8 * (count - 1 - index))) as u8;
    }
    1 + count
}
