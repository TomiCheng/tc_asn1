//! CER's limit on primitive strings (X.690 §9.2) and the constructed bit.

use alloc::vec::Vec;

use crate::{EncodingOptions, EncodingType};

/// CER writes a string primitive up to this many contents octets and
/// otherwise as 1000-octet segments.
pub(crate) const CER_SEGMENT_LEN: usize = 1000;

/// Whether CER forbids the primitive form for contents of this length.
pub(crate) fn too_long_for_cer(contents_len: usize, rules: &EncodingOptions) -> bool {
    rules.encoding_type() == EncodingType::Cer && contents_len > CER_SEGMENT_LEN
}

/// The identifier with the constructed bit set: X.690 §8.14.3 makes the form
/// follow the base encoding, so a constructed value sets it whatever the
/// caller passed.
pub(crate) fn constructed_tag(tag: &[u8]) -> Vec<u8> {
    let mut tag = tag.to_vec();
    if let Some(first) = tag.first_mut() {
        *first |= 0x20;
    }
    tag
}
