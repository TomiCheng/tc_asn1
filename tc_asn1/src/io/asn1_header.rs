//! The identifier and length octets of a TLV.

use super::{Asn1Length, Asn1Tag};

/// The identifier and length octets of one TLV, read before its contents.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Asn1Header {
    tag: Asn1Tag,
    length: Asn1Length,
}

impl Asn1Header {
    pub(crate) fn new(tag: Asn1Tag, length: Asn1Length) -> Self {
        Self { tag, length }
    }

    /// The identifier octets. Constant time.
    pub fn tag(&self) -> &Asn1Tag {
        &self.tag
    }

    /// The length the header states. Constant time.
    pub fn length(&self) -> Asn1Length {
        self.length
    }

    // The end-of-contents octets that close an indefinite length
    pub(crate) fn is_end_of_contents(&self) -> bool {
        self.tag.as_bytes() == [0x00] && self.length == Asn1Length::Definite(0)
    }
}
