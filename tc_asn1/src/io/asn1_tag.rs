//! The identifier octets of a TLV, owned.

use alloc::vec::Vec;

use crate::Asn1Class;

/// The identifier octets of one TLV as read, high tag numbers included,
/// owned so that a header outlives the reader that produced it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Asn1Tag {
    octets: Vec<u8>,
}

impl Asn1Tag {
    pub(crate) fn new(octets: Vec<u8>) -> Self {
        Self { octets }
    }

    /// The identifier octets, never empty. Constant time.
    pub fn as_bytes(&self) -> &[u8] {
        &self.octets
    }

    /// The class bits of the first identifier octet. Constant time.
    pub fn class(&self) -> Asn1Class {
        Asn1Class::of(self.octets[0])
    }

    /// Whether the constructed bit `0x20` is set. Constant time.
    pub fn is_constructed(&self) -> bool {
        self.octets[0] & 0x20 != 0
    }
}
