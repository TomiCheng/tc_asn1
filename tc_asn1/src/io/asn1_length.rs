//! The length of a TLV as its header states it.

/// The length octets of one TLV: a count of contents octets, or the
/// indefinite form that end-of-contents octets close (X.690 §8.1.3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Asn1Length {
    /// The contents are this many octets.
    Definite(usize),
    /// The contents run to end-of-contents octets; constructed values only.
    Indefinite,
}
