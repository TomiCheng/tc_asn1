//! One part of a value, as reading it step by step meets it.

use super::{Asn1Body, Asn1Length, Asn1Tag};

/// One step of [`Asn1Reader::read`](super::Asn1Reader::read) or
/// [`Asn1Body::read`]: the parts of each value in the order they come.
#[derive(Debug)]
pub enum Asn1Item<'a, R> {
    /// The identifier octets of the next value, as
    /// [`read_header`](super::Asn1Reader::read_header) gives them.
    Header(Asn1Tag),
    /// Its length, as [`read_len`](super::Asn1Reader::read_len) gives it.
    Len(Asn1Length),
    /// Its contents, as [`read_body`](super::Asn1Reader::read_body) gives
    /// them; the next read of the same level skips what is left of them.
    Body(Asn1Body<'a, R>),
}
