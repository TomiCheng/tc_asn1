//! What walking a stream of values meets next.

use super::Asn1Header;

/// One step of [`Asn1Reader::read`](super::Asn1Reader::read), walking the
/// values of a stream without reading any of them whole.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Asn1Event {
    /// A constructed value begins; what follows are its children, up to the
    /// matching [`End`](Self::End).
    Start(Asn1Header),
    /// A primitive value; its contents are next, to read with
    /// [`Asn1Reader::body`](super::Asn1Reader::body) or to leave, in which
    /// case the next step skips them.
    Primitive(Asn1Header),
    /// The innermost open constructed value ends: its definite length is
    /// used up, or its end-of-contents octets were read.
    End,
}
