//! Reading and writing encoded values over `std::io`.
//!
//! The rest of the crate works on `&[u8]`: [`Decode`](crate::Decode) needs
//! the whole encoding in memory, and [`Encode`](crate::Encode) writes into a
//! buffer whose length it computes first. That serves a value already in
//! memory, and it cannot serve these:
//!
//! - Reading exactly one value from a stream, a socket or a file of values
//!   one after another, leaving what follows it unread: where a value ends
//!   is known only by reading it.
//! - Data larger than memory, such as a CRL of millions of entries or CMS
//!   content of several gigabytes, read or written part by part.
//! - Input that is not trusted, whose lengths must be checked against
//!   [`DecodingOptions`](crate::DecodingOptions) before anything is held for
//!   them, with memory growing with the octets that arrive rather than with
//!   the lengths a peer claims.
//! - Output produced as it goes, whose size is not known in advance or is
//!   known without the data being at hand.
//!
//! [`Asn1Reader`] and [`Asn1Writer`] serve them, a value whole or in steps
//! under a state machine per level, with an [`Asn1Body`] or an
//! [`Asn1BodyWriter`] for the contents of each value. The `&[u8]` API is
//! unchanged beside them.
//!
//! Available with the `std` feature.

mod asn1_item;
mod asn1_length;
mod asn1_reader;
mod asn1_tag;
mod asn1_writer;

pub use asn1_item::Asn1Item;
pub use asn1_length::Asn1Length;
pub use asn1_reader::{Asn1Body, Asn1Reader};
pub use asn1_tag::Asn1Tag;
pub use asn1_writer::{Asn1BodyWriter, Asn1Writer};
