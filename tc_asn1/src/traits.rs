//! The behavior contracts every ASN.1 type implements.
//!
//! A value is written and read in three layers, each a trait, so that a type
//! defines its contents once and the tagging wrappers, the `OF` containers
//! and the tagged-field helpers can reuse them:
//!
//! | Layer | Decoding | Encoding |
//! | --- | --- | --- |
//! | The contents octets, given the tag and length | [`DecodeContent`] | [`EncodeContent`] |
//! | A complete TLV under a caller-chosen tag | — | [`EncodeTagged`] |
//! | A complete TLV under the type's own tag | [`DecodeInner`] | [`Encode`] |
//! | The standalone entry points | [`Decode`] | — |
//!
//! [`Tagged`] names the universal tag the type uses on its own, so a caller
//! can recognize it before decoding (an OPTIONAL field).
//!
//! A type with a primitive encoding implements `DecodeContent`, `DecodeInner`,
//! `Decode`, `Tagged`, `EncodeContent`, `EncodeTagged` (usually empty) and
//! `Encode` (two one-liners forwarding to `EncodeTagged` with `Self::TAG`). A
//! constructed type such as a SEQUENCE has no meaningful `DecodeContent`: it
//! parses its children in `DecodeInner` instead. The decoding side takes a
//! [`DecodingContext`](crate::DecodingContext) carrying the limits, the
//! nesting depth and whether DER is being enforced; the encoding side takes
//! [`EncodingOptions`](crate::EncodingOptions) choosing BER, CER or DER.

mod decode;
pub(crate) mod encode;
mod tagged;

pub use decode::{Decode, DecodeContent, DecodeInner};
pub use encode::{Encode, EncodeContent, EncodeTagged};
pub use tagged::Tagged;
