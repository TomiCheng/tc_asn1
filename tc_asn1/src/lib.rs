//! BER, CER and DER codecs for the ASN.1 universal types (X.690), for
//! building the structures of X.509 and its neighbours on.
//!
//! `no_std` with `alloc`; no dependencies, no macros, no I/O. Values are
//! decoded from a slice and encoded into one, and every check is done on
//! the structure before anything is allocated for it.
//!
//! # What is here
//!
//! - The universal types, each as its own struct: [`Asn1Integer`],
//!   [`Asn1Oid`], [`Asn1BitString`], the string types, the time types,
//!   [`Asn1SequenceOf`] and [`Asn1SetOf`], and so on. Each keeps the value
//!   the way the wire does (an INTEGER as its octets, a SET OF in the order
//!   given) and applies the DER rules on output and, when asked, on input.
//! - The structural layer for reading without a schema: [`Asn1Ref`] for one
//!   TLV, [`Children`] for the elements of a constructed one, [`Asn1Any`] to
//!   keep an element as octets, [`Asn1Constructed`] for a constructed value
//!   under any tag, [`Asn1Object`] for a whole decoded tree.
//! - The traits a structure implements to become a type of its own, in
//!   three layers so that the tagging wrappers and the containers can reuse
//!   them:
//!
//!   | Layer | Decoding | Encoding |
//!   | --- | --- | --- |
//!   | The contents octets, given the tag and length | [`DecodeContent`] | [`EncodeContent`] |
//!   | A complete TLV under a caller-chosen tag | — | [`EncodeTagged`] |
//!   | A complete TLV under the type's own tag | [`DecodeInner`] | [`Encode`] |
//!   | The standalone entry points | [`Decode`] | — |
//!
//!   [`DecodeInner`] and [`EncodeContent`] do the work, the rest are
//!   one-liners; [`Tagged`] names the type's own tag. [`Explicit`] and
//!   [`Implicit`] write tagged fields, [`Children::get_explicit_opt`] and
//!   friends read them.
//! - [`NamedOid`] for constant tables of OIDs with names, checked when
//!   compiled.
//!
//! # Decoding and encoding
//!
//! [`Decode::decode`] accepts any BER; [`Decode::decode_der`] rejects with
//! [`Asn1Error::NotDer`] whatever is not the canonical form. Both return
//! the octets used, and neither complains about what follows. Encoding
//! takes an [`EncodingOptions`] choosing BER, CER or DER; the three differ
//! only where X.690 leaves a choice, see [`EncodingType`]. Limits on depth,
//! length and element count come from [`DecodingOptions`].
//!
//! ```
//! use tc_asn1::{Asn1Error, Asn1Integer, Asn1Object, Asn1SequenceOf, Decode, DecodingOptions, Encode, EncodingOptions, EncodingType};
//!
//! // A SEQUENCE OF INTEGER, written under DER and read back.
//! let list = Asn1SequenceOf::new(vec![Asn1Integer::from(1), Asn1Integer::from(-1)]);
//! let der = list.encode_to_vec(&EncodingOptions::DER)?;
//! assert_eq!(der, [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0xFF]);
//! let (used, back) = Asn1SequenceOf::<Asn1Integer>::decode(&der, &DecodingOptions::default())?;
//! assert_eq!((used, back), (8, list));
//!
//! // The same octets without a schema, as a tree.
//! let (_, tree) = Asn1Object::decode(&der, &DecodingOptions::default())?;
//! assert_eq!(tree.to_string(), "SEQUENCE\n  INTEGER 1\n  INTEGER -1\n");
//! # Ok::<(), Asn1Error>(())
//! ```
//!
//! # Defining a structure
//!
//! A SEQUENCE with fields is a struct implementing [`DecodeInner`] (parse
//! the outer element, read the fields through [`Asn1Ref::children`], call
//! [`Children::end`]) and [`EncodeContent`] (write the fields back to
//! back), plus the empty [`Decode`], [`EncodeTagged`] and two-line
//! [`Encode`] and [`Tagged`] impls. A CHOICE dispatches on the tag in
//! `DecodeInner` and on the variant in `Encode`. Each type states what it
//! validates and whether it runs in constant time; nothing in this crate
//! handles secret data, so every method is variable time and documents it.
//!
//! # Not here
//!
//! No derive macro or schema language, no streaming or incremental
//! decoding, no constructed string segments beyond [`Asn1Constructed`], and
//! no knowledge of any particular protocol: the OIDs, the extensions and
//! the profiles belong to the crates built on this one.

#![no_std]

extern crate alloc;

mod asn1_any;
mod asn1_constructed;
mod asn1_object;
mod asn1_ref;
mod decoding;
mod decoding_context;
mod decoding_options;
mod encoding_options;
mod encoding_type;
mod error;
mod tagging;
mod traits;
mod universal;

pub use asn1_any::Asn1Any;
pub use asn1_constructed::Asn1Constructed;
pub use asn1_object::Asn1Object;
pub use asn1_ref::{Asn1Class, Asn1Ref, Children};
pub use decoding_context::DecodingContext;
pub use decoding_options::DecodingOptions;
pub use encoding_options::EncodingOptions;
pub use encoding_type::{EncodingType, LengthForm};
pub use error::Asn1Error;

pub use tagging::{Explicit, Implicit};
pub use traits::{Decode, DecodeContent, DecodeInner, Encode, EncodeContent, EncodeTagged, Tagged};
pub use universal::tag;
pub use universal::{
    Arcs, Asn1BitString, Asn1BmpString, Asn1Boolean, Asn1Date, Asn1DateTime, Asn1Duration,
    Asn1Enumerated, Asn1GeneralizedTime, Asn1Ia5String, Asn1Integer, Asn1Null, Asn1NumericString,
    Asn1OctetString, Asn1Oid, Asn1OidIri, Asn1PrintableString, Asn1Real, Asn1RelativeOid,
    Asn1RelativeOidIri, Asn1SequenceOf, Asn1SetOf, Asn1Time, Asn1TimeOfDay, Asn1UniversalString,
    Asn1UtcTime, Asn1Utf8String, Asn1VisibleString, NamedOid,
};
