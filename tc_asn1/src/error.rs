//! The one error type of the crate.

use core::fmt;

/// Why a decode, an encode or a conversion failed.
///
/// The decoding errors fall into three kinds: the input is not valid BER at
/// all (`Truncated`, `NonMinimalTag`, `LengthOverflow`, `MalformedValue`),
/// it is valid BER but not the canonical form a DER context demands
/// (`NotDer`), or it is not what the caller expected (`UnexpectedTag`,
/// `TrailingData`). The `*Exceeded` variants are the
/// [`DecodingOptions`](crate::DecodingOptions) limits. `BufferTooSmall`
/// and `PrimitiveTooLong` come from encoding, `InexactValue` from a
/// conversion that would have to round.
///
/// No variant carries a position or a path: the caller knows which field
/// it was reading. The enum is `non_exhaustive`; match with a wildcard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Asn1Error {
    /// The input ended inside a tag, a length or the contents, or before
    /// the end-of-contents octets of an indefinite length.
    Truncated,
    /// Octets follow a value that should have been the last one: after the
    /// fields of a SEQUENCE, or after a value that must fill its buffer.
    TrailingData,
    /// Valid BER, but not the canonical form: an indefinite length, a
    /// non-minimal length, a written DEFAULT, a BOOLEAN TRUE other than
    /// `FF`, an unsorted SET OF written back, and so on. Raised only when
    /// the context enforces DER.
    NotDer,
    /// A high-tag-number identifier with a leading zero group or a number
    /// below 31 (X.690 §8.1.2.4.2).
    NonMinimalTag,
    /// A length or a number too big for its target: length octets beyond
    /// `usize`, an integer beyond the primitive type asked for, an OID arc
    /// beyond `u64`, a REAL exponent beyond the wire format.
    LengthOverflow,
    /// The identifier is not the one the type or the field expects.
    UnexpectedTag,
    /// The contents are not valid for the type: an INTEGER with a redundant
    /// sign octet, a PrintableString with `@`, a February 30th, an empty
    /// list where the schema says `SIZE (1..MAX)`.
    MalformedValue,
    /// The value exists but the target type cannot hold it exactly: a REAL
    /// that `f64` would round.
    InexactValue,
    /// Constructed values nested deeper than
    /// [`DecodingOptions::depth`](crate::DecodingOptions::depth).
    DepthExceeded,
    /// A value's contents longer than
    /// [`DecodingOptions::max_content_len`](crate::DecodingOptions::max_content_len).
    ContentLengthExceeded,
    /// A constructed value with more elements than
    /// [`DecodingOptions::max_children`](crate::DecodingOptions::max_children).
    ChildrenExceeded,
    /// The output slice is shorter than the encoding; nothing was written
    /// past its end.
    BufferTooSmall,
    /// CER limits a primitive string to 1000 contents octets (X.690 §9.2);
    /// larger values need the constructed type.
    PrimitiveTooLong,
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Truncated => "input ended inside a TLV",
            Self::TrailingData => "unexpected bytes after the encoded value",
            Self::NotDer => "encoding is not DER",
            Self::NonMinimalTag => "tag number is not in the shortest form",
            Self::LengthOverflow => "length exceeds the platform's usize",
            Self::UnexpectedTag => "tag does not match the expected type",
            Self::MalformedValue => "contents are not valid for this type",
            Self::InexactValue => "value cannot be represented exactly by the target type",
            Self::DepthExceeded => "nesting is deeper than the allowed limit",
            Self::ContentLengthExceeded => "contents exceed the configured length limit",
            Self::ChildrenExceeded => "child count exceeds the configured limit",
            Self::BufferTooSmall => "output buffer is too small",
            Self::PrimitiveTooLong => {
                "CER requires the constructed form for contents over 1000 octets"
            }
        })
    }
}

impl core::error::Error for Asn1Error {}
