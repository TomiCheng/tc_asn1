use crate::{Asn1Error, DecodingContext, DecodingOptions};

/// Reads the contents octets of a primitive encoding, the tag and length
/// having been consumed by the caller.
///
/// This is the layer the IMPLICIT tagging helper
/// ([`Children::get_implicit_opt`](crate::Children::get_implicit_opt)) uses:
/// the tag on the wire is not the type's own, so only the contents can be
/// handed over. Types with DER contents rules (BOOLEAN, BIT STRING, REAL,
/// the time types) check them when `context.is_der()` and return
/// [`Asn1Error::NotDer`] on a violation.
pub trait DecodeContent: Sized {
    /// `value` is exactly the contents octets. Implementations check the
    /// contents against `context.options()` (the length limit) and, under
    /// DER, the canonical form.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error>;
}

/// Reads one complete TLV under the type's own tag, inside a decoding
/// already in progress.
///
/// Every type implements this; it is what a SEQUENCE calls for each of its
/// fields, through [`Children`](crate::Children). The tag is checked here
/// (a mismatch is [`Asn1Error::UnexpectedTag`]), the length is read and the
/// contents are decoded, with the caller's context carrying the nesting
/// depth and the DER flag along.
pub trait DecodeInner: Sized {
    /// Decodes the TLV at the start of `buff`, ignoring what follows, and
    /// returns the number of octets it took together with the value.
    fn decode_inner(buff: &[u8], context: &mut DecodingContext)
    -> Result<(usize, Self), Asn1Error>;
}

/// The standalone entry points: a fresh context per call, BER-lenient or
/// DER. Implemented as `impl Decode for T {}` on top of [`DecodeInner`].
///
/// Neither method rejects trailing octets; the returned count says where the
/// value ended, and it is the caller's decision whether anything may follow.
pub trait Decode: DecodeInner {
    /// Accepts every encoding [`DecodeInner`] accepts: definite or
    /// indefinite lengths, non-minimal contents, unsorted SETs.
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }

    /// Enforces DER throughout: any encoding that is valid BER but not the
    /// canonical form is [`Asn1Error::NotDer`].
    fn decode_der(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new_der(options.clone()))
    }
}
