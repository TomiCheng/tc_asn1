//! The limits a decoding is held to.

use crate::Asn1Error;

/// Bounds on what a decoding may consume, so that untrusted input cannot
/// drive memory or recursion beyond what the caller planned for.
///
/// The three limits are independent of each other and of the input length:
/// a 20-octet value can still nest 40 levels deep or claim a 4 GiB length.
/// They are checked where the structure is read, not where a value is
/// built, so an offending encoding is rejected before anything is
/// allocated for it. The defaults fit a certificate or a CMS message with
/// room to spare; a decoder for a narrower format may tighten them.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Object, Decode, DecodingOptions};
///
/// // SEQUENCE { SEQUENCE { SEQUENCE { } } }: three levels of nesting.
/// let nested = [0x30, 0x04, 0x30, 0x02, 0x30, 0x00];
/// assert!(Asn1Object::decode(&nested, &DecodingOptions::default()).is_ok());
/// assert!(matches!(
///     Asn1Object::decode(&nested, &DecodingOptions::new(2, 1024, 16)),
///     Err(Asn1Error::DepthExceeded)
/// ));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodingOptions {
    depth: u32,
    max_content_len: usize,
    max_children: usize,
}

impl DecodingOptions {
    /// [`Asn1Error::ContentLengthExceeded`] when `len` is over the limit.
    pub(crate) fn check_content_len(&self, len: usize) -> Result<(), Asn1Error> {
        if len > self.max_content_len {
            Err(Asn1Error::ContentLengthExceeded)
        } else {
            Ok(())
        }
    }

    /// Limits in the order of the accessors below.
    pub const fn new(depth: u32, max_content_len: usize, max_children: usize) -> Self {
        Self {
            depth,
            max_content_len,
            max_children,
        }
    }

    /// How many constructed values may be open at once. The outermost TLV
    /// is at depth 0, so this many levels of children can be entered;
    /// opening one more is [`Asn1Error::DepthExceeded`]. Bounds the stack,
    /// since every level is a recursive call.
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// The most contents octets a single value may have, whether primitive
    /// or constructed. A definite length over it is
    /// [`Asn1Error::ContentLengthExceeded`] as soon as the length is read,
    /// before the octets are looked at; an indefinite-length value is
    /// measured as its children are scanned. Bounds what one value can
    /// make the decoder copy.
    pub const fn max_content_len(&self) -> usize {
        self.max_content_len
    }

    /// The most elements one constructed value may hold; the next one is
    /// [`Asn1Error::ChildrenExceeded`]. Bounds the element count of a
    /// SEQUENCE OF or SET OF independently of their sizes.
    pub const fn max_children(&self) -> usize {
        self.max_children
    }
}

/// Depth 32, 16 MiB of contents, 65 536 children.
impl Default for DecodingOptions {
    fn default() -> Self {
        Self {
            depth: 32,
            max_content_len: 16 * 1024 * 1024,
            max_children: 65_536,
        }
    }
}
