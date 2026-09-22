//! The TLV structure of an encoding, read without interpreting it.
//!
//! [`Asn1Ref`] is one element borrowed from the input: its identifier,
//! contents and, for an indefinite length, the end-of-contents octets.
//! [`Children`] walks the elements inside a constructed one and is how a
//! SEQUENCE reads its fields. Both check only the structure: X.690 §8.1 for
//! everything, §10.1 and §10.2 when the context is DER.

use crate::decoding_context::DepthScope;
use crate::error::Asn1Error;
use crate::traits::DecodeInner;
use crate::traits::encode::len_octets;
use crate::{DecodeContent, DecodingContext, DecodingOptions, Tagged};

/// The class bits of an identifier octet (X.690 §8.1.2.2).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Asn1Class {
    /// `00`: the types X.680 defines.
    Universal,
    /// `01`: tags an application defines.
    Application,
    /// `10`: `[n]` tags, read in the context of the enclosing type.
    ContextSpecific,
    /// `11`: tags for private use.
    Private,
}

impl Asn1Class {
    pub(crate) fn of(first: u8) -> Self {
        match first >> 6 {
            0 => Self::Universal,
            1 => Self::Application,
            2 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }
}

/// One TLV borrowed from its buffer: the identifier, the contents and
/// the end-of-contents octets if any.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Class, Asn1Error, Asn1Integer, Asn1Ref, DecodingContext, DecodingOptions};
///
/// let mut context = DecodingContext::new(DecodingOptions::default());
/// // SEQUENCE { INTEGER 1, INTEGER 2 }, followed by an octet that is not part of it
/// let wire = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0xFF];
/// let element = Asn1Ref::parse(&wire, &mut context)?;
/// assert_eq!((element.tag(), element.class()), (&[0x30][..], Asn1Class::Universal));
/// assert!(element.is_constructed());
/// assert_eq!(element.total_len(), 8);
/// assert_eq!(element.value(), &wire[2..8]);
///
/// // The fields are read one by one, in order, then the end is asserted.
/// let mut fields = element.children(&mut context)?;
/// let first: Asn1Integer = fields.get()?;
/// let second: Asn1Integer = fields.get()?;
/// fields.end()?;
/// assert_eq!((first, second), (Asn1Integer::from(1), Asn1Integer::from(2)));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Asn1Ref<'a> {
    raw: &'a [u8],
    tag: &'a [u8],
    value: &'a [u8],
    eoc: &'a [u8],
}

impl<'a> Asn1Ref<'a> {
    pub(crate) fn from_validated_parts(
        raw: &'a [u8],
        length_offset: usize,
        value_offset: usize,
        eoc_offset: usize,
    ) -> Self {
        Self {
            raw,
            tag: &raw[..length_offset],
            value: &raw[value_offset..eoc_offset],
            eoc: &raw[eoc_offset..],
        }
    }

    /// Reads one TLV. With `context.is_der()` the identifier must be in DER
    /// form, the length definite and shortest (X.690 §10.1, §10.2).
    /// Variable time: branches only on the encoding structure.
    pub fn parse(buff: &'a [u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let tag = parse_tag(buff)?;
        let (len_len, length) = parse_len(&buff[tag.len()..])?;
        if context.is_der() {
            crate::decoding::check_der_tag(tag)?;
            if tag == [0] || length.is_none() || length.is_some_and(|n| len_len != len_octets(n)) {
                return Err(Asn1Error::NotDer);
            }
        }
        let offset = tag.len() + len_len;

        match length {
            Some(n) => {
                let end = offset.checked_add(n).ok_or(Asn1Error::LengthOverflow)?;
                context.options().check_content_len(n)?;
                let value = buff.get(offset..end).ok_or(Asn1Error::Truncated)?;
                Ok(Self {
                    raw: &buff[..end],
                    tag,
                    value,
                    eoc: &buff[end..end],
                })
            }
            None => {
                // Only constructed encodings may end with an EOC instead of a length.
                if tag[0] & 0x20 == 0 {
                    return Err(Asn1Error::MalformedValue);
                }

                let mut scope = context.enter()?;
                let mut at = offset;
                let mut count = 0;
                loop {
                    let rest = buff.get(at..).ok_or(Asn1Error::Truncated)?;
                    if rest.len() < 2 {
                        return Err(Asn1Error::Truncated);
                    }
                    if rest[..2] == [0x00, 0x00] {
                        break;
                    }
                    if count == scope.options().max_children() {
                        return Err(Asn1Error::ChildrenExceeded);
                    }
                    at += Self::parse(rest, scope.context())?.total_len(); // Skip the complete child TLV.
                    count += 1;
                    scope.options().check_content_len(at - offset)?;
                }
                Ok(Self {
                    raw: &buff[..at + 2],
                    tag,
                    value: &buff[offset..at],
                    eoc: &buff[at..at + 2],
                })
            }
        }
    }

    /// The whole TLV, end-of-contents octets included: what a signature
    /// covers.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The identifier octets, one for tag numbers up to 30.
    pub fn tag(&self) -> &'a [u8] {
        self.tag
    }

    /// The class bits of [`tag`](Self::tag).
    pub fn class(&self) -> Asn1Class {
        Asn1Class::of(self.tag[0])
    }

    /// Whether the constructed bit `0x20` of [`tag`](Self::tag) is set.
    pub fn is_constructed(&self) -> bool {
        self.tag[0] & 0x20 != 0
    }

    /// The contents octets, without the end-of-contents octets.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The length of [`raw`](Self::raw): what to skip to reach the next
    /// element.
    pub fn total_len(&self) -> usize {
        self.raw().len()
    }

    /// `00 00` after an indefinite length, empty otherwise.
    pub fn eoc(&self) -> &'a [u8] {
        self.eoc
    }

    /// The elements inside a constructed value, one level deeper in the
    /// context; empty for a primitive value. `DepthExceeded` at the limit.
    pub fn children<'b>(
        &self,
        context: &'b mut DecodingContext,
    ) -> Result<Children<'a, 'b>, Asn1Error> {
        let scope = context.enter()?;
        Ok(Children::new(
            if self.is_constructed() {
                self.value
            } else {
                &[]
            },
            scope,
        ))
    }

    /// This element as a `T`, which must take all of it.
    pub fn decode_as<T: DecodeInner>(&self, context: &mut DecodingContext) -> Result<T, Asn1Error> {
        let (used, value) = T::decode_inner(self.raw, context)?;
        if used != self.total_len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }

    /// `UnexpectedTag` unless the identifier is `tag`; for chaining after
    /// [`parse`](Self::parse).
    pub fn assert_tag(self, tag: &[u8]) -> Result<Self, Asn1Error> {
        if self.tag != tag {
            Err(Asn1Error::UnexpectedTag)
        } else {
            Ok(self)
        }
    }
}

/// The elements of a constructed value, one level deeper in the context.
///
/// An iterator over the raw elements, plus the typed reads a SEQUENCE
/// needs: [`get`](Self::get) for a required field, [`get_opt`](Self::get_opt)
/// and [`get_default`](Self::get_default) for OPTIONAL and DEFAULT ones,
/// the `get_explicit_*` and `get_implicit_*` methods for tagged ones, and
/// [`end`](Self::end) to reject anything left over. The optional reads look
/// at the next element without consuming it, so a mismatch leaves it for
/// the next field.
pub struct Children<'a, 'b> {
    cursor: ChildCursor<'a>,
    scope: DepthScope<'b>,
    /// An element read by `peek` and not yet handed out by `next`.
    lookahead: Option<Result<Asn1Ref<'a>, Asn1Error>>,
}

impl<'a, 'b> Children<'a, 'b> {
    pub(crate) fn new(rest: &'a [u8], scope: DepthScope<'b>) -> Self {
        Self {
            cursor: ChildCursor::new(rest, scope.options()),
            scope,
            lookahead: None,
        }
    }

    /// The context at this depth, for decoding an element by hand.
    pub fn context(&mut self) -> &mut DecodingContext {
        self.scope.context()
    }

    /// The next element without consuming it; `None` at the end.
    pub fn peek(&mut self) -> Option<Result<Asn1Ref<'a>, Asn1Error>> {
        if self.lookahead.is_none() {
            self.lookahead = self.cursor.next(&mut self.scope);
        }
        self.lookahead
    }

    /// A required field: the next element as a `T`, `Truncated` when there
    /// is none.
    pub fn get<T: DecodeInner>(&mut self) -> Result<T, Asn1Error> {
        self.next()
            .ok_or(Asn1Error::Truncated)??
            .decode_as::<T>(self.context())
    }

    /// An OPTIONAL field: the next element as a `T` when it carries
    /// `T::TAG`, `None` otherwise, leaving the element for the next field.
    pub fn get_opt<T: DecodeInner + Tagged>(&mut self) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(child)) if child.tag() == T::TAG => self.get().map(Some),
            _ => Ok(None),
        }
    }

    /// An OPTIONAL field with a DEFAULT: the value when present, `default`
    /// otherwise. Under DER a value equal to the default must not be written
    /// (X.690 §11.5), so one that is present is `NotDer`.
    /// Variable time: branches only on the encoding structure.
    pub fn get_default<T: DecodeInner + Tagged + PartialEq>(
        &mut self,
        default: T,
    ) -> Result<T, Asn1Error> {
        match self.get_opt::<T>()? {
            Some(value) => {
                if value == default && self.context().is_der() {
                    return Err(Asn1Error::NotDer);
                }
                Ok(value)
            }
            None => Ok(default),
        }
    }

    /// The next element as a `T` whatever its tag, `None` at the end: for
    /// a trailing OPTIONAL field of a type without a single tag, such as a
    /// CHOICE.
    pub fn get_any_opt<T: DecodeInner>(&mut self) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(_)) => self.get().map(Some),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// A required `[n] EXPLICIT T` field, `tag` being the wrapper's
    /// identifier octets (`[0xA0]` for `[0]`): the value inside the next
    /// element. `Truncated` when the field or its inner value is missing,
    /// `UnexpectedTag` when the wrapper or inner type has the wrong tag,
    /// and `TrailingData` when another element follows inside the wrapper.
    /// The wrapper must hold exactly one element.
    /// Variable time: branches only on the encoding structure.
    pub fn get_explicit<T: DecodeInner>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let wrapper = self.next().ok_or(Asn1Error::Truncated)??.assert_tag(tag)?;
        let mut inner = wrapper.children(self.context())?;
        let value = inner.get::<T>()?;
        inner.end()?;
        Ok(value)
    }

    /// A `[n] EXPLICIT T OPTIONAL` field, `tag` being the wrapper's
    /// identifier octets (`[0xA0]` for `[0]`): the value inside when the
    /// next element carries that tag, `None` otherwise, leaving the element
    /// for the next field. The wrapper must hold exactly one element.
    /// Variable time: branches only on the encoding structure.
    pub fn get_explicit_opt<T: DecodeInner>(
        &mut self,
        tag: impl AsRef<[u8]>,
    ) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(child)) if child.tag() == tag.as_ref() => {
                self.next(); // the wrapper itself
                let mut inner = child.children(self.context())?;
                let value = inner.get::<T>()?;
                inner.end()?;
                Ok(Some(value))
            }
            _ => Ok(None),
        }
    }

    /// [`get_explicit_opt`](Self::get_explicit_opt) for a field with a
    /// DEFAULT: `default` when the wrapper is absent. Under DER a written
    /// value equal to the default is `NotDer` (X.690 §11.5).
    /// Variable time: branches only on the encoding structure.
    pub fn get_explicit_default<T: DecodeInner + PartialEq>(
        &mut self,
        tag: impl AsRef<[u8]>,
        default: T,
    ) -> Result<T, Asn1Error> {
        match self.get_explicit_opt::<T>(tag)? {
            Some(value) if value == default && self.context().is_der() => Err(Asn1Error::NotDer),
            Some(value) => Ok(value),
            None => Ok(default),
        }
    }

    /// A required `[n] IMPLICIT T` field, `tag` being the identifier octets
    /// that replace `T`'s own (`[0x81]` for `[1]` on a primitive type): the
    /// next element's contents decoded as `T`. `Truncated` when there is no
    /// next element and `UnexpectedTag` when its identifier is not `tag`.
    /// Contents are checked under the caller's decoding context.
    /// Variable time: branches only on the encoding structure.
    pub fn get_implicit<T: DecodeContent>(&mut self, tag: &[u8]) -> Result<T, Asn1Error> {
        let element = self.next().ok_or(Asn1Error::Truncated)??.assert_tag(tag)?;
        T::decode_content(element.value(), self.context())
    }

    /// [`get_implicit_opt`](Self::get_implicit_opt) for a field with a
    /// DEFAULT: `default` when the field is absent, leaving a nonmatching
    /// element for the next field. Under DER a written value equal to the
    /// default is `NotDer` (X.690 §11.5).
    /// Variable time: branches only on the encoding structure.
    pub fn get_implicit_default<T: DecodeContent + PartialEq>(
        &mut self,
        tag: &[u8],
        default: T,
    ) -> Result<T, Asn1Error> {
        match self.get_implicit_opt::<T>(tag)? {
            Some(value) if value == default && self.context().is_der() => Err(Asn1Error::NotDer),
            Some(value) => Ok(value),
            None => Ok(default),
        }
    }

    /// A `[n] IMPLICIT T OPTIONAL` field, `tag` being the identifier octets
    /// that replace `T`'s own (`[0x81]` for `[1]` on a primitive type): the
    /// contents decoded as `T` when the next element carries that tag,
    /// `None` otherwise, leaving the element for the next field.
    /// Variable time: branches only on the encoding structure.
    pub fn get_implicit_opt<T: DecodeContent>(
        &mut self,
        tag: impl AsRef<[u8]>,
    ) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(child)) if child.tag() == tag.as_ref() => {
                self.next();
                Ok(Some(T::decode_content(child.value(), self.context())?))
            }
            _ => Ok(None),
        }
    }

    /// Asserts that every element has been read: `TrailingData` otherwise.
    pub fn end(mut self) -> Result<(), Asn1Error> {
        match self.next() {
            None => Ok(()),
            Some(Err(e)) => Err(e),
            Some(Ok(_)) => Err(Asn1Error::TrailingData),
        }
    }
}

impl<'a> Iterator for Children<'a, '_> {
    type Item = Result<Asn1Ref<'a>, Asn1Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.lookahead.take() {
            Some(item) => Some(item),
            None => self.cursor.next(&mut self.scope),
        }
    }
}

pub(crate) struct ChildCursor<'a> {
    rest: &'a [u8],
    remaining: usize,
    oversized: bool,
}
impl<'a> ChildCursor<'a> {
    pub(crate) fn new(rest: &'a [u8], options: &DecodingOptions) -> Self {
        Self {
            rest,
            remaining: options.max_children(),
            oversized: rest.len() > options.max_content_len(),
        }
    }
    pub(crate) fn next(
        &mut self,
        scope: &mut DepthScope,
    ) -> Option<Result<Asn1Ref<'a>, Asn1Error>> {
        if self.rest.is_empty() {
            return None;
        }
        if self.oversized || self.remaining == 0 {
            self.rest = &[];
            return Some(Err(if self.oversized {
                Asn1Error::ContentLengthExceeded
            } else {
                Asn1Error::ChildrenExceeded
            }));
        }
        match Asn1Ref::parse(self.rest, scope.context()) {
            Ok(child) => {
                self.remaining -= 1;
                self.rest = &self.rest[child.total_len()..];
                Some(Ok(child))
            }
            Err(error) => {
                self.rest = &[];
                Some(Err(error))
            }
        }
    }
}

pub(crate) fn parse_tag(buff: &[u8]) -> Result<&[u8], Asn1Error> {
    let first = *buff.first().ok_or(Asn1Error::Truncated)?;
    if first & 0x1F != 0x1F {
        return Ok(&buff[..1]);
    }

    // Each high-tag-number octet carries seven bits and a continuation bit.
    for (index, byte) in buff[1..].iter().enumerate() {
        if index == 0 && *byte == 0x80 {
            return Err(Asn1Error::NonMinimalTag); // Leading zero group.
        }
        if byte & 0x80 == 0 {
            if index == 0 && *byte <= 30 {
                return Err(Asn1Error::NonMinimalTag); // Numbers below 31 require short form.
            }
            return Ok(&buff[..index + 2]);
        }
    }
    Err(Asn1Error::Truncated)
}

fn parse_len(buff: &[u8]) -> Result<(usize, Option<usize>), Asn1Error> {
    let (first, rest) = buff.split_first().ok_or(Asn1Error::Truncated)?;
    match *first {
        0x00..=0x7F => Ok((1, Some(usize::from(*first)))),
        0x80 => Ok((1, None)),
        0xFF => Err(Asn1Error::MalformedValue), // Reserved by X.690.
        _ => {
            let count = usize::from(first & 0x7F);
            let octets = rest.get(..count).ok_or(Asn1Error::Truncated)?;
            let mut length: usize = 0;
            for byte in octets {
                // checked_shl would not detect discarded high bits.
                length = length
                    .checked_mul(256)
                    .and_then(|shifted| shifted.checked_add(usize::from(*byte)))
                    .ok_or(Asn1Error::LengthOverflow)?;
            }
            Ok((1 + count, Some(length)))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{Asn1Class, Asn1Ref};
    use crate::{
        Asn1Any, Asn1Boolean, Asn1Error, Asn1Integer, Asn1Null, Asn1OctetString, DecodingContext,
        DecodingOptions,
    };

    fn ber() -> DecodingContext {
        DecodingContext::new(DecodingOptions::default())
    }

    fn der() -> DecodingContext {
        DecodingContext::new_der(DecodingOptions::default())
    }

    #[test]
    fn a_definite_length_element_is_split_into_tag_and_contents() {
        let wire = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0xFF];
        let element = Asn1Ref::parse(&wire, &mut ber()).unwrap();
        assert_eq!(element.raw(), &wire[..8]);
        assert_eq!(element.tag(), [0x30]);
        assert_eq!(element.value(), &wire[2..8]);
        assert_eq!(element.eoc(), &[] as &[u8]);
        assert_eq!(element.total_len(), 8);
        assert!(element.is_constructed());

        let mut long = Vec::from([0x04, 0x82, 0x01, 0x00]);
        long.extend_from_slice(&[0xAA; 256]);
        let element = Asn1Ref::parse(&long, &mut der()).unwrap();
        assert_eq!((element.value().len(), element.total_len()), (256, 260));
        assert!(!element.is_constructed());
    }

    #[test]
    fn the_class_comes_from_the_top_two_bits() {
        for (first, class) in [
            (0x30, Asn1Class::Universal),
            (0x41, Asn1Class::Application),
            (0xA0, Asn1Class::ContextSpecific),
            (0xC1, Asn1Class::Private),
        ] {
            let wire = [first, 0x00];
            assert_eq!(Asn1Ref::parse(&wire, &mut ber()).unwrap().class(), class);
        }
    }

    #[test]
    fn an_indefinite_length_runs_to_the_end_of_contents_octets() {
        let wire = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0xFF];
        let element = Asn1Ref::parse(&wire, &mut ber()).unwrap();
        assert_eq!(element.value(), [0x02, 0x01, 0x01]);
        assert_eq!(element.eoc(), [0x00, 0x00]);
        assert_eq!(element.total_len(), 7);
        assert!(matches!(
            Asn1Ref::parse(&wire, &mut der()),
            Err(Asn1Error::NotDer)
        ));
        // a primitive value cannot be indefinite; a missing EOC is truncation
        assert!(matches!(
            Asn1Ref::parse(&[0x04, 0x80, 0x00, 0x00], &mut ber()),
            Err(Asn1Error::MalformedValue)
        ));
        for wire in [
            &[0x30, 0x80, 0x02, 0x01, 0x01][..],
            &[0x30, 0x80],
            &[0x30, 0x80, 0x00],
        ] {
            assert!(matches!(
                Asn1Ref::parse(wire, &mut ber()),
                Err(Asn1Error::Truncated)
            ));
        }
    }

    #[test]
    fn identifier_and_length_octets_are_checked() {
        assert_eq!(
            Asn1Ref::parse(&[0x1F, 0x81, 0x00, 0x00], &mut ber())
                .unwrap()
                .tag(),
            [0x1F, 0x81, 0x00] // tag number 128
        );
        for wire in [&[0x1F, 0x05, 0x00][..], &[0x1F, 0x80, 0x01, 0x00]] {
            assert!(matches!(
                Asn1Ref::parse(wire, &mut ber()),
                Err(Asn1Error::NonMinimalTag)
            ));
        }
        assert!(matches!(
            Asn1Ref::parse(&[0x04, 0xFF], &mut ber()),
            Err(Asn1Error::MalformedValue)
        ));
        let mut huge = Vec::from([0x04, 0x89, 0x01]);
        huge.extend_from_slice(&[0x00; 8]);
        assert!(matches!(
            Asn1Ref::parse(&huge, &mut ber()),
            Err(Asn1Error::LengthOverflow)
        ));
        for wire in [&[][..], &[0x04], &[0x04, 0x05, 0x01, 0x02], &[0x1F, 0x81]] {
            assert!(matches!(
                Asn1Ref::parse(wire, &mut ber()),
                Err(Asn1Error::Truncated)
            ));
        }
        // a non-minimal length is BER but not DER
        let padded = [0x02, 0x81, 0x01, 0x01];
        assert!(Asn1Ref::parse(&padded, &mut ber()).is_ok());
        assert!(matches!(
            Asn1Ref::parse(&padded, &mut der()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn children_are_read_in_order_with_lookahead_for_the_optional_ones() {
        // SEQUENCE { INTEGER 1, OCTET STRING AA, NULL }
        let wire = [0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x01, 0xAA, 0x05, 0x00];
        let mut context = ber();
        let element = Asn1Ref::parse(&wire, &mut context).unwrap();
        let mut children = element.children(&mut context).unwrap();
        assert_eq!(children.context().depth(), 1);
        assert_eq!(children.peek().unwrap().unwrap().tag(), [0x02]);
        assert_eq!(children.next().unwrap().unwrap().tag(), [0x02]); // the peeked one
        assert!(children.get_opt::<Asn1Integer>().unwrap().is_none()); // next is 04, left in place
        assert_eq!(
            children.get_opt::<Asn1OctetString>().unwrap(),
            Some(Asn1OctetString::new(&[0xAA]))
        );
        assert_eq!(children.get::<Asn1Null>().unwrap(), Asn1Null);
        assert!(children.get_any_opt::<Asn1Any>().unwrap().is_none());
        assert!(matches!(
            children.get::<Asn1Null>(),
            Err(Asn1Error::Truncated)
        ));
        children.end().unwrap();
        assert_eq!(context.depth(), 0);

        let mut children = element.children(&mut context).unwrap();
        children.get::<Asn1Integer>().unwrap();
        assert!(matches!(children.end(), Err(Asn1Error::TrailingData)));
        assert!(
            Asn1Ref::parse(&[0x02, 0x01, 0x01], &mut context)
                .unwrap()
                .children(&mut context)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn a_default_written_out_is_ber_only() {
        let written = [0x30, 0x03, 0x01, 0x01, 0x00];
        let mut context = ber();
        let element = Asn1Ref::parse(&written, &mut context).unwrap();
        let mut children = element.children(&mut context).unwrap();
        assert_eq!(
            children.get_default(Asn1Boolean::from(false)).unwrap(),
            Asn1Boolean::from(false)
        );
        let mut context = der();
        let element = Asn1Ref::parse(&written, &mut context).unwrap();
        let mut children = element.children(&mut context).unwrap();
        assert!(matches!(
            children.get_default(Asn1Boolean::from(false)),
            Err(Asn1Error::NotDer)
        ));
        let mut context = der();
        let element = Asn1Ref::parse(&[0x30, 0x00], &mut context).unwrap();
        let mut children = element.children(&mut context).unwrap();
        assert_eq!(
            children.get_default(Asn1Boolean::from(false)).unwrap(),
            Asn1Boolean::from(false)
        );
    }

    #[test]
    fn explicit_reads_one_wrapped_value_and_preserves_the_next_field() {
        let wire = [0x30, 0x07, 0xA0, 0x03, 0x02, 0x01, 0x07, 0x05, 0x00];
        for mut context in [ber(), der()] {
            let element = Asn1Ref::parse(&wire, &mut context).unwrap();
            let mut children = element.children(&mut context).unwrap();
            children.peek().unwrap().unwrap();
            assert_eq!(
                children.get_explicit::<Asn1Integer>(&[0xA0]).unwrap(),
                Asn1Integer::from(7)
            );
            assert_eq!(children.context().depth(), 1);
            assert_eq!(children.get::<Asn1Null>().unwrap(), Asn1Null);
            children.end().unwrap();
            assert_eq!(context.depth(), 0);
        }
    }

    #[test]
    fn explicit_rejects_missing_wrong_or_extra_elements() {
        for (wire, expected) in [
            (&[0x30, 0x00][..], Asn1Error::Truncated),
            (&[0x30, 0x02, 0xA0, 0x00], Asn1Error::Truncated),
            (
                &[0x30, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x07],
                Asn1Error::UnexpectedTag,
            ),
            (
                &[0x30, 0x04, 0xA0, 0x02, 0x05, 0x00],
                Asn1Error::UnexpectedTag,
            ),
            (
                &[0x30, 0x08, 0xA0, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x08],
                Asn1Error::TrailingData,
            ),
            (&[0x30, 0x03, 0xA0, 0x01, 0x02], Asn1Error::Truncated),
        ] {
            let mut context = ber();
            let element = Asn1Ref::parse(wire, &mut context).unwrap();
            let mut children = element.children(&mut context).unwrap();
            assert_eq!(children.get_explicit::<Asn1Integer>(&[0xA0]), Err(expected));
            assert_eq!(children.context().depth(), 1);
        }
    }

    #[test]
    fn implicit_reads_contents_and_preserves_the_next_field() {
        let wire = [0x30, 0x05, 0x81, 0x01, 0x07, 0x05, 0x00];
        for mut context in [ber(), der()] {
            let element = Asn1Ref::parse(&wire, &mut context).unwrap();
            let mut children = element.children(&mut context).unwrap();
            children.peek().unwrap().unwrap();
            assert_eq!(
                children.get_implicit::<Asn1Integer>(&[0x81]).unwrap(),
                Asn1Integer::from(7)
            );
            assert_eq!(children.get::<Asn1Null>().unwrap(), Asn1Null);
            children.end().unwrap();
        }
    }

    #[test]
    fn implicit_propagates_tag_structure_and_contents_errors() {
        for (wire, expected) in [
            (&[0x30, 0x00][..], Asn1Error::Truncated),
            (&[0x30, 0x03, 0x82, 0x01, 0x07], Asn1Error::UnexpectedTag),
            (&[0x30, 0x02, 0x81, 0x01], Asn1Error::Truncated),
            (&[0x30, 0x02, 0x81, 0x00], Asn1Error::MalformedValue),
        ] {
            let mut context = ber();
            let element = Asn1Ref::parse(wire, &mut context).unwrap();
            let mut children = element.children(&mut context).unwrap();
            assert_eq!(children.get_implicit::<Asn1Integer>(&[0x81]), Err(expected));
        }
    }

    #[test]
    fn implicit_keeps_the_contexts_der_contents_rules() {
        let wire = [0x30, 0x03, 0x81, 0x01, 0x01]; // BER TRUE, not DER FF
        for (mut context, expected) in [
            (ber(), Ok(Asn1Boolean::from(true))),
            (der(), Err(Asn1Error::NotDer)),
        ] {
            let element = Asn1Ref::parse(&wire, &mut context).unwrap();
            let mut children = element.children(&mut context).unwrap();
            assert_eq!(children.get_implicit::<Asn1Boolean>(&[0x81]), expected);
        }
    }

    #[test]
    fn implicit_default_leaves_a_nonmatching_field_in_place() {
        for wire in [&[0x30, 0x00][..], &[0x30, 0x02, 0x05, 0x00]] {
            for mut context in [ber(), der()] {
                let element = Asn1Ref::parse(wire, &mut context).unwrap();
                let mut children = element.children(&mut context).unwrap();
                assert_eq!(
                    children.get_implicit_default(&[0x81], Asn1Boolean::from(false)),
                    Ok(Asn1Boolean::from(false))
                );
                if wire.len() > 2 {
                    assert_eq!(children.get::<Asn1Null>().unwrap(), Asn1Null);
                }
                children.end().unwrap();
            }
        }
    }

    #[test]
    fn implicit_default_checks_written_values_under_ber_and_der() {
        for (contents, ber_result, der_result) in [
            (0x00, Ok(Asn1Boolean::from(false)), Err(Asn1Error::NotDer)),
            (
                0xFF,
                Ok(Asn1Boolean::from(true)),
                Ok(Asn1Boolean::from(true)),
            ),
            (0x01, Ok(Asn1Boolean::from(true)), Err(Asn1Error::NotDer)),
        ] {
            let wire = [0x30, 0x03, 0x81, 0x01, contents];
            for (mut context, expected) in [(ber(), ber_result), (der(), der_result)] {
                let element = Asn1Ref::parse(&wire, &mut context).unwrap();
                let mut children = element.children(&mut context).unwrap();
                assert_eq!(
                    children.get_implicit_default(&[0x81], Asn1Boolean::from(false)),
                    expected
                );
                children.end().unwrap();
            }
        }
    }

    #[test]
    fn implicit_default_propagates_invalid_contents() {
        for mut context in [ber(), der()] {
            let element = Asn1Ref::parse(&[0x30, 0x02, 0x81, 0x00], &mut context).unwrap();
            let mut children = element.children(&mut context).unwrap();
            assert_eq!(
                children.get_implicit_default(&[0x81], Asn1Boolean::from(false)),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn decode_as_and_assert_tag_check_the_type() {
        let mut context = ber();
        let element = Asn1Ref::parse(&[0x02, 0x01, 0x07], &mut context).unwrap();
        assert_eq!(
            element.decode_as::<Asn1Integer>(&mut context).unwrap(),
            Asn1Integer::from(7)
        );
        assert!(matches!(
            element.decode_as::<Asn1Null>(&mut context),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(element.assert_tag(&[0x02]).is_ok());
        assert!(matches!(
            element.assert_tag(&[0x04]),
            Err(Asn1Error::UnexpectedTag)
        ));
    }
}
