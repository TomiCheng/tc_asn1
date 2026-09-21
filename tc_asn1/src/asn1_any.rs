//! An element kept as its octets: the ANY of a schema, and the way to
//! carry a value this crate does not interpret.

use alloc::vec::Vec;

use crate::traits::encode::{len_octets, write_len};
use crate::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions,
};

/// One complete TLV, stored byte for byte.
///
/// Decoding checks only the structure and keeps the octets, so a BER
/// original stays BER when written again under DER rules: the type is
/// for passing an element through unchanged, an extension value or an
/// unknown parameter, not for producing canonical output. Equality is by
/// the octets.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Any, Asn1Error, Asn1Integer, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions};
///
/// // An indefinite-length SEQUENCE, kept as found and written back as found.
/// let ber = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
/// let (used, any) = Asn1Any::decode(&ber, &DecodingOptions::default())?;
/// assert_eq!((used, any.raw()), (7, &ber[..]));
/// assert_eq!(any.encode_to_vec(&EncodingOptions::DER)?, ber);
///
/// // The structure is still there to be read.
/// let mut context = DecodingContext::new(DecodingOptions::default());
/// let element = any.as_ref();
/// assert_eq!(element.eoc(), [0x00, 0x00]);
/// let inner: Asn1Integer = element.children(&mut context)?.get()?;
/// assert_eq!(inner, Asn1Integer::from(1));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Any {
    raw: Vec<u8>,
    length_offset: usize,
    value_offset: usize,
    eoc_offset: usize,
}

impl Asn1Any {
    /// Builds a primitive, definite-length TLV from an identifier and its contents,
    /// for types this crate keeps opaque (TeletexString, GraphicString, ...).
    /// `tag` must be a complete identifier, e.g. `tag::TELETEX_STRING`.
    /// Variable time: branches only on the lengths.
    pub fn primitive(tag: &[u8], value: &[u8]) -> Self {
        let length_offset = tag.len();
        let value_offset = length_offset + len_octets(value.len());
        let mut raw = alloc::vec![0; value_offset + value.len()];
        raw[..length_offset].copy_from_slice(tag);
        write_len(value.len(), &mut raw[length_offset..]);
        raw[value_offset..].copy_from_slice(value);
        Self {
            raw,
            length_offset,
            value_offset,
            eoc_offset: value_offset + value.len(),
        }
    }

    /// The whole TLV.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The stored element split into its parts, to read its tag and
    /// contents or walk its children.
    pub fn as_ref(&self) -> Asn1Ref<'_> {
        Asn1Ref::from_validated_parts(
            &self.raw,
            self.length_offset,
            self.value_offset,
            self.eoc_offset,
        )
    }
}

impl From<&Asn1Ref<'_>> for Asn1Any {
    fn from(element: &Asn1Ref<'_>) -> Self {
        let eoc_offset = element.total_len() - element.eoc().len();
        Self {
            raw: element.raw().to_vec(),
            length_offset: element.tag().len(),
            value_offset: eoc_offset - element.value().len(),
            eoc_offset,
        }
    }
}

/// Walks every nested element so that, under DER, each one goes through
/// `Asn1Ref::parse`'s identifier and length checks. Contents rules that need
/// the type (BOOLEAN FF, BIT STRING unused bits, SET order) are not checked
/// here; Asn1Object covers those. Variable time: branches only on the structure.
fn walk(element: &Asn1Ref<'_>, context: &mut DecodingContext) -> Result<(), Asn1Error> {
    if !element.is_constructed() {
        return Ok(());
    }
    let mut children = element.children(context)?;
    while let Some(child) = children.next() {
        walk(&child?, children.context())?;
    }
    Ok(())
}

impl DecodeInner for Asn1Any {
    /// Any element at all. Under DER every nested identifier and length is
    /// checked, but not the contents rules that need the type.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        if context.is_der() {
            walk(&element, context)?;
        }
        Ok((element.total_len(), Self::from(&element)))
    }
}

impl Decode for Asn1Any {}

impl EncodeContent for Asn1Any {
    /// The stored contents octets, whatever the rules.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.as_ref().value().len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let value = self.as_ref().value();
        let out = out
            .get_mut(..value.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(value);
        Ok(value.len())
    }
}

/// Under another identifier (IMPLICIT tagging) the contents are re-wrapped with
/// the default header, so an indefinite-length original becomes definite there.
impl EncodeTagged for Asn1Any {}

impl Encode for Asn1Any {
    /// Writes the stored TLV byte for byte, whatever the rules: this type keeps
    /// what was decoded, so a BER original stays BER under DER rules.
    fn encoded_len(&self, _: &EncodingOptions) -> usize {
        self.raw.len()
    }

    fn encode(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.raw.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.raw);
        Ok(self.raw.len())
    }
}

#[cfg(test)]
mod tests {
    use super::Asn1Any;
    use crate::{
        Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions, EncodingType, Implicit, tag,
    };

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn primitive_builds_a_definite_length_tlv() {
        let teletex = Asn1Any::primitive(tag::TELETEX_STRING, b"abc");
        assert_eq!(teletex.raw(), b"\x14\x03abc");
        assert_eq!(teletex.as_ref().value(), b"abc");
        assert_eq!(teletex.encode_to_vec(&der()).unwrap(), b"\x14\x03abc");

        let long = Asn1Any::primitive(tag::OCTET_STRING, &[0xAA; 200]);
        assert_eq!(long.raw()[..3], [0x04, 0x81, 0xC8]);
        assert_eq!(long.raw().len(), 203);
    }

    #[test]
    fn what_was_decoded_is_written_back_unchanged_whatever_the_rules() {
        let ber = [0x30, 0x80, 0x02, 0x81, 0x01, 0x01, 0x00, 0x00];
        let (used, any) = Asn1Any::decode(&ber, &options()).unwrap();
        assert_eq!(used, 8);
        for rules in [EncodingType::Der, EncodingType::Cer] {
            assert_eq!(
                any.encode_to_vec(&EncodingOptions::new(rules)).unwrap(),
                ber
            );
        }
        assert_eq!(any, Asn1Any::from(&any.as_ref()));
    }

    #[test]
    fn der_decoding_checks_every_nested_header() {
        let nested_non_minimal = [0x30, 0x04, 0x02, 0x81, 0x01, 0x01];
        assert!(Asn1Any::decode(&nested_non_minimal, &options()).is_ok());
        assert!(matches!(
            Asn1Any::decode_der(&nested_non_minimal, &options()),
            Err(Asn1Error::NotDer)
        ));
        // a contents rule is not: BOOLEAN 01 passes as Any
        assert!(Asn1Any::decode_der(&[0x01, 0x01, 0x01], &options()).is_ok());
    }

    #[test]
    fn under_another_tag_the_contents_are_rewrapped_with_a_definite_length() {
        let (_, any) =
            Asn1Any::decode(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00], &options()).unwrap();
        assert_eq!(
            Implicit::new(&[0xA1], &any).encode_to_vec(&der()).unwrap(),
            [0xA1, 0x03, 0x02, 0x01, 0x01]
        );
    }
}
