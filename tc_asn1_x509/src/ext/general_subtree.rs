//! RFC 5280 §4.2.1.10 `GeneralSubtree`, one entry of a name constraint.
//!
//! ```text
//! GeneralSubtree ::= SEQUENCE {
//!     base     GeneralName,
//!     minimum  [0] BaseDistance DEFAULT 0,
//!     maximum  [1] BaseDistance OPTIONAL }
//!
//! BaseDistance ::= INTEGER (0..MAX)
//! ```
//!
//! A name space: every name under `base`. X.509 lets `minimum` and
//! `maximum` narrow that to a band of levels below the base; RFC 5280
//! requires `minimum` to be 0 and `maximum` to be absent, so the whole
//! subtree always counts. Both fields are therefore checked on decoding,
//! never written, and not kept.
//!
//! What "under" means for each kind of name (a DNS suffix, a mailbox or
//! host, a URI's host, an address inside a mask, a DN prefix) is the
//! validator's business; here an iPAddress base is only required to carry
//! a mask, 8 octets for IPv4 and 32 for IPv6.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::name::GeneralName;

const MINIMUM: &[u8] = &[0x80];
const MAXIMUM: &[u8] = &[0x81];

/// A name space rooted at one name.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::{ext::GeneralSubtree, name::GeneralName};
///
/// // Every host under example.com.
/// let subtree = GeneralSubtree::new(GeneralName::dns_name("example.com")?)?;
/// assert_eq!(subtree.to_string(), "DNS:example.com");
///
/// let der = subtree.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = GeneralSubtree::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back.base(), subtree.base());
///
/// // An address base is a network: address and mask.
/// assert!(GeneralSubtree::new(GeneralName::ip_address(&[10, 0, 0, 0, 255, 0, 0, 0])).is_ok());
/// assert!(matches!(
///     GeneralSubtree::new(GeneralName::ip_address(&[10, 0, 0, 1])),
///     Err(Asn1Error::MalformedValue)
/// ));
/// # Ok::<(), Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GeneralSubtree {
    base: GeneralName,
}

impl GeneralSubtree {
    /// An iPAddress base without a mask (any length but 8 or 32) is
    /// `MalformedValue`; every other kind is taken as given.
    pub fn new(base: GeneralName) -> Result<Self, Asn1Error> {
        let unmasked = matches!(
            &base,
            GeneralName::IpAddress(octets) if !matches!(octets.as_bytes().len(), 8 | 32)
        );
        if unmasked {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { base })
    }

    /// The name the subtree is rooted at.
    pub fn base(&self) -> &GeneralName {
        &self.base
    }
}

/// The base as [`GeneralName`] prints it.
impl fmt::Display for GeneralSubtree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)
    }
}

impl DecodeContent for GeneralSubtree {
    /// A `minimum` other than 0 or a `maximum` at all is `MalformedValue`,
    /// as is an address base without a mask. Variable time: branches only
    /// on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let base = fields.get()?;
        let minimum = fields.get_implicit_default(MINIMUM, Asn1Integer::from(0))?;
        let maximum = fields.get_implicit_opt::<Asn1Integer>(MAXIMUM)?;
        fields.end()?;
        if minimum != Asn1Integer::from(0) || maximum.is_some() {
            return Err(Asn1Error::MalformedValue);
        }
        Self::new(base)
    }
}

impl DecodeInner for GeneralSubtree {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for GeneralSubtree {}

impl Tagged for GeneralSubtree {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for GeneralSubtree {
    /// The base alone: `minimum` is its DEFAULT and `maximum` is absent.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.base.encoded_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.base.encode(rules, out)
    }
}

impl EncodeTagged for GeneralSubtree {}

impl Encode for GeneralSubtree {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::GeneralSubtree;
    use crate::name::GeneralName;

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn a_subtree_is_its_base_alone_on_the_wire() {
        let subtree = GeneralSubtree::new(GeneralName::dns_name("x.tw").unwrap()).unwrap();
        let der = subtree.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der, b"\x30\x06\x82\x04x.tw");
        let (used, back) = GeneralSubtree::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), &subtree));
        assert_eq!(back.to_string(), "DNS:x.tw");
        assert_eq!(
            GeneralSubtree::decode_der(&der, &options()).unwrap().1,
            subtree
        );
    }

    #[test]
    fn a_written_minimum_of_zero_is_ber_only_and_anything_else_is_rejected() {
        let zero = b"\x30\x09\x82\x04x.tw\x80\x01\x00";
        let (_, back) = GeneralSubtree::decode(zero, &options()).unwrap();
        assert_eq!(back.base(), &GeneralName::dns_name("x.tw").unwrap());
        assert!(matches!(
            GeneralSubtree::decode_der(zero, &options()),
            Err(Asn1Error::NotDer)
        ));
        for wire in [
            &b"\x30\x09\x82\x04x.tw\x80\x01\x01"[..], // minimum 1
            b"\x30\x09\x82\x04x.tw\x81\x01\x02",      // maximum 2
        ] {
            assert!(
                matches!(
                    GeneralSubtree::decode(wire, &options()),
                    Err(Asn1Error::MalformedValue)
                ),
                "{wire:02X?}"
            );
        }
    }

    #[test]
    fn an_address_base_needs_a_mask() {
        for octets in [&[10, 0, 0, 0, 255, 0, 0, 0][..], &[0; 32]] {
            assert!(GeneralSubtree::new(GeneralName::ip_address(octets)).is_ok());
        }
        for octets in [&[10, 0, 0, 1][..], &[0; 16], &[1, 2, 3]] {
            assert!(matches!(
                GeneralSubtree::new(GeneralName::ip_address(octets)),
                Err(Asn1Error::MalformedValue)
            ));
        }
        assert!(matches!(
            GeneralSubtree::decode(b"\x30\x06\x87\x04\x0a\x00\x00\x01", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_missing_base_or_a_stray_field_is_rejected() {
        assert!(matches!(
            GeneralSubtree::decode(b"\x30\x00", &options()),
            Err(Asn1Error::Truncated)
        ));
        assert!(matches!(
            GeneralSubtree::decode(b"\x30\x08\x82\x04x.tw\x05\x00", &options()),
            Err(Asn1Error::TrailingData)
        ));
    }
}
