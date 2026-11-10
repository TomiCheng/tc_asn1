//! RFC 5280 §4.2.1.6 `GeneralName`.
//!
//! ```text
//! GeneralName ::= CHOICE {
//!     otherName                 [0] OtherName,
//!     rfc822Name                [1] IA5String,
//!     dNSName                   [2] IA5String,
//!     x400Address               [3] ORAddress,
//!     directoryName             [4] Name,
//!     ediPartyName              [5] EDIPartyName,
//!     uniformResourceIdentifier [6] IA5String,
//!     iPAddress                 [7] OCTET STRING,
//!     registeredID              [8] OBJECT IDENTIFIER }
//! ```
//!
//! A name of any of nine kinds, the CHOICE told apart by the context tag
//! alone: there is no wrapper, the element's own identifier is `81` for an
//! rfc822Name, `82` for a dNSName, and so on. The module is IMPLICIT TAGS,
//! so those tags replace the type's own, except `directoryName [4]`: `Name`
//! is itself a CHOICE, which cannot be tagged implicitly (X.680 §31.2.7),
//! so `A4` wraps the complete SEQUENCE.
//!
//! Only the structure is handled here. What a name means for matching, the
//! case folding of a DNS name, the mailbox of an rfc822Name, the host of a
//! URI, belongs to the validator; the length of an iPAddress depends on the
//! extension (4 or 16 octets in subjectAltName, address and mask in
//! nameConstraints) and is checked there.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ia5String, Asn1Object, Asn1OctetString, Asn1Oid, Asn1Ref, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions,
};
use tc_asn1_x500::Name;

use crate::name::{EdiPartyName, OtherName, ip_text};

/// A name as it appears in subjectAltName, issuerAltName,
/// authorityKeyIdentifier, cRLDistributionPoints and nameConstraints.
///
/// A CHOICE has no tag of its own, so this type does not implement
/// `Tagged` and cannot be an OPTIONAL field read with `get_opt`; as a
/// required field `get` works. `Display` uses the OpenSSL labels.
///
/// # Examples
///
/// ```
/// use tc_asn1::Asn1Error;
/// use tc_asn1_x509::name::GeneralName;
///
/// let host = GeneralName::dns_name("www.example.com")?;
/// assert_eq!(host.to_string(), "DNS:www.example.com");
///
/// let dir = GeneralName::DirectoryName("CN=Alice".parse()?);
/// assert_eq!(dir.to_string(), "DirName:CN=Alice");
/// # Ok::<(), Asn1Error>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum GeneralName {
    /// `[0]`: a name of a kind identified by an OID, such as a Microsoft UPN.
    OtherName(OtherName),
    /// `[1]`: an e-mail address.
    Rfc822Name(Asn1Ia5String),
    /// `[2]`: a host name.
    DnsName(Asn1Ia5String),
    /// `[3]`: an X.400 ORAddress, kept as a decoded tree until the type
    /// exists.
    X400Address(Asn1Object),
    /// `[4]`: a distinguished name.
    DirectoryName(Name),
    /// `[5]`: an EDI party name.
    EdiPartyName(EdiPartyName),
    /// `[6]`: a URI.
    Uri(Asn1Ia5String),
    /// `[7]`: an IPv4 or IPv6 address, or address and mask in a name
    /// constraint; the length is not checked here.
    IpAddress(Asn1OctetString),
    /// `[8]`: an object identifier.
    RegisteredId(Asn1Oid),
}

impl GeneralName {
    /// An rfc822Name; anything outside ASCII is `MalformedValue`.
    pub fn rfc822_name(text: &str) -> Result<Self, Asn1Error> {
        Asn1Ia5String::new(text).map(Self::Rfc822Name)
    }

    /// A dNSName; anything outside ASCII is `MalformedValue`.
    pub fn dns_name(text: &str) -> Result<Self, Asn1Error> {
        Asn1Ia5String::new(text).map(Self::DnsName)
    }

    /// A uniformResourceIdentifier; anything outside ASCII is
    /// `MalformedValue`.
    pub fn uri(text: &str) -> Result<Self, Asn1Error> {
        Asn1Ia5String::new(text).map(Self::Uri)
    }

    /// An iPAddress from its octets: 4 or 16 for an address, 8 or 32 for
    /// an address and mask.
    pub fn ip_address(octets: &[u8]) -> Self {
        Self::IpAddress(Asn1OctetString::new(octets))
    }

    /// An iPAddress from text, as Bouncy Castle's
    /// `GeneralName(IPAddress, string)` reads it: an IPv4 or IPv6 address,
    /// optionally followed by `/` and a mask written as an address or a
    /// prefix length. Anything else is `MalformedValue`.
    /// Variable time: branches on the text, which is public.
    pub fn ip_address_from_str(text: &str) -> Result<Self, Asn1Error> {
        ip_text::to_octets(text)
            .map(|octets| Self::ip_address(&octets))
            .ok_or(Asn1Error::MalformedValue)
    }

    /// The context tag this variant is written under.
    fn tag(&self) -> &'static [u8] {
        match self {
            Self::OtherName(_) => &[0xA0],
            Self::Rfc822Name(_) => &[0x81],
            Self::DnsName(_) => &[0x82],
            Self::X400Address(_) => &[0xA3],
            Self::DirectoryName(_) => &[0xA4],
            Self::EdiPartyName(_) => &[0xA5],
            Self::Uri(_) => &[0x86],
            Self::IpAddress(_) => &[0x87],
            Self::RegisteredId(_) => &[0x88],
        }
    }
}

/// An IPv4 address dotted, an IPv6 address as eight hex groups, an address
/// and mask as `address/mask`, anything else as hex.
fn write_ip(octets: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fn v4(octets: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    }
    fn v6(octets: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, pair) in octets.chunks(2).enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{:x}", u16::from_be_bytes([pair[0], pair[1]]))?;
        }
        Ok(())
    }
    match octets.len() {
        4 => v4(octets, f),
        16 => v6(octets, f),
        8 => {
            v4(&octets[..4], f)?;
            f.write_str("/")?;
            v4(&octets[4..], f)
        }
        32 => {
            v6(&octets[..16], f)?;
            f.write_str("/")?;
            v6(&octets[16..], f)
        }
        _ => {
            for byte in octets {
                write!(f, "{byte:02x}")?;
            }
            Ok(())
        }
    }
}

/// OpenSSL's labels: `email:`, `DNS:`, `URI:`, `IP:`, `DirName:`, `RID:`,
/// `otherName:`, `EdiPartyName:`; an X.400 address as its tree dump.
impl fmt::Display for GeneralName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherName(inner) => write!(f, "otherName:{inner}"),
            Self::Rfc822Name(inner) => write!(f, "email:{inner}"),
            Self::DnsName(inner) => write!(f, "DNS:{inner}"),
            Self::X400Address(inner) => write!(f, "X400Name:{inner}"),
            Self::DirectoryName(inner) => write!(f, "DirName:{inner}"),
            Self::EdiPartyName(inner) => write!(f, "EdiPartyName:{inner}"),
            Self::Uri(inner) => write!(f, "URI:{inner}"),
            Self::IpAddress(inner) => {
                f.write_str("IP:")?;
                write_ip(inner.as_bytes(), f)
            }
            Self::RegisteredId(inner) => write!(f, "RID:{inner}"),
        }
    }
}

impl DecodeInner for GeneralName {
    /// The context tag picks the alternative: the implicit ones read the
    /// contents as their type, `[4]` reads the whole Name inside the
    /// wrapper, `[3]` is kept as a tree.
    /// Any other identifier, a universal one included, is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0xA0] => Self::OtherName(OtherName::decode_content(element.value(), context)?),
            [0x81] => Self::Rfc822Name(Asn1Ia5String::decode_content(element.value(), context)?),
            [0x82] => Self::DnsName(Asn1Ia5String::decode_content(element.value(), context)?),
            [0xA3] => Self::X400Address(element.decode_as(context)?),
            [0xA4] => {
                let mut inner = element.children(context)?;
                let name = inner.get()?;
                inner.end()?;
                Self::DirectoryName(name)
            }
            [0xA5] => Self::EdiPartyName(EdiPartyName::decode_content(element.value(), context)?),
            [0x86] => Self::Uri(Asn1Ia5String::decode_content(element.value(), context)?),
            [0x87] => Self::IpAddress(Asn1OctetString::decode_content(element.value(), context)?),
            [0x88] => Self::RegisteredId(Asn1Oid::decode_content(element.value(), context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for GeneralName {}

impl EncodeContent for GeneralName {
    /// The contents under the variant's tag: the inner value's own contents
    /// for the implicit alternatives, the whole Name TLV for `directoryName`.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::OtherName(inner) => inner.content_len(rules),
            Self::Rfc822Name(inner) | Self::DnsName(inner) | Self::Uri(inner) => {
                inner.content_len(rules)
            }
            Self::X400Address(inner) => inner.content_len(rules),
            Self::DirectoryName(inner) => inner.encoded_len(rules),
            Self::EdiPartyName(inner) => inner.content_len(rules),
            Self::IpAddress(inner) => inner.content_len(rules),
            Self::RegisteredId(inner) => inner.content_len(rules),
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::OtherName(inner) => inner.encode_content(rules, out),
            Self::Rfc822Name(inner) | Self::DnsName(inner) | Self::Uri(inner) => {
                inner.encode_content(rules, out)
            }
            Self::X400Address(inner) => inner.encode_content(rules, out),
            Self::DirectoryName(inner) => inner.encode(rules, out),
            Self::EdiPartyName(inner) => inner.encode_content(rules, out),
            Self::IpAddress(inner) => inner.encode_content(rules, out),
            Self::RegisteredId(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for GeneralName {}

impl Encode for GeneralName {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(self.tag(), rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(self.tag(), rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1Error, Asn1Object, Asn1Oid, Asn1Utf8String, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };
    use tc_asn1_x500::DirectoryString;

    use super::GeneralName;
    use crate::name::{EdiPartyName, OtherName};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    fn round_trip(name: &GeneralName) -> Vec<u8> {
        let der = name.encode_to_vec(&EncodingOptions::DER).unwrap();
        let (used, back) = GeneralName::decode(&der, &options()).unwrap();
        assert_eq!((used, &back), (der.len(), name));
        assert_eq!(GeneralName::decode_der(&der, &options()).unwrap().1, *name);
        der
    }

    #[test]
    fn the_implicit_kinds_replace_the_inner_tag_with_the_context_one() {
        for (name, wire, text) in [
            (
                GeneralName::rfc822_name("a@x.tw").unwrap(),
                &b"\x81\x06a@x.tw"[..],
                "email:a@x.tw",
            ),
            (
                GeneralName::dns_name("www.x.tw").unwrap(),
                b"\x82\x08www.x.tw",
                "DNS:www.x.tw",
            ),
            (
                GeneralName::uri("http://x.tw/").unwrap(),
                b"\x86\x0chttp://x.tw/",
                "URI:http://x.tw/",
            ),
            (
                GeneralName::ip_address(&[192, 168, 0, 1]),
                b"\x87\x04\xc0\xa8\x00\x01",
                "IP:192.168.0.1",
            ),
            (
                GeneralName::RegisteredId("2.5.4.3".parse().unwrap()),
                b"\x88\x03\x55\x04\x03",
                "RID:2.5.4.3",
            ),
        ] {
            assert_eq!(round_trip(&name), wire, "{text}");
            assert_eq!(name.to_string(), text);
        }
        assert!(matches!(
            GeneralName::dns_name("caf\u{e9}.tw"),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn a_directory_name_is_tagged_explicitly_because_name_is_a_choice() {
        let name = GeneralName::DirectoryName("CN=A".parse().unwrap());
        let der = round_trip(&name);
        assert_eq!(
            der,
            b"\xa4\x0e\x30\x0c\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x13\x01A"
        );
        assert_eq!(name.to_string(), "DirName:CN=A");
        // the RDNs directly inside [4], as an implicit tag would put them, are not a Name
        assert!(
            GeneralName::decode(
                b"\xa4\x0c\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x13\x01A",
                &options()
            )
            .is_err()
        );
    }

    #[test]
    fn the_sequence_kinds_carry_their_fields_directly_under_the_context_tag() {
        let upn = OtherName::new(
            "1.3.6.1.4.1.311.20.2.3".parse::<Asn1Oid>().unwrap(),
            Asn1Utf8String::new("u@x"),
        );
        let name = GeneralName::OtherName(upn);
        let der = round_trip(&name);
        assert_eq!(
            der,
            b"\xa0\x13\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03\xa0\x05\x0c\x03u@x"
        );
        assert_eq!(name.to_string(), "otherName:1.3.6.1.4.1.311.20.2.3:u@x");

        let party =
            GeneralName::EdiPartyName(EdiPartyName::new(DirectoryString::new("Acme").unwrap()));
        let der = round_trip(&party);
        assert_eq!(der, b"\xa5\x08\xa1\x06\x13\x04Acme");
        assert_eq!(party.to_string(), "EdiPartyName:Acme");
    }

    #[test]
    fn an_x400_address_is_kept_as_a_tree_and_written_back_under_its_tag() {
        let wire = b"\xa3\x05\x30\x03\x02\x01\x07";
        let (_, name) = GeneralName::decode(wire, &options()).unwrap();
        assert!(matches!(
            &name,
            GeneralName::X400Address(Asn1Object::Constructed(_))
        ));
        assert_eq!(name.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            name.to_string(),
            "X400Name:[CONTEXT 3]\n  SEQUENCE\n    INTEGER 7\n"
        );
    }

    #[test]
    fn ip_addresses_print_by_length() {
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        v6[15] = 1;
        for (octets, text) in [
            (&v6[..], "IP:2001:db8:0:0:0:0:0:1"),
            (&[10, 0, 0, 0, 255, 0, 0, 0], "IP:10.0.0.0/255.0.0.0"),
            (&[1, 2, 3], "IP:010203"),
        ] {
            assert_eq!(GeneralName::ip_address(octets).to_string(), text);
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The vectors of Bouncy Castle's `GeneralNameTest.IPv4` and `IPv6`.
    #[test]
    fn ip_addresses_written_as_text_encode_like_bouncy_castle() {
        for (text, der) in [
            ("10.9.8.0", "87040a090800"),
            ("10.9.8.0/255.255.255.0", "87080a090800ffffff00"),
            ("10.9.8.0/24", "87080a090800ffffff00"),
            ("10.9.8.0/255.255.128.0", "87080a090800ffff8000"),
            ("10.9.8.0/17", "87080a090800ffff8000"),
            ("10.9.8.0/255.255.192.0", "87080a090800ffffc000"),
            ("10.9.8.0/18", "87080a090800ffffc000"),
            (
                "2001:0db8:85a3:08d3:1319:8a2e:0370:7334",
                "871020010db885a308d313198a2e03707334",
            ),
            (
                "2001:0db8:85a3::1319:8a2e:0370:7334",
                "871020010db885a3000013198a2e03707334",
            ),
            ("::1", "871000000000000000000000000000000001"),
            (
                "2001:0db8:85a3::8a2e:0370:7334",
                "871020010db885a3000000008a2e03707334",
            ),
            (
                "2001:0db8:85a3::8a2e:10.9.8.0",
                "871020010db885a3000000008a2e0a090800",
            ),
            (
                "2001:0db8:85a3::8a2e:10.9.8.0/ffff:ffff:ffff::0000",
                "872020010db885a3000000008a2e0a090800ffffffffffff00000000000000000000",
            ),
            (
                "2001:0db8:85a3::8a2e:10.9.8.0/128",
                "872020010db885a3000000008a2e0a090800ffffffffffffffffffffffffffffffff",
            ),
            (
                "2001:0db8:85a3::/48",
                "872020010db885a300000000000000000000ffffffffffff00000000000000000000",
            ),
            (
                "2001:0db8:85a3::/47",
                "872020010db885a300000000000000000000fffffffffffe00000000000000000000",
            ),
            (
                "2001:0db8:85a3::/49",
                "872020010db885a300000000000000000000ffffffffffff80000000000000000000",
            ),
        ] {
            let name = GeneralName::ip_address_from_str(text).unwrap();
            assert_eq!(round_trip(&name), hex(der), "{text}");
        }
    }

    #[test]
    fn ip_address_text_round_trips_through_display_and_rejects_anything_else() {
        for text in ["10.0.0.0/255.0.0.0", "2001:db8:0:0:0:0:0:1"] {
            let name = GeneralName::ip_address_from_str(text).unwrap();
            assert_eq!(name.to_string(), alloc::format!("IP:{text}"));
        }
        // BC reads a mask of "::" as a prefix length and throws; it is mask zero here.
        let name = GeneralName::ip_address_from_str("2001:db8::/::").unwrap();
        let mut octets = [0u8; 32];
        octets[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(name, GeneralName::ip_address(&octets));
        for invalid in [
            "",
            "10.9.8",
            "10.9.8.0/33",
            "www.example.com",
            "1::2::3",
            "g::1",
        ] {
            assert_eq!(
                GeneralName::ip_address_from_str(invalid),
                Err(Asn1Error::MalformedValue),
                "{invalid}"
            );
        }
    }

    #[test]
    fn a_tag_outside_the_choice_is_unexpected() {
        for wire in [
            &b"\x89\x00"[..],      // [9]
            b"\x16\x04x.tw",       // a universal IA5String
            b"\x02\x01\x01",       // INTEGER
            b"\xa1\x04\x16\x02x.", // [1] constructed
        ] {
            assert!(
                matches!(
                    GeneralName::decode(wire, &options()),
                    Err(Asn1Error::UnexpectedTag)
                ),
                "{wire:02X?}"
            );
        }
    }
}
