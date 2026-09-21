//! The identifier octets of the universal types (X.680 §8.4, X.690 §8.1.2).
//!
//! Each constant is the complete identifier as it appears on the wire, not
//! the tag number: `SEQUENCE` is `30`, the number 16 with the constructed
//! bit `0x20` set, and the types with numbers above 30 take two octets,
//! `1F` followed by the number. The `CONSTRUCTED_*` constants are the
//! string types with the constructed bit set, the form BER allows and CER
//! requires over 1000 octets. Context-specific identifiers such as `[0]`
//! are written inline where they are used (`[0xA0]`, `[0x81]`); there is
//! no table for them.

pub const BOOLEAN: &[u8] = &[0x01];
pub const INTEGER: &[u8] = &[0x02];
pub const BIT_STRING: &[u8] = &[0x03];
pub const CONSTRUCTED_BIT_STRING: &[u8] = &[0x23];
pub const OCTET_STRING: &[u8] = &[0x04];
pub const CONSTRUCTED_OCTET_STRING: &[u8] = &[0x24];
pub const NULL: &[u8] = &[0x05];
pub const OBJECT_IDENTIFIER: &[u8] = &[0x06];
pub const OBJECT_DESCRIPTOR: &[u8] = &[0x07];
pub const CONSTRUCTED_OBJECT_DESCRIPTOR: &[u8] = &[0x27];
/// Always constructed.
pub const EXTERNAL: &[u8] = &[0x28];
pub const REAL: &[u8] = &[0x09];
pub const ENUMERATED: &[u8] = &[0x0A];
/// Always constructed.
pub const EMBEDDED_PDV: &[u8] = &[0x2B];
pub const UTF8_STRING: &[u8] = &[0x0C];
pub const CONSTRUCTED_UTF8_STRING: &[u8] = &[0x2C];
pub const RELATIVE_OID: &[u8] = &[0x0D];
pub const TIME: &[u8] = &[0x0E];
/// Always constructed.
pub const SEQUENCE: &[u8] = &[0x30];
/// Always constructed.
pub const SET: &[u8] = &[0x31];
pub const NUMERIC_STRING: &[u8] = &[0x12];
pub const CONSTRUCTED_NUMERIC_STRING: &[u8] = &[0x32];
pub const PRINTABLE_STRING: &[u8] = &[0x13];
pub const CONSTRUCTED_PRINTABLE_STRING: &[u8] = &[0x33];
/// T.61; kept opaque as an [`Asn1Any`](crate::Asn1Any).
pub const TELETEX_STRING: &[u8] = &[0x14];
pub const CONSTRUCTED_TELETEX_STRING: &[u8] = &[0x34];
pub const VIDEOTEX_STRING: &[u8] = &[0x15];
pub const CONSTRUCTED_VIDEOTEX_STRING: &[u8] = &[0x35];
pub const IA5_STRING: &[u8] = &[0x16];
pub const CONSTRUCTED_IA5_STRING: &[u8] = &[0x36];
pub const UTC_TIME: &[u8] = &[0x17];
pub const GENERALIZED_TIME: &[u8] = &[0x18];
pub const GRAPHIC_STRING: &[u8] = &[0x19];
pub const CONSTRUCTED_GRAPHIC_STRING: &[u8] = &[0x39];
pub const VISIBLE_STRING: &[u8] = &[0x1A];
pub const CONSTRUCTED_VISIBLE_STRING: &[u8] = &[0x3A];
pub const GENERAL_STRING: &[u8] = &[0x1B];
pub const CONSTRUCTED_GENERAL_STRING: &[u8] = &[0x3B];
pub const UNIVERSAL_STRING: &[u8] = &[0x1C];
pub const CONSTRUCTED_UNIVERSAL_STRING: &[u8] = &[0x3C];
/// Always constructed.
pub const CHARACTER_STRING: &[u8] = &[0x3D];
pub const BMP_STRING: &[u8] = &[0x1E];
pub const CONSTRUCTED_BMP_STRING: &[u8] = &[0x3E];
pub const DATE: &[u8] = &[0x1F, 0x1F];
pub const TIME_OF_DAY: &[u8] = &[0x1F, 0x20];
pub const DATE_TIME: &[u8] = &[0x1F, 0x21];
pub const DURATION: &[u8] = &[0x1F, 0x22];
pub const OID_IRI: &[u8] = &[0x1F, 0x23];
pub const RELATIVE_OID_IRI: &[u8] = &[0x1F, 0x24];
