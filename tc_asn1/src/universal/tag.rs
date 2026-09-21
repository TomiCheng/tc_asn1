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

/// BOOLEAN, `01`.
pub const BOOLEAN: &[u8] = &[0x01];
/// INTEGER, `02`.
pub const INTEGER: &[u8] = &[0x02];
/// BIT STRING, `03`.
pub const BIT_STRING: &[u8] = &[0x03];
/// Constructed BIT STRING, `23`.
pub const CONSTRUCTED_BIT_STRING: &[u8] = &[0x23];
/// OCTET STRING, `04`.
pub const OCTET_STRING: &[u8] = &[0x04];
/// Constructed OCTET STRING, `24`.
pub const CONSTRUCTED_OCTET_STRING: &[u8] = &[0x24];
/// NULL, `05`.
pub const NULL: &[u8] = &[0x05];
/// OBJECT IDENTIFIER, `06`.
pub const OBJECT_IDENTIFIER: &[u8] = &[0x06];
/// ObjectDescriptor, `07`; kept opaque as an [`Asn1Any`](crate::Asn1Any).
pub const OBJECT_DESCRIPTOR: &[u8] = &[0x07];
/// Constructed ObjectDescriptor, `27`.
pub const CONSTRUCTED_OBJECT_DESCRIPTOR: &[u8] = &[0x27];
/// Always constructed.
pub const EXTERNAL: &[u8] = &[0x28];
/// REAL, `09`.
pub const REAL: &[u8] = &[0x09];
/// ENUMERATED, `0A`.
pub const ENUMERATED: &[u8] = &[0x0A];
/// Always constructed.
pub const EMBEDDED_PDV: &[u8] = &[0x2B];
/// UTF8String, `0C`.
pub const UTF8_STRING: &[u8] = &[0x0C];
/// Constructed UTF8String, `2C`.
pub const CONSTRUCTED_UTF8_STRING: &[u8] = &[0x2C];
/// RELATIVE-OID, `0D`.
pub const RELATIVE_OID: &[u8] = &[0x0D];
/// TIME, `0E`.
pub const TIME: &[u8] = &[0x0E];
/// Always constructed.
pub const SEQUENCE: &[u8] = &[0x30];
/// Always constructed.
pub const SET: &[u8] = &[0x31];
/// NumericString, `12`.
pub const NUMERIC_STRING: &[u8] = &[0x12];
/// Constructed NumericString, `32`.
pub const CONSTRUCTED_NUMERIC_STRING: &[u8] = &[0x32];
/// PrintableString, `13`.
pub const PRINTABLE_STRING: &[u8] = &[0x13];
/// Constructed PrintableString, `33`.
pub const CONSTRUCTED_PRINTABLE_STRING: &[u8] = &[0x33];
/// T.61; kept opaque as an [`Asn1Any`](crate::Asn1Any).
pub const TELETEX_STRING: &[u8] = &[0x14];
/// Constructed TeletexString, `34`.
pub const CONSTRUCTED_TELETEX_STRING: &[u8] = &[0x34];
/// VideotexString, `15`; kept opaque as an [`Asn1Any`](crate::Asn1Any).
pub const VIDEOTEX_STRING: &[u8] = &[0x15];
/// Constructed VideotexString, `35`.
pub const CONSTRUCTED_VIDEOTEX_STRING: &[u8] = &[0x35];
/// IA5String, `16`.
pub const IA5_STRING: &[u8] = &[0x16];
/// Constructed IA5String, `36`.
pub const CONSTRUCTED_IA5_STRING: &[u8] = &[0x36];
/// UTCTime, `17`.
pub const UTC_TIME: &[u8] = &[0x17];
/// GeneralizedTime, `18`.
pub const GENERALIZED_TIME: &[u8] = &[0x18];
/// GraphicString, `19`; kept opaque as an [`Asn1Any`](crate::Asn1Any).
pub const GRAPHIC_STRING: &[u8] = &[0x19];
/// Constructed GraphicString, `39`.
pub const CONSTRUCTED_GRAPHIC_STRING: &[u8] = &[0x39];
/// VisibleString, `1A`.
pub const VISIBLE_STRING: &[u8] = &[0x1A];
/// Constructed VisibleString, `3A`.
pub const CONSTRUCTED_VISIBLE_STRING: &[u8] = &[0x3A];
/// GeneralString, `1B`; kept opaque as an [`Asn1Any`](crate::Asn1Any).
pub const GENERAL_STRING: &[u8] = &[0x1B];
/// Constructed GeneralString, `3B`.
pub const CONSTRUCTED_GENERAL_STRING: &[u8] = &[0x3B];
/// UniversalString, `1C`.
pub const UNIVERSAL_STRING: &[u8] = &[0x1C];
/// Constructed UniversalString, `3C`.
pub const CONSTRUCTED_UNIVERSAL_STRING: &[u8] = &[0x3C];
/// Always constructed.
pub const CHARACTER_STRING: &[u8] = &[0x3D];
/// BMPString, `1E`.
pub const BMP_STRING: &[u8] = &[0x1E];
/// Constructed BMPString, `3E`.
pub const CONSTRUCTED_BMP_STRING: &[u8] = &[0x3E];
/// DATE, `1F 1F`.
pub const DATE: &[u8] = &[0x1F, 0x1F];
/// TIME-OF-DAY, `1F 20`.
pub const TIME_OF_DAY: &[u8] = &[0x1F, 0x20];
/// DATE-TIME, `1F 21`.
pub const DATE_TIME: &[u8] = &[0x1F, 0x21];
/// DURATION, `1F 22`.
pub const DURATION: &[u8] = &[0x1F, 0x22];
/// OID-IRI, `1F 23`.
pub const OID_IRI: &[u8] = &[0x1F, 0x23];
/// RELATIVE-OID-IRI, `1F 24`.
pub const RELATIVE_OID_IRI: &[u8] = &[0x1F, 0x24];
