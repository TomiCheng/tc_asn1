//! Shared validation for decoded representations.

use crate::Asn1Error;

/// Check the DER encoding form of known universal identifiers.
pub(crate) fn check_der_tag(identifier: &[u8]) -> Result<(), Asn1Error> {
    if identifier[0] & 0xc0 != 0 {
        return Ok(());
    }
    use crate::tag;
    for expected in [
        tag::BOOLEAN,
        tag::INTEGER,
        tag::BIT_STRING,
        tag::OCTET_STRING,
        tag::NULL,
        tag::OBJECT_IDENTIFIER,
        tag::OBJECT_DESCRIPTOR,
        tag::EXTERNAL,
        tag::REAL,
        tag::ENUMERATED,
        tag::EMBEDDED_PDV,
        tag::UTF8_STRING,
        tag::RELATIVE_OID,
        tag::TIME,
        tag::SEQUENCE,
        tag::SET,
        tag::NUMERIC_STRING,
        tag::PRINTABLE_STRING,
        tag::TELETEX_STRING,
        tag::VIDEOTEX_STRING,
        tag::IA5_STRING,
        tag::UTC_TIME,
        tag::GENERALIZED_TIME,
        tag::GRAPHIC_STRING,
        tag::VISIBLE_STRING,
        tag::GENERAL_STRING,
        tag::UNIVERSAL_STRING,
        tag::CHARACTER_STRING,
        tag::BMP_STRING,
        tag::DATE,
        tag::TIME_OF_DAY,
        tag::DATE_TIME,
        tag::DURATION,
        tag::OID_IRI,
        tag::RELATIVE_OID_IRI,
    ] {
        if identifier.len() == expected.len()
            && identifier[0] & !0x20 == expected[0] & !0x20
            && identifier[1..] == expected[1..]
            && identifier != expected
        {
            return Err(Asn1Error::NotDer);
        }
    }
    Ok(())
}
