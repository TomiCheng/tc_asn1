//! `Name` from its RFC 4514 string representation.
//!
//! ```text
//! distinguishedName = [ RDN *( "," RDN ) ]        -- most specific first
//! RDN               = attribute *( "+" attribute )
//! attribute         = type "=" value
//! type              = short name (any case) / dotted OID [ "OID." prefix ]
//! value             = string with "\" escapes / "#" hex of the DER value
//! ```
//!
//! Beyond RFC 4514 this accepts, as RFC 2253 did, whitespace around the
//! separators and a value in double quotes. A text value takes the syntax
//! its type declares: an IA5String for `DC` and `emailAddress`; a
//! PrintableString for `C`, `serialNumber`, `dnQualifier`,
//! `telephoneNumber`, `gender`, `countryOfCitizenship`, `countryOfResidence`
//! and `jurisdictionCountryName`; a GeneralizedTime, `YYYYMMDDhhmmssZ`, for
//! `dateOfBirth`; and a [`DirectoryString`] for every other type.
//! `x500UniqueIdentifier` (a BIT STRING) and `postalAddress` (a SEQUENCE OF)
//! have no text form here and take only the `#` form. Size constraints, such
//! as a country code being two letters, are not checked. A `#` value is
//! decoded as DER and classified like a decoded one. Every syntax error is
//! `MalformedValue`.

use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ia5String, Asn1Object, Asn1Oid, Decode, DecodeContent,
    DecodingContext, DecodingOptions,
};

use crate::{
    AttributeType, AttributeTypeAndValue, AttributeValue, DirectoryString, Name,
    RelativeDistinguishedName,
};

impl FromStr for Name {
    type Err = Asn1Error;

    /// Variable time; for public values.
    fn from_str(text: &str) -> Result<Self, Asn1Error> {
        // Only leading whitespace can be dropped here: a trailing escaped
        // space belongs to the last value.
        let mut rest = text.trim_start();
        let mut rdns = Vec::new();
        let mut attributes = Vec::new();
        if rest.is_empty() {
            return Ok(Self::new(rdns));
        }
        loop {
            let (attribute, separator, after) = parse_attribute(rest)?;
            attributes.push(attribute);
            rest = after;
            if separator != Some('+') {
                rdns.push(RelativeDistinguishedName::new(core::mem::take(
                    &mut attributes,
                ))?);
            }
            if separator.is_none() {
                break;
            }
        }
        rdns.reverse();
        Ok(Self::new(rdns))
    }
}

/// One `type=value`, the separator that ended it and what follows it.
fn parse_attribute(text: &str) -> Result<(AttributeTypeAndValue, Option<char>, &str), Asn1Error> {
    let (type_text, rest) = text.split_once('=').ok_or(Asn1Error::MalformedValue)?;
    let attribute_type = parse_type(type_text.trim())?;
    let (raw, separator, rest) = parse_value(rest)?;
    let value = match raw {
        Raw::Der(der) => {
            let (used, value) = AttributeValue::decode_der(&der, &DecodingOptions::default())?;
            if used != der.len() {
                return Err(Asn1Error::TrailingData);
            }
            value
        }
        Raw::Text(text) => text_value(&attribute_type, &text)?,
    };
    Ok((
        AttributeTypeAndValue::new(attribute_type, value),
        separator,
        rest,
    ))
}

/// A text value in the syntax its type declares.
fn text_value(attribute_type: &Asn1Oid, text: &str) -> Result<AttributeValue, Asn1Error> {
    Ok(match AttributeType::from_oid(attribute_type) {
        Some(AttributeType::DOMAIN_COMPONENT | AttributeType::EMAIL_ADDRESS) => {
            Asn1Ia5String::new(text)?.into()
        }
        Some(
            AttributeType::COUNTRY_NAME
            | AttributeType::SERIAL_NUMBER
            | AttributeType::DN_QUALIFIER
            | AttributeType::TELEPHONE_NUMBER
            | AttributeType::GENDER
            | AttributeType::COUNTRY_OF_CITIZENSHIP
            | AttributeType::COUNTRY_OF_RESIDENCE
            | AttributeType::JURISDICTION_COUNTRY_NAME,
        ) => match DirectoryString::new(text)? {
            // `new` falls back to UTF8String, which these types do not allow.
            printable @ DirectoryString::PrintableString(_) => printable.into(),
            _ => return Err(Asn1Error::MalformedValue),
        },
        Some(AttributeType::DATE_OF_BIRTH) => {
            // The contents octets of a GeneralizedTime are its text.
            let mut context = DecodingContext::new(DecodingOptions::default());
            let time = Asn1GeneralizedTime::decode_content(text.as_bytes(), &mut context)?;
            Asn1Object::from(time).into()
        }
        Some(AttributeType::X500_UNIQUE_IDENTIFIER | AttributeType::POSTAL_ADDRESS) => {
            return Err(Asn1Error::MalformedValue);
        }
        _ => DirectoryString::new(text)?.into(),
    })
}

fn parse_type(text: &str) -> Result<Asn1Oid, Asn1Error> {
    if let Some(known) = AttributeType::from_short_name(text) {
        return Ok(known.oid());
    }
    let dotted = text
        .strip_prefix("OID.")
        .or_else(|| text.strip_prefix("oid."))
        .unwrap_or(text);
    dotted.parse()
}

enum Raw {
    Text(String),
    Der(Vec<u8>),
}

/// The value up to an unescaped `,` or `+`, with escapes resolved. Leading
/// whitespace and unescaped trailing whitespace are dropped.
fn parse_value(text: &str) -> Result<(Raw, Option<char>, &str), Asn1Error> {
    let text = text.trim_start();
    if let Some(hex) = text.strip_prefix('#') {
        let end = hex.find([',', '+']).unwrap_or(hex.len());
        let der = decode_hex(hex[..end].trim_end())?;
        let (separator, rest) = after_value(&hex[end..])?;
        return Ok((Raw::Der(der), separator, rest));
    }

    let (quoted, text) = match text.strip_prefix('"') {
        Some(inner) => (true, inner),
        None => (false, text),
    };
    let mut bytes = Vec::new();
    let mut keep = 0; // length of `bytes` up to the last non-blank or escaped byte
    let mut end = text.len();
    let mut closed = !quoted;
    let mut chars = text.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                if let Some(byte) = hex_pair(&text[i + 1..]) {
                    bytes.push(byte);
                    chars.nth(1);
                } else {
                    let (_, special) = chars.next().ok_or(Asn1Error::MalformedValue)?;
                    if !" \"#+,;<=>\\".contains(special) {
                        return Err(Asn1Error::MalformedValue);
                    }
                    push_char(&mut bytes, special);
                }
                keep = bytes.len();
            }
            '"' if quoted => {
                closed = true;
                keep = bytes.len(); // quoting preserves trailing whitespace
                end = i + 1;
                break;
            }
            ',' | '+' if !quoted => {
                end = i;
                break;
            }
            '"' => return Err(Asn1Error::MalformedValue),
            _ => {
                push_char(&mut bytes, c);
                if !c.is_whitespace() {
                    keep = bytes.len();
                }
            }
        }
    }
    if !closed {
        return Err(Asn1Error::MalformedValue);
    }
    bytes.truncate(keep);
    let value = String::from_utf8(bytes).map_err(|_| Asn1Error::MalformedValue)?;
    let (separator, rest) = after_value(&text[end..])?;
    Ok((Raw::Text(value), separator, rest))
}

/// What may follow a value: nothing, or a separator and the next attribute.
fn after_value(text: &str) -> Result<(Option<char>, &str), Asn1Error> {
    let text = text.trim_start();
    match text.chars().next() {
        None => Ok((None, text)),
        Some(c @ (',' | '+')) => Ok((Some(c), &text[1..])),
        Some(_) => Err(Asn1Error::MalformedValue),
    }
}

fn push_char(bytes: &mut Vec<u8>, c: char) {
    let mut buf = [0; 4];
    bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

fn hex_pair(text: &str) -> Option<u8> {
    let pair = text.get(..2)?;
    if pair.bytes().all(|b| b.is_ascii_hexdigit()) {
        u8::from_str_radix(pair, 16).ok()
    } else {
        None
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, Asn1Error> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(Asn1Error::MalformedValue);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| hex_pair(&text[i..]).ok_or(Asn1Error::MalformedValue))
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1Error, Asn1GeneralizedTime, Asn1Ia5String, Asn1Integer, Asn1Object, NamedOid,
    };

    use crate::{
        AttributeType, AttributeTypeAndValue, AttributeValue, DirectoryString, Name,
        RelativeDistinguishedName,
    };

    fn single(
        attribute_type: NamedOid,
        value: impl Into<AttributeValue>,
    ) -> RelativeDistinguishedName {
        RelativeDistinguishedName::single(AttributeTypeAndValue::new(attribute_type.oid(), value))
    }

    fn text(s: &str) -> DirectoryString {
        DirectoryString::new(s).unwrap()
    }

    fn parse(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn a_plain_name_parses_most_specific_first_and_prints_back_the_same() {
        let expected = Name::new(Vec::from([
            single(AttributeType::COUNTRY_NAME, text("TW")),
            single(AttributeType::ORGANIZATION_NAME, text("Example")),
            single(AttributeType::COMMON_NAME, text("Alice")),
        ]));
        assert_eq!(parse("CN=Alice,O=Example,C=TW"), expected);
        assert_eq!(parse(" cn = Alice , o=Example ,C=TW "), expected);
        assert_eq!(
            parse("2.5.4.3=Alice,OID.2.5.4.10=Example,oid.2.5.4.6=TW"),
            expected
        );
        assert_eq!(
            parse("CN=Alice,O=Example,C=TW").to_string(),
            "CN=Alice,O=Example,C=TW"
        );
        assert!(parse("").is_empty());
        assert!(parse("   ").is_empty());
    }

    #[test]
    fn a_multi_valued_rdn_is_joined_with_plus() {
        let name = parse("CN=Alice+serialNumber=123,O=Example");
        assert_eq!(name.rdns().len(), 2);
        assert!(name.rdns()[1].is_multi_valued());
        assert_eq!(
            name.rdns()[1].attributes()[0].attribute_type(),
            &AttributeType::COMMON_NAME.oid()
        );
        assert_eq!(name.to_string(), "CN=Alice+serialNumber=123,O=Example");
    }

    #[test]
    fn escapes_hex_pairs_and_quotes_resolve_to_the_literal_text() {
        let cn = |s: &str| {
            parse(s).rdns().last().unwrap().attributes()[0]
                .value()
                .clone()
        }; // the CN is written first, so stored last
        assert_eq!(cn(r"CN=Smith\, John"), text("Smith, John").into());
        assert_eq!(
            cn(r"CN=\ lead\ and\ trail\ "),
            text(" lead and trail ").into()
        );
        assert_eq!(cn(r"CN=\#not\ hex"), text("#not hex").into());
        assert_eq!(
            cn(r#"CN=a\+b\=c\<d\>e\;f\"g\\h"#),
            text("a+b=c<d>e;f\"g\\h").into()
        );
        assert_eq!(cn(r"CN=Caf\C3\A9"), text("Caf\u{e9}").into());
        assert_eq!(cn(r#"CN="Smith, John ""#), text("Smith, John ").into());
        assert_eq!(cn(r#"CN="a\"b",O=x"#), text("a\"b").into());
        // the printer escapes everything the parser resolves
        for s in ["CN=\\ a\\,b\\+c\\\\d#\\ ", "CN=\\#x", "CN=Caf\u{e9}"] {
            assert_eq!(parse(s).to_string(), s);
        }
    }

    #[test]
    fn a_hash_value_is_the_der_of_the_value() {
        let name = parse("1.2.3.4=#02012a");
        assert_eq!(
            name.rdns()[0].attributes()[0].value(),
            &AttributeValue::Other(Asn1Object::from(Asn1Integer::from(42)))
        );
        assert_eq!(name.to_string(), "1.2.3.4=#02012a");
        assert_eq!(parse("CN=#1305416c696365"), parse("CN=Alice"));
        // a TeletexString prints as hex, since it has no text form
        assert_eq!(parse("CN=#14025457").to_string(), "CN=#14025457");
    }

    #[test]
    fn the_attribute_type_picks_ia5string_for_dc_and_email() {
        let name = parse("emailAddress=a@example.com,DC=example,DC=com");
        assert_eq!(
            name.rdns()[0],
            single(
                AttributeType::DOMAIN_COMPONENT,
                Asn1Ia5String::new("com").unwrap()
            )
        );
        assert!(matches!(
            name.rdns()[2].attributes()[0].value(),
            AttributeValue::Ia5String(s) if s.as_str() == "a@example.com"
        ));
        assert!(matches!(
            parse("CN=Caf\u{e9}").rdns()[0].attributes()[0].value(),
            AttributeValue::DirectoryString(DirectoryString::Utf8String(_))
        ));
    }

    #[test]
    fn printable_string_types_take_printable_text_and_refuse_the_rest() {
        for s in [
            "C=TW",
            "serialNumber=A123",
            "dnQualifier=x",
            r"telephoneNumber=\+886 2 1234 5678",
            "gender=F",
            "countryOfCitizenship=TW",
            "countryOfResidence=TW",
            "jurisdictionCountryName=TW",
        ] {
            assert!(
                matches!(
                    parse(s).rdns()[0].attributes()[0].value(),
                    AttributeValue::DirectoryString(DirectoryString::PrintableString(_))
                ),
                "{s}"
            );
        }
        // A DirectoryString type falls back to UTF8String; these do not.
        for s in ["C=T\u{e9}", "serialNumber=a@b", "gender="] {
            assert!(
                matches!(s.parse::<Name>(), Err(Asn1Error::MalformedValue)),
                "{s}"
            );
        }
    }

    #[test]
    fn date_of_birth_text_becomes_a_generalized_time() {
        let name = parse("dateOfBirth=19800101120000Z");
        let time = Asn1GeneralizedTime::new(1980, 1, 1, 12, 0, 0).unwrap();
        assert_eq!(
            name.rdns()[0],
            single(AttributeType::DATE_OF_BIRTH, Asn1Object::from(time))
        );
        // No text form on output: it prints as the hex of its DER, which
        // parses back to the same name.
        let printed = name.to_string();
        assert_eq!(printed, "dateOfBirth=#180f31393830303130313132303030305a");
        assert_eq!(parse(&printed), name);
        for s in ["dateOfBirth=1980-01-01", "dateOfBirth=19800101"] {
            assert!(
                matches!(s.parse::<Name>(), Err(Asn1Error::MalformedValue)),
                "{s}"
            );
        }
    }

    #[test]
    fn types_without_a_text_form_accept_only_the_hash_form() {
        for s in ["x500UniqueIdentifier=abc", "postalAddress=1 Main St"] {
            assert!(
                matches!(s.parse::<Name>(), Err(Asn1Error::MalformedValue)),
                "{s}"
            );
        }
        let name = parse("x500UniqueIdentifier=#030200ff");
        assert!(matches!(
            name.rdns()[0].attributes()[0].value(),
            AttributeValue::Other(_)
        ));
        assert_eq!(name.to_string(), "x500UniqueIdentifier=#030200ff");
    }

    #[test]
    fn malformed_text_is_rejected() {
        for s in [
            "CN",             // no '='
            "CN=",            // empty value
            "=Alice",         // empty type
            "bogus=Alice",    // unknown type name
            "CN=Alice,,O=x",  // empty RDN
            "CN=Alice,",      // trailing separator
            "CN=a\\",         // dangling escape
            "CN=a\\q",        // escaping a non-special
            "CN=a\"b",        // unescaped quote inside
            "CN=\"unclosed",  // unclosed quote
            "CN=\"still\\\"", // unclosed quote ending in an escaped one
            "CN=\"a\" b",     // text after the closing quote
            "CN=#",           // no hex
            "CN=#020",        // odd hex digits
            "CN=#02zz",       // not hex
            "CN=#0201",       // truncated DER
            "CN=#02012a00",   // DER with trailing data
            "CN=\\FF",        // not UTF-8
            "DC=caf\u{e9}",   // not IA5
        ] {
            assert!(
                matches!(
                    s.parse::<Name>(),
                    Err(Asn1Error::MalformedValue)
                        | Err(Asn1Error::TrailingData)
                        | Err(Asn1Error::Truncated)
                ),
                "{s}"
            );
        }
    }
}
