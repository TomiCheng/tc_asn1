//! The `Zeroize` implementations behind the `zeroize` feature: each type is
//! left holding the value its documentation names, and that value is still
//! valid, encoding and decoding back unchanged.

#![cfg(feature = "zeroize")]

use core::fmt::Debug;

use tc_asn1::{
    Asn1Any, Asn1BitString, Asn1BmpString, Asn1Boolean, Asn1Constructed, Asn1Date, Asn1DateTime,
    Asn1Duration, Asn1Enumerated, Asn1GeneralizedTime, Asn1Ia5String, Asn1Integer, Asn1Null,
    Asn1NumericString, Asn1Object, Asn1OctetString, Asn1Oid, Asn1OidIri, Asn1PrintableString,
    Asn1Real, Asn1RelativeOid, Asn1RelativeOidIri, Asn1SequenceOf, Asn1SetOf, Asn1Time,
    Asn1TimeOfDay, Asn1UniversalString, Asn1UtcTime, Asn1Utf8String, Asn1VisibleString, Decode,
    DecodingOptions, Encode, EncodingOptions, tag,
};
use tc_zeroize::Zeroize;

/// Zeroizes `value`, checks it against `expected`, and checks that the result
/// survives a DER round trip.
fn check<T>(mut value: T, expected: T)
where
    T: Zeroize + Encode + Decode + PartialEq + Debug,
{
    value.zeroize();
    assert_eq!(value, expected);
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (used, back) = T::decode_der(&der, &DecodingOptions::default()).unwrap();
    assert_eq!((used, back), (der.len(), value));
}

#[test]
fn integers_and_enumerations_are_left_as_zero() {
    let secret = Asn1Integer::from_unsigned_bytes(&[0xa5; 256]);
    check(secret, Asn1Integer::from(0));
    check(Asn1Integer::from(-7), Asn1Integer::from(0));
    check(Asn1Enumerated::from(9u64), Asn1Enumerated::from(0u64));
}

#[test]
fn octet_and_bit_strings_are_left_empty() {
    check(Asn1OctetString::new(&[0x5a; 64]), Asn1OctetString::new(&[]));
    check(
        Asn1BitString::from_bits(&[0xf0], 4),
        Asn1BitString::from_bytes(&[]),
    );
}

#[test]
fn booleans_become_false_and_nulls_stay_null() {
    check(Asn1Boolean::from(true), Asn1Boolean::from(false));
    check(Asn1Null, Asn1Null);
}

#[test]
fn identifiers_are_left_as_their_shortest_value() {
    check(
        "1.2.840.113549.1.1.1".parse::<Asn1Oid>().unwrap(),
        "0.0".parse().unwrap(),
    );
    check(
        "8571.3.2".parse::<Asn1RelativeOid>().unwrap(),
        "0".parse().unwrap(),
    );
    check(
        Asn1OidIri::new("/ISO/Registration_Authority").unwrap(),
        Asn1OidIri::new("/0").unwrap(),
    );
    check(
        Asn1RelativeOidIri::new("Registration_Authority/1").unwrap(),
        Asn1RelativeOidIri::new("0").unwrap(),
    );
}

#[test]
fn reals_are_left_as_positive_zero() {
    check(Asn1Real::from(-1234.5), Asn1Real::from(0.0));
}

#[test]
fn character_strings_are_left_empty() {
    check(Asn1Utf8String::new("hunter2"), Asn1Utf8String::new(""));
    check(
        Asn1UniversalString::new("hunter2"),
        Asn1UniversalString::new(""),
    );
    check(
        Asn1NumericString::new("0123 4567").unwrap(),
        Asn1NumericString::new("").unwrap(),
    );
    check(
        Asn1PrintableString::new("hunter2").unwrap(),
        Asn1PrintableString::new("").unwrap(),
    );
    check(
        Asn1Ia5String::new("hunter2").unwrap(),
        Asn1Ia5String::new("").unwrap(),
    );
    check(
        Asn1VisibleString::new("hunter2").unwrap(),
        Asn1VisibleString::new("").unwrap(),
    );
    check(
        Asn1BmpString::new("hunter2").unwrap(),
        Asn1BmpString::new("").unwrap(),
    );
}

#[test]
fn times_are_left_at_the_earliest_value_of_their_type() {
    check(
        Asn1UtcTime::new(2024, 2, 29, 12, 30, 45).unwrap(),
        Asn1UtcTime::new(1950, 1, 1, 0, 0, 0).unwrap(),
    );
    check(
        Asn1GeneralizedTime::new(2024, 2, 29, 12, 30, 45).unwrap(),
        Asn1GeneralizedTime::new(0, 1, 1, 0, 0, 0).unwrap(),
    );
    check(
        Asn1Time::new("2024-01-01T12:30+08:00").unwrap(),
        Asn1Time::new("1582-01-01").unwrap(),
    );
    check(
        Asn1Date::new("2024-02-29").unwrap(),
        Asn1Date::new("1582-01-01").unwrap(),
    );
    check(
        Asn1TimeOfDay::new("23:59:59").unwrap(),
        Asn1TimeOfDay::new("00:00:00").unwrap(),
    );
    check(
        Asn1DateTime::new("2024-02-29T24:00:00").unwrap(),
        Asn1DateTime::new("1582-01-01T00:00:00").unwrap(),
    );
    check(
        Asn1Duration::new("P1Y2M3DT4H5M6S").unwrap(),
        Asn1Duration::new("PT0S").unwrap(),
    );
}

#[test]
fn containers_wipe_their_elements_and_are_left_empty() {
    let integers = || vec![Asn1Integer::from(1), Asn1Integer::from(0x1234)];
    check(Asn1SequenceOf::new(integers()), Asn1SequenceOf::new(vec![]));
    check(Asn1SetOf::new(integers()), Asn1SetOf::new(vec![]));
    check(
        Asn1Constructed::new(&[0xa0], integers()),
        Asn1Constructed::new(&[0xa0], vec![]),
    );
}

#[test]
fn an_any_keeps_its_tag_and_loses_its_contents() {
    check(
        Asn1Any::primitive(tag::OCTET_STRING, b"secret key octets"),
        Asn1Any::primitive(tag::OCTET_STRING, &[]),
    );
    // An indefinite-length SEQUENCE becomes a definite, empty one.
    let ber = [0x30, 0x80, 0x02, 0x01, 0x2a, 0x00, 0x00];
    let mut any = Asn1Any::decode(&ber, &DecodingOptions::default())
        .unwrap()
        .1;
    any.zeroize();
    assert_eq!(any.raw(), [0x30, 0x00]);
    assert_eq!(any.as_ref().value(), []);
    assert_eq!(
        any.encode_to_vec(&EncodingOptions::DER).unwrap(),
        [0x30, 0x00]
    );
}

#[test]
fn a_decoded_tree_is_wiped_through_every_level() {
    // SEQUENCE { INTEGER 0x0102, [0] { OCTET STRING "k" }, BOOLEAN TRUE }
    let der = [
        0x30, 0x0c, 0x02, 0x02, 0x01, 0x02, 0xa0, 0x03, 0x04, 0x01, 0x6b, 0x01, 0x01, 0xff,
    ];
    let mut tree = Asn1Object::decode(&der, &DecodingOptions::default())
        .unwrap()
        .1;
    let Asn1Object::SequenceOf(fields) = &tree else {
        panic!("not a SEQUENCE");
    };
    assert_eq!(fields.elements().len(), 3);
    tree.zeroize();
    assert_eq!(
        tree.encode_to_vec(&EncodingOptions::DER).unwrap(),
        [0x30, 0x00]
    );

    let mut leaf = Asn1Object::from(Asn1Integer::from(0x0102));
    leaf.zeroize();
    assert_eq!(leaf, Asn1Object::from(Asn1Integer::from(0)));
}
