# Changelog

All notable changes to `tc_asn1_x500` are documented in this file.

## 0.1.0 - 2026-09-23

Initial release.

### Added

- `Name`, the X.501 distinguished name as profiled by RFC 5280 §4.1.2.4: a
  SEQUENCE OF `RelativeDistinguishedName`, stored root first and possibly
  empty. `FromStr` parses the RFC 4514 text form, most specific first, with
  short names in any case, dotted OIDs with or without an `OID.` prefix,
  `\` escapes and `#` hex values, and, as RFC 2253 did, whitespace around
  the separators and quoted values. A text value takes the syntax its type
  declares: IA5String for `DC` and `emailAddress`, PrintableString for
  `C`, `serialNumber` and the other printable-only types, GeneralizedTime
  for `dateOfBirth`, and `DirectoryString` otherwise. `Display` writes the
  same form back, using `#` hex for types it does not know and for values
  with no text form.
- `RelativeDistinguishedName`, a non-empty SET OF `AttributeTypeAndValue`,
  with `single` for the usual one-attribute level and `is_multi_valued`.
  CER and DER write the members sorted; construction and wire order is kept.
- `AttributeTypeAndValue`, one `type = value` pair, and `AttributeValue`,
  which classifies the value by its identifier alone: a `DirectoryString`,
  an `Asn1Ia5String`, or any other value kept as an `Asn1Object`. The OID
  is not consulted while decoding. `AttributeValue` is `#[non_exhaustive]`.
- `DirectoryString`, the X.520 string CHOICE. `new` picks PrintableString
  when every character allows it and UTF8String otherwise, as RFC 5280
  prefers, and refuses empty text; decoding accepts an empty value, which
  some certificates carry. TeletexString is kept as its raw octets, and
  `as_str` returns `None` for it.
- `Attribute`, an OID with a non-empty SET OF `AttributeValue`, as in
  certificate request attributes.
- `AttributeType`, 39 `NamedOid` constants for the attribute types found in
  names, from X.520, RFC 4519, PKCS#9, RFC 3739, ISIS-MTT and the CA/Browser
  Forum EV Guidelines, with `ALL`, `from_oid`, and `from_short_name`, which
  ignores ASCII case. Short names follow RFC 4514 §3 where it defines them
  and each type's registered descriptor otherwise.
- `equivalent` on `Name`, `RelativeDistinguishedName`,
  `AttributeTypeAndValue`, `AttributeValue` and `DirectoryString`, the
  relaxed comparison of RFC 5280 §7.1: strings match regardless of their
  string type after RFC 4518 preparation, which ignores case, drops
  invisible characters and collapses whitespace, and the attributes of an
  RDN match in any order. `==` remains the strict comparison of the
  encodings.
- `Decode` and `Encode` for every type, so each reads any BER, writes BER,
  CER or DER, and can be a field of a larger structure; `Tagged` for the
  SEQUENCE and SET types, while the CHOICEs `AttributeValue` and
  `DirectoryString` take the tag of the alternative they hold.
- `no_std` + `alloc` builds with no feature flags, depending only on
  `tc_asn1`.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Requires `tc_asn1` 0.1.1 or later.
- String preparation leaves out the steps that need Unicode tables: NFKC
  normalization and full case folding are not applied, and case folding is
  `char::to_lowercase` one character at a time, so a precomposed and a
  decomposed accent, or `ß` and `ss`, do not match. Text with a code point
  the preparation prohibits matches only identical text.
- Profile rules are not checked: size constraints such as a two-letter
  country code, distinct attribute types within one RDN, and whether a
  particular name may be empty belong to the layer that applies a profile.
- `x500UniqueIdentifier` and `postalAddress` have no text form and take only
  the `#` hex form when parsed.
- No name constraints matching.
- Nothing in this crate handles secret data, so every method runs in
  variable time.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
