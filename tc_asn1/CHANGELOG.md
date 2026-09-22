# Changelog

All notable changes to `tc_asn1` are documented in this file.

## 0.1.1 - Unreleased

### Added

- `Children::from_contents` for reading fields directly from contents
  octets with the decoding context's depth, length and child count limits.
- `Children::collect_all` for decoding all remaining elements into a vector.
- `DecodeContent` for `Asn1SequenceOf<T>` and `Asn1SetOf<T>`, enabling
  IMPLICIT container fields through the tagged readers.
- `Children::get_explicit` for required EXPLICIT fields, checking the
  wrapper tag and requiring exactly one inner element.
- `Children::get_implicit` for required IMPLICIT fields, decoding the
  contents under the caller's tag and decoding context.
- `Children::get_implicit_default` for IMPLICIT fields with a DEFAULT,
  rejecting explicitly encoded default values under DER.
- All three readers accept `impl AsRef<[u8]>`, matching the existing
  tagged readers and supporting both tag arrays and borrowed slices.

### Compatibility

- Additive. Every 0.1.0 program compiles and behaves the same.

## 0.1.0 - 2026-09-21

Initial release.

### Added

- BER, CER and DER codecs for the ASN.1 universal types of X.690, each as
  its own struct: `Asn1Boolean`, `Asn1Integer`, `Asn1BitString`,
  `Asn1OctetString`, `Asn1Null`, `Asn1Oid`, `Asn1RelativeOid`, `Asn1Real`,
  `Asn1Enumerated`, the string types (`Asn1Utf8String`, `Asn1NumericString`,
  `Asn1PrintableString`, `Asn1Ia5String`, `Asn1VisibleString`,
  `Asn1UniversalString`, `Asn1BmpString`), the time types (`Asn1UtcTime`,
  `Asn1GeneralizedTime`, `Asn1Time`, `Asn1Date`, `Asn1TimeOfDay`,
  `Asn1DateTime`, `Asn1Duration`), `Asn1OidIri`, `Asn1RelativeOidIri`,
  `Asn1SequenceOf<T>` and `Asn1SetOf<T>`. Each keeps the value the way the
  wire does, validates its contents on input, and applies the DER rules on
  output and, when decoding under DER, on input.
- The trait layers a structure implements to become a type of its own:
  `DecodeContent` and `EncodeContent` for the contents octets, `EncodeTagged`
  for a complete TLV under a caller-chosen tag, `DecodeInner` and `Encode`
  for one under the type's own tag, `Decode` for the standalone entry points
  `decode` and `decode_der`, and `Tagged` naming the type's tag.
- The tagging wrappers `Explicit` and `Implicit` for writing `[n] EXPLICIT`
  and `[n] IMPLICIT` fields, and `Children::get_explicit_opt`,
  `get_explicit_default` and `get_implicit_opt` for reading them, beside
  `get`, `get_opt`, `get_default` and `end` for plain, OPTIONAL and DEFAULT
  fields and for rejecting leftovers.
- The structural layer for reading without a schema: `Asn1Ref` for one TLV
  borrowed from the input with its tag, class, contents and raw octets;
  `Children` for the elements of a constructed value; `Asn1Any` to keep an
  element as the octets it was read with; `Asn1Constructed<T>` for a
  constructed value under any tag; `Asn1Object` for a whole decoded tree,
  with a `Display` dump.
- `NamedOid`, an OID constant with its dotted form and a name whose content
  octets are checked when compiled, and `Arcs` for iterating an OID.
- `EncodingOptions` with the `BER`, `CER` and `DER` constants, and
  `EncodingType` and `LengthForm` for the places where X.690 leaves the
  encoder a choice: the length form of a constructed value, the order of a
  SET OF, and the segmentation of strings over 1000 octets under CER.
- `DecodingOptions` bounding the nesting depth, the contents length of a
  single value and the element count of a constructed one, checked before
  anything is allocated, with `DecodingContext` carrying the state of a
  decoding; the defaults are depth 32, 16 MiB and 65 536 elements.
- `Asn1Error` naming every rejection, with `NotDer` for what a DER decoding
  refuses beyond the checks every element gets.
- The `tag` module of universal tag constants, including the `CONSTRUCTED_*`
  forms of the string types.
- Dependency-free, `no_std` + `alloc` builds with no feature flags, no
  macros and no I/O.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Decoding accepts any BER; `Decode::decode_der` rejects what is not the
  canonical form. Encoding never produces the looser forms BER permits: the
  three rule sets differ only in the length form, SET OF order and CER
  string segmentation.
- Nothing in this crate handles secret data, so every method runs in
  variable time and documents it.
- Not represented: TeletexString, VideotexString, GraphicString,
  GeneralString and ObjectDescriptor, which stay opaque as `Asn1Any`, and
  the constructed form of the string types beyond `Asn1Constructed`.
  UTCTime and GeneralizedTime accept the RFC 5280 forms only: a UTC offset,
  omitted seconds or fractional seconds are rejected even under BER.
- No derive macro or schema language, no streaming or incremental decoding,
  and no knowledge of any particular protocol; OIDs, extensions and profiles
  belong to the crates built on this one.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
