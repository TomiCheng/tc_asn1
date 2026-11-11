# Changelog

All notable changes to `tc_asn1` are documented in this file.

## 0.1.4 - Unreleased

### Added

- `Encode::encode_to_writer`, behind the `std` feature below: writes the
  whole TLV to a borrowed `dyn std::io::Write`, so `dyn Encode` stays
  possible. The provided method encodes in memory and writes the result; a
  type that may be large can write its parts as it goes instead.
  `Asn1OctetString` does: it writes its identifier and length octets, then
  its contents straight from the value.
- An optional `std` feature, off by default, with the `io` module and
  `io::Asn1Writer`, after Bouncy Castle's `Asn1OutputStream`: it wraps any `std::io::Write`, such as a file
  or a socket, and writes values one after another under the rules it was
  created with. An encoding failure is `io::ErrorKind::InvalidData` carrying
  the `Asn1Error`, with nothing written. Each value is encoded in memory and
  then written whole.
- `io::Asn1Reader`, also behind `std`, after Bouncy Castle's `Asn1InputStream`: it
  wraps any `std::io::Read` and, with `read_value`, reads values one after
  another, `None` at the end of the input. Each value is read whole,
  following an indefinite length to its end-of-contents octets, and decoded as BER. A definite length is
  checked against `max_content_len` before it is read, the whole value is held
  to that limit, and nesting to `depth`, so a peer cannot make it allocate
  without bound. Input ending inside a value is `UnexpectedEof`; a value over
  a limit or of another type is `InvalidData` carrying the `Asn1Error`.
  It reads exactly the octets of a value and nothing past them, and memory
  grows with the octets that arrive, not with the length a peer claims.
  `read_object` reads a value of unknown type as an `Asn1Object`, and
  `read_header` reads only the identifier and length octets, as an
  `io::Asn1Header` of an `io::Asn1Tag` and an `io::Asn1Length`, under the same
  rules `Asn1Ref::parse` applies.
- `io::Asn1Reader::read`, after Bouncy Castle's `Asn1StreamParser`: it walks
  values without reading any of them whole, as `io::Asn1Event`s, the start of
  a constructed value, a primitive value whose contents `body` streams, and
  the end of the innermost open one, so a value larger than memory can be
  read part by part. `read_value` inside a value it opened reads the next child
  whole and gives `None` at the end of that value. A child reaching past the
  definite length around it is `MalformedValue`.

### Compatibility

- Additive. Without `std` the crate is `no_std` as before and has the same
  API; with it, it links the standard library and adds no dependency.
  `encode_to_writer` is a provided method, so every existing `Encode`
  implementation keeps compiling; a crate that overrides it does so under
  `tc_asn1/std`.

## 0.1.3 - 2026-11-10

### Added

- Fractional seconds in `Asn1GeneralizedTime`, to the nanosecond:
  `with_nanosecond`, `with_microsecond` and `with_millisecond` set them, and
  `nanosecond`, `microsecond` and `millisecond` read them, the last two
  rounding down. Decoding accepts
  one to nine digits after a full stop; under DER a comma, a trailing zero or
  a zero fraction is `NotDer`, and BER accepts them. More than nine digits, or
  a separator without digits, is `MalformedValue`. Encoding always writes the
  DER form, leaving a zero fraction out, and `Display` adds the digits before
  the `Z`. RFC 3161 timestamps carry such times.

### Compatibility

- Additive in the API: `new` and the accessors are unchanged, and a time
  without a fraction encodes, displays and compares as before.
- Decoding accepts the fractional seconds that 0.1.2 refused as
  `MalformedValue`. RFC 5280 forbids them in certificates, so a certificate
  reader that relied on the refusal checks `nanosecond() == 0` itself.
- With `chrono`, converting to `chrono::DateTime<Utc>` now carries the
  fraction, which was always zero before. Converting from chrono still
  truncates to the second; `with_nanosecond` adds the fraction back.

## 0.1.2 - 2026-10-25

### Added

- An optional `zeroize` feature, off by default, implementing
  `tc_zeroize::Zeroize` for every type that owns data: `Asn1Integer`,
  `Asn1Enumerated`, `Asn1OctetString`, `Asn1BitString`, `Asn1Boolean`,
  `Asn1Null`, `Asn1Oid`, `Asn1RelativeOid`, `Asn1Real`, the string types,
  the time types, `Asn1OidIri`, `Asn1RelativeOidIri` and `Asn1Any`, and
  `Asn1SequenceOf<T>`, `Asn1SetOf<T>`, `Asn1Constructed<T>` and
  `Asn1Object` when their elements are `Zeroize`. A key container can now
  erase the secret octets it decoded from its own `Drop`.
- A zeroized value remains a valid value of its type: integers,
  enumerations and REAL become zero, strings and containers empty,
  identifiers their shortest value, times the earliest value of their type,
  and `Asn1Any` keeps its tag with empty contents. No type erases itself on
  drop; that policy belongs to the container that knows it holds a secret.
- An optional `chrono` feature, off by default, converting `Asn1UtcTime`
  and `Asn1GeneralizedTime` to `chrono::DateTime<Utc>` with `From`, and
  back with `TryFrom`, which truncates to the second, turns a leap second
  into `:59`, and returns `MalformedValue` for a year outside the type's
  range.

### Compatibility

- Additive. Both features are off by default; every 0.1.x program compiles
  and behaves the same, and the default build still has no dependencies.

## 0.1.1 - 2026-09-22

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
