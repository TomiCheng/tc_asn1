# tc_asn1

[![crates.io](https://img.shields.io/crates/v/tc_asn1.svg)](https://crates.io/crates/tc_asn1)
[![docs.rs](https://docs.rs/tc_asn1/badge.svg)](https://docs.rs/tc_asn1)
[![CI](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

A toolkit for writing ASN.1 schemas as Rust types.

An ASN.1 module defines structures — a certificate, a signed message, a key
file — and this crate is what those structures are written with. A
structure of your own reads and writes its fields through the same traits
the built-in universal types use, so it becomes a type like them and can be
a field of the next structure up. The X.690 rules — tags, lengths, the DER
canonical form, the places where BER, CER and DER differ — live in the
crate, not in the schema.

The second use is looking at an encoding whose schema you do not have, or
have not written yet: decode any BER into a tree and dump it, or walk the
elements one level at a time.

The crate is `no_std` + `alloc`, has no dependencies, no macros and no I/O,
and knows nothing of any protocol.

## Usage

One structure, with a `[0] EXPLICIT` field: on the wire it is wrapped in a
constructed element tagged `A0` (context-specific, constructed, number 0),
and being OPTIONAL the wrapper is simply absent when the field is.

```rust
use tc_asn1::{Asn1Integer, Asn1Utf8String, Tagged, tag};

/// Note ::= SEQUENCE {
///     text      UTF8String,
///     priority  [0] EXPLICIT INTEGER OPTIONAL }
#[derive(Debug, PartialEq, Eq)]
pub struct Note {
    pub text: Asn1Utf8String,
    pub priority: Option<Asn1Integer>,
}

impl Tagged for Note {
    const TAG: &'static [u8] = tag::SEQUENCE;
}
```

### Encoding

`EncodeContent` writes the fields back to back, the `Explicit` wrapper
adding the `A0` header around the tagged one; `Encode` puts the SEQUENCE
header in front. `EncodeTagged` is the layer between them and needs no
code.

```rust
use tc_asn1::{Asn1Error, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit};

impl EncodeContent for Note {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.text.encoded_len(rules)
            + self
                .priority
                .as_ref()
                .map_or(0, |p| Explicit::new(&[0xA0], p).encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.text.encode(rules, out)?;
        if let Some(priority) = &self.priority {
            at += Explicit::new(&[0xA0], priority).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}
impl EncodeTagged for Note {}

impl Encode for Note {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

let note = Note {
    text: Asn1Utf8String::new("hi"),
    priority: Some(Asn1Integer::from(2)),
};
let der = note.encode_to_vec(&EncodingOptions::DER)?;
assert_eq!(der, [0x30, 0x09, 0x0C, 0x02, b'h', b'i', 0xA0, 0x03, 0x02, 0x01, 0x02]);

let plain = Note { text: Asn1Utf8String::new("hi"), priority: None };
assert_eq!(plain.encode_to_vec(&EncodingOptions::DER)?, [0x30, 0x04, 0x0C, 0x02, b'h', b'i']);
# Ok::<(), Asn1Error>(())
```

`EncodingOptions` picks the rule set: `DER` here, `BER` and `CER` are the
other constants, and `new` takes anything else such as indefinite BER.

### Decoding

`DecodeInner` parses the SEQUENCE and reads the fields in order through
`Children`: `get` for a required field, `get_explicit_opt` for the tagged
OPTIONAL one, which looks at the next element and leaves it alone when the
tag is not `A0`, and `end` to reject anything left over. `Decode` adds the
standalone entry points and needs no code.

```rust
use tc_asn1::{Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, DecodingOptions};

impl DecodeInner for Note {
    fn decode_inner(buff: &[u8], context: &mut DecodingContext) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let text = fields.get()?;
        let priority = fields.get_explicit_opt([0xA0])?;
        fields.end()?;
        Ok((element.total_len(), Self { text, priority }))
    }
}
impl Decode for Note {}

let der = [0x30, 0x09, 0x0C, 0x02, b'h', b'i', 0xA0, 0x03, 0x02, 0x01, 0x02];
let (used, note) = Note::decode(&der, &DecodingOptions::default())?;
assert_eq!(used, der.len());
assert_eq!(note.text.as_str(), "hi");
assert_eq!(note.priority, Some(Asn1Integer::from(2)));

let (_, plain) = Note::decode(&[0x30, 0x04, 0x0C, 0x02, b'h', b'i'], &DecodingOptions::default())?;
assert_eq!(plain.priority, None);
# Ok::<(), Asn1Error>(())
```

`decode` accepts any BER and returns how many octets it used; `decode_der`
also rejects whatever is not the canonical form.

## Without a schema

`Asn1Object` is a tree with one variant per universal type, a `Constructed`
node for a constructed value under any other tag and an `Unknown` leaf for
a primitive one. It is built by hand or decoded from any BER, encodes under
any rule set and dumps itself through `Display`.

### Encoding

```rust
use tc_asn1::{Asn1Error, Asn1Integer, Asn1Null, Asn1Object, Asn1OctetString, Asn1Oid, Encode, EncodingOptions};

// AlgorithmIdentifier { rsaEncryption, NULL }, then a key inside an OCTET STRING.
let tree = Asn1Object::sequence(vec![
    Asn1Object::sequence(vec![
        "1.2.840.113549.1.1.1".parse::<Asn1Oid>()?.into(),
        Asn1Null.into(),
    ]),
    Asn1OctetString::new(&[0x01, 0x02, 0x03]).into(),
]);
let der = tree.encode_to_vec(&EncodingOptions::DER)?;
assert_eq!(der, [
    0x30, 0x14, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x04, 0x03, 0x01, 0x02, 0x03,
]);

// A SET is sorted on the way out under DER, whatever order it was built in.
let set = Asn1Object::set(vec![Asn1Integer::from(2).into(), Asn1Integer::from(1).into()]);
assert_eq!(set.encode_to_vec(&EncodingOptions::DER)?, [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
# Ok::<(), Asn1Error>(())
```

### Decoding

```rust
use tc_asn1::{Asn1Error, Asn1Object, Asn1Ref, Decode, DecodingContext, DecodingOptions};

// Something received without its schema.
let bytes = [
    0x30, 0x0F, 0x02, 0x01, 0x01, 0xA0, 0x05, 0x0C, 0x03, b'a', b'b', b'c', 0x04, 0x03, 0x01,
    0x02, 0x03,
];

// As a tree.
let (_, tree) = Asn1Object::decode(&bytes, &DecodingOptions::default())?;
assert_eq!(
    tree.to_string(),
    "SEQUENCE\n  INTEGER 1\n  [CONTEXT 0]\n    UTF8String \"abc\"\n  OCTET STRING (3 bytes) 010203\n"
);
if let Asn1Object::SequenceOf(fields) = &tree {
    if let Asn1Object::Integer(version) = &fields.elements()[0] {
        assert_eq!(u8::try_from(version)?, 1);
    }
}

// One level at a time, borrowing from the input without building anything.
let mut context = DecodingContext::new(DecodingOptions::default());
let outer = Asn1Ref::parse(&bytes, &mut context)?;
let tags: Vec<&[u8]> = outer
    .children(&mut context)?
    .map(|child| child.map(|c| c.tag()))
    .collect::<Result<_, _>>()?;
assert_eq!(tags, [&[0x02][..], &[0xA0], &[0x04]]);
# Ok::<(), Asn1Error>(())
```

A structure that must carry an element it does not interpret keeps it as an
`Asn1Any`, which writes back exactly the octets it read.

## Tool types

The types that are not ASN.1 values themselves but what a schema is written
with, or what stands in for one.

| Type | Role |
| --- | --- |
| `Asn1Ref` | One TLV borrowed from the input: tag, class, contents, end-of-contents octets, and the whole thing as `raw()` for a signature to cover |
| `Children` | The elements of a constructed value, read in order: `get` for a required field, `get_opt` and `get_default` for OPTIONAL and DEFAULT, `get_explicit_opt`, `get_explicit_default` and `get_implicit_opt` for tagged fields, `end` to reject leftovers |
| `Explicit`, `Implicit` | The encoding side of a tagged field: `Explicit` wraps the value's whole TLV under the tag, `Implicit` writes the value's contents under it |
| `Asn1Any` | An element kept as the octets it was read with, written back unchanged under any rules; for what a structure carries but does not interpret |
| `Asn1Constructed<T>` | A constructed value under any tag holding elements of one type: the mechanism behind SEQUENCE OF, SET OF and `[n] IMPLICIT SEQUENCE OF` |
| `Asn1Object` | A whole decoded tree, one variant per universal type, for reading and writing without a schema |
| `NamedOid` | An OID constant with its dotted form and a name, checked when compiled; the building block of an OID table |
| `DecodingContext`, `DecodingOptions` | The state a decoding carries (depth, DER or not) and the limits it is held to (depth, contents length, element count) |
| `EncodingOptions` | The rule set to write: `BER`, `CER`, `DER`, or `new` for indefinite BER |

## Universal types

Every type decodes any BER, applies the DER contents rules on output and,
in a DER decoding context, on input; the last column is what that context
rejects with `NotDer` beyond the header checks every element gets.

| ASN.1 | Tag | Rust type | Validated | DER adds |
| --- | --- | --- | --- | --- |
| BOOLEAN | `01` | `Asn1Boolean` | one octet | TRUE is `FF` |
| INTEGER | `02` | `Asn1Integer` | shortest two's complement; any size, `TryFrom` to the primitives, `Display` and hex | — |
| BIT STRING | `03` | `Asn1BitString` | unused bits 0–7 | unused bits are zero |
| OCTET STRING | `04` | `Asn1OctetString` | — | — |
| NULL | `05` | `Asn1Null` | no contents | — |
| OBJECT IDENTIFIER | `06` | `Asn1Oid` | base-128 arcs, first-arc rules; dotted text both ways | — |
| REAL | `09` | `Asn1Real` | binary and decimal forms kept exactly; `f64` both ways, exact or `InexactValue` | canonical base-2 or NR3 form |
| ENUMERATED | `0A` | `Asn1Enumerated` | as INTEGER | — |
| UTF8String | `0C` | `Asn1Utf8String` | valid UTF-8 | — |
| RELATIVE-OID | `0D` | `Asn1RelativeOid` | base-128 arcs | — |
| TIME | `0E` | `Asn1Time` | X.680 §38 notation | canonical notation |
| SEQUENCE OF | `30` | `Asn1SequenceOf<T>` | element type | — |
| SET OF | `31` | `Asn1SetOf<T>` | element type; sorted on CER/DER output, order-free `Eq` | — (order is not checked) |
| NumericString | `12` | `Asn1NumericString` | digits and space | — |
| PrintableString | `13` | `Asn1PrintableString` | the X.680 §41.4 set | — |
| IA5String | `16` | `Asn1Ia5String` | 7-bit ASCII | — |
| UTCTime | `17` | `Asn1UtcTime` | `YYMMDDhhmmssZ` only, Gregorian calendar, 1950–2049 | — |
| GeneralizedTime | `18` | `Asn1GeneralizedTime` | `YYYYMMDDhhmmssZ` only, Gregorian calendar | — |
| VisibleString | `1A` | `Asn1VisibleString` | `0x20`–`0x7E` | — |
| UniversalString | `1C` | `Asn1UniversalString` | UCS-4 scalar values | — |
| BMPString | `1E` | `Asn1BmpString` | UCS-2, no surrogates | — |
| DATE, TIME-OF-DAY, DATE-TIME, DURATION | `1F 1F`–`1F 22` | `Asn1Date`, `Asn1TimeOfDay`, `Asn1DateTime`, `Asn1Duration` | X.680 §38 notation | canonical notation |
| OID-IRI, RELATIVE-OID-IRI | `1F 23`, `1F 24` | `Asn1OidIri`, `Asn1RelativeOidIri` | X.660 §7.5 labels | — |

Not represented: TeletexString, VideotexString, GraphicString,
GeneralString and ObjectDescriptor, which stay opaque as `Asn1Any`; the
constructed form of the string types, for which `Asn1Constructed` with the
`CONSTRUCTED_*` tag serves. UTCTime and GeneralizedTime accept the RFC 5280
forms only, so a UTC offset, omitted seconds or fractional seconds are
rejected even under BER.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
