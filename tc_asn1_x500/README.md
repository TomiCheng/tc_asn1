# tc_asn1_x500

[![crates.io](https://img.shields.io/crates/v/tc_asn1_x500.svg)](https://crates.io/crates/tc_asn1_x500)
[![docs.rs](https://docs.rs/tc_asn1_x500/badge.svg)](https://docs.rs/tc_asn1_x500)
[![CI](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

X.500 distinguished names, as used for the subject and issuer of X.509
certificates: `Name` and its parts, the X.520 `DirectoryString`, and the
attribute types that appear in names.

The crate is `no_std` + `alloc` and built on `tc_asn1`. Every type decodes
from BER, CER or DER, encodes under any of the three, and keeps what it
decoded. Names also convert to and from their RFC 4514 text form, and
compare either strictly or with the relaxed matching of RFC 5280 §7.1.

## Usage

```rust
use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_x500::Name;

let name: Name = "CN=Alice,O=Example,C=TW".parse()?;
let der = name.encode_to_vec(&EncodingOptions::DER)?;
let (_, decoded) = Name::decode(&der, &DecodingOptions::default())?;
assert_eq!(decoded.to_string(), "CN=Alice,O=Example,C=TW");
assert!(decoded.equivalent(&"cn=alice, o=EXAMPLE, c=TW".parse()?));
# Ok::<(), tc_asn1::Asn1Error>(())
```

## Types

- **`Name`**: a distinguished name, stored root first. Prints and parses
  as RFC 4514 text, most specific first. `==` compares the DER;
  `equivalent` ignores case, string type and extra whitespace.
- **`RelativeDistinguishedName`**: one level of a name, usually a single
  attribute (`CN=Alice`), sometimes several (`CN=Alice+UID=alice`).
- **`AttributeTypeAndValue`**: one `type=value` pair. The value is a
  `DirectoryString`, an IA5String, or any other ASN.1 value kept as decoded.
- **`DirectoryString`**: the string type most attributes use.
- **`Attribute`**: a type with a set of values, as in certificate request
  attributes.
- **`AttributeType`**: constants for the attribute types found in names,
  looked up by OID or by short name.

## Limitations

- No name constraints matching.
- `equivalent` applies RFC 4518 string preparation except the steps that
  need Unicode tables, NFKC normalization and full case folding: a
  precomposed and a decomposed accent, or `ß` and `ss`, still differ.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
