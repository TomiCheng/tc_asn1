# tc_asn1

BER, CER and DER codecs for the ASN.1 universal types, and a toolkit for
writing ASN.1 schemas as Rust types. `no_std` + `alloc`, no macros, no
dependencies unless an optional feature is on.

## Usage

```rust
use tc_asn1::{Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions};

let der = Asn1Integer::from(300).encode_to_vec(&EncodingOptions::DER)?;
let (_, back) = Asn1Integer::decode_der(&der, &DecodingOptions::default())?;
assert_eq!(back, Asn1Integer::from(300));
```

## Features

- `zeroize`: implements `tc_zeroize::Zeroize` for every type that owns
  data, so a value can be erased; nothing wipes itself on drop.
- `chrono`: converts `Asn1UtcTime` and `Asn1GeneralizedTime` to and from
  `chrono::DateTime<Utc>`.
- `std`: the `io` module, reading and writing values over `std::io`.

## More

The full guide, with a schema written as Rust types, is the
[README on GitHub](https://github.com/TomiCheng/tc_asn1/blob/main/tc_asn1/README.md);
the API is on [docs.rs](https://docs.rs/tc_asn1).

Licensed under MIT or Apache-2.0, at your option.
