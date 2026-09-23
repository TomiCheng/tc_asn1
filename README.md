# tc_asn1

A Rust workspace for ASN.1. It holds the X.690 codec crate, `tc_asn1`, which
carries no protocol knowledge of its own, and the crates that build protocol
structures on it, starting with `tc_asn1_x500` for X.500 names. Each crate is
published separately and keeps its own README, changelog, and validation
commands.

[![CI](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_asn1`](tc_asn1) | [![crates.io](https://img.shields.io/crates/v/tc_asn1.svg)](https://crates.io/crates/tc_asn1) [![docs.rs](https://docs.rs/tc_asn1/badge.svg)](https://docs.rs/tc_asn1) | BER, CER and DER codecs for the ASN.1 universal types, and the traits through which a schema's structures become Rust types with the same encoding and decoding as the built-in ones. Any BER can also be decoded into a tree without a schema. `no_std` + `alloc`, no dependencies, no macros, no I/O. |
| [`tc_asn1_x500`](tc_asn1_x500) | [![crates.io](https://img.shields.io/crates/v/tc_asn1_x500.svg)](https://crates.io/crates/tc_asn1_x500) [![docs.rs](https://docs.rs/tc_asn1_x500/badge.svg)](https://docs.rs/tc_asn1_x500) | X.500 distinguished names as used for the subject and issuer of X.509 certificates: `Name`, its relative distinguished names and attribute type-and-value pairs, the X.520 `DirectoryString`, and constants for the attribute types found in names. Converts to and from RFC 4514 text and compares strictly or with the matching of RFC 5280 §7.1. `no_std` + `alloc`, depends only on `tc_asn1`. |

`tc_asn1` knows the X.690 rules and nothing of any protocol; the OIDs,
attribute types and matching rules of X.500 live in `tc_asn1_x500`, which
depends on nothing but `tc_asn1`.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
reaches the heap only through the sysroot `alloc` crate, and none has feature
flags. `tc_asn1` has no dependencies; `tc_asn1_x500` depends only on
`tc_asn1`.

## Workspace checks

```text
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, checks the `wasm32-unknown-unknown` and `aarch64-unknown-none`
targets and each crate's dependency tree on them, pins an MSRV job to Rust
1.85.0, and verifies the package archives.
See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
