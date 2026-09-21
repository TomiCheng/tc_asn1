# tc_asn1

A Rust workspace for ASN.1. It holds the X.690 codec crate, `tc_asn1`, which
carries no protocol knowledge of its own: the OIDs, extensions and profiles of
X.500, X.509 and their neighbours belong to crates built on top of it. Each
crate is published separately and keeps its own README, changelog, and
validation commands.

[![CI](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_asn1`](tc_asn1) | [![crates.io](https://img.shields.io/crates/v/tc_asn1.svg)](https://crates.io/crates/tc_asn1) [![docs.rs](https://docs.rs/tc_asn1/badge.svg)](https://docs.rs/tc_asn1) | BER, CER and DER codecs for the ASN.1 universal types, and the traits through which a schema's structures become Rust types with the same encoding and decoding as the built-in ones. Any BER can also be decoded into a tree without a schema. `no_std` + `alloc`, no dependencies, no macros, no I/O. |

## Requirements

Rust 1.85 or later, edition 2024. The crate builds without `std` and reaches
the heap only through the sysroot `alloc` crate; it has no feature flags and
no dependencies.

## Workspace checks

```text
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, checks the `wasm32-unknown-unknown` and `aarch64-unknown-none`
targets, pins an MSRV job to Rust 1.85.0, and verifies the package archive.
See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
