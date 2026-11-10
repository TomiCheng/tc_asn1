# tc_asn1_x509

[![crates.io](https://img.shields.io/crates/v/tc_asn1_x509.svg)](https://crates.io/crates/tc_asn1_x509)
[![docs.rs](https://docs.rs/tc_asn1_x509/badge.svg)](https://docs.rs/tc_asn1_x509)
[![CI](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asn1/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

X.509 and PKIX structures, after Bouncy Castle's `Asn1.X509`: certificates,
CRLs, attribute certificates, their extensions, and the names and algorithm
identifiers they share.

The crate is `no_std` + `alloc` and built on `tc_asn1` and `tc_asn1_x500`.
Every type decodes from BER, CER or DER, encodes under any of the three, and
checks only what its structure requires. A decoded certificate, CRL or
attribute certificate keeps its signed octets as received, so a signature
verifies over them whatever re-encoding would give.

## Usage

```rust
use tc_asn1::{Decode, DecodingOptions};
use tc_asn1_x509::cert::Certificate;

let (_, certificate) = Certificate::decode(der, &DecodingOptions::default())?;
println!("{} issued by {}", certificate.subject(), certificate.issuer());
let signed = certificate.tbs_raw();   // the octets the signature covers
# Ok::<(), tc_asn1::Asn1Error>(())
```

## Types

- **`cert`**: `Certificate`, `TbsCertificate`, `SubjectPublicKeyInfo`,
  `Validity`, `Time` and `Version` (RFC 5280 §4.1), and `CertificatePair`.
- **`crl`**: `CertificateList`, `TbsCertList`, `RevokedCertificate`, and the
  CRL extension values (RFC 5280 §5).
- **`attr`**: `AttributeCertificate`, its `Holder` and `AttCertIssuer`, and the
  attribute types of RFC 5755.
- **`ext`**: `Extension` and `Extensions`, `ExtensionId` and `KeyPurposeId`
  constants, and the value of every RFC 5280 certificate extension.
- **`name`**: `GeneralName`, `GeneralNames`, `OtherName` and `EdiPartyName`.
- **`alg`**: `AlgorithmIdentifier` and `DigestInfo`.
- **`qualified`**, **`sigi`**, **`netscape`**: qualified certificate
  statements (RFC 3739), German signature law, and Netscape extensions.

## Features

- **`chrono`** (off by default): converts `Time`, and through `tc_asn1`
  UTCTime and GeneralizedTime, to and from `chrono::DateTime<Utc>`.

## Limitations

- Structures only: no signature verification, path building, revocation
  checking or name constraints matching.
- A `Time` is to the second, as RFC 5280 requires: a GeneralizedTime with
  fractional seconds is refused when decoding and truncated when converted.
- Algorithm parameters are kept as decoded; their meaning belongs to the
  algorithm.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
