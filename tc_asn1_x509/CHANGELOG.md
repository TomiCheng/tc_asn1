# Changelog

All notable changes to `tc_asn1_x509` are documented in this file.

## 0.1.0 - 2026-11-10

Initial release.

### Added

- `cert`: `Certificate`, which keeps its `tbsCertificate` octets as received
  for the signature, `TbsCertificate`, `Version`, `SubjectPublicKeyInfo`,
  `Validity` and `Time`, which picks UTCTime through 2049 and GeneralizedTime
  from 2050 as RFC 5280 §4.1.2.5 requires; and `CertificatePair`.
- `crl`: `CertificateList`, which keeps its signed octets likewise,
  `TbsCertList`, `RevokedCertificate`, and the CRL extension values: CRL
  number, reason code, distribution points, issuing distribution point and
  reason flags.
- `attr`: the RFC 5755 attribute certificate, `AttributeCertificate` and
  `AttributeCertificateInfo`, with its `Holder`, `AttCertIssuer`, `V2Form`,
  `IssuerSerial`, `ObjectDigestInfo`, validity period, and the role, IETF
  attribute syntax and targeting attribute types.
- `ext`: `Extension` and `Extensions`, which refuse a repeated OID; the
  `ExtensionId` and `KeyPurposeId` constants; and the value of every RFC 5280
  certificate extension, with typed getters on `Extensions`, as well as the
  alternative signature and delta certificate extensions.
- `name`: `GeneralName` and its alternatives, with an `iPAddress` from IPv4
  or IPv6 text, `GeneralNames`, `OtherName` and `EdiPartyName`.
- `alg`: `AlgorithmIdentifier`, with absent, NULL or other parameters, and
  `DigestInfo`.
- `qualified`, `sigi` and `netscape`: qualified certificate statements, the
  German signature law attributes, and the Netscape certificate type,
  revocation URL and signed public key and challenge.
- The optional `chrono` feature, converting `Time` to and from
  `chrono::DateTime<Utc>` and turning on `tc_asn1`'s.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std` + `alloc`. Depends on `tc_asn1` 0.1.3 and `tc_asn1_x500` 0.1, and
  with `chrono` on `chrono` without its default features.
- `Time` refuses a GeneralizedTime with fractional seconds, which `tc_asn1`
  0.1.3 decodes and RFC 5280 forbids, and `From<Asn1GeneralizedTime>` drops
  them.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
