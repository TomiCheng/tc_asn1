//! X.509 and PKIX structures on [`tc_asn1`]: certificates, CRLs, attribute
//! certificates, their extensions and the names and algorithm identifiers they
//! share, after Bouncy Castle's `Asn1.X509`.
//!
//! Each type is the ASN.1 structure of its RFC and nothing more: it decodes any
//! BER, encodes under BER, CER or DER through the `tc_asn1` traits, and checks
//! only what the structure itself requires. Signatures, certificate paths,
//! revocation and the meaning of algorithm parameters belong to the crates
//! built on these types.
//!
//! - [`cert`]: the certificate, its signed fields, the subject public key, and
//!   the validity period and its times.
//! - [`crl`]: the certificate revocation list, its entries and the CRL
//!   extensions.
//! - [`attr`]: the attribute certificate of RFC 5755 and its attribute types.
//! - [`ext`]: extensions and the certificate extension values.
//! - [`name`]: `GeneralName` and its alternatives.
//! - [`alg`]: `AlgorithmIdentifier` and `DigestInfo`.
//! - [`qualified`], [`sigi`], [`netscape`]: the qualified certificate, German
//!   signature law and Netscape extensions.
//!
//! A decoded certificate keeps its signed octets as received, so a signature
//! verifies over them whatever re-encoding would give:
//!
//! ```
//! use tc_asn1::{Decode, DecodingOptions};
//! use tc_asn1_x509::cert::Certificate;
//!
//! let der = include_bytes!("../tests/data/rfc8410.der");
//! let (_, certificate) = Certificate::decode(der, &DecodingOptions::default())?;
//! assert_eq!(certificate.subject().to_string(), "CN=IETF Test Demo");
//! assert_eq!(certificate.tbs_raw(), &der[4..230]);
//! # Ok::<(), tc_asn1::Asn1Error>(())
//! ```
//!
//! # Features
//!
//! - `chrono`, off by default, converts `cert::Time`, and through `tc_asn1`
//!   UTCTime and GeneralizedTime, to and from `chrono::DateTime<Utc>`.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

pub mod alg;
pub mod attr;
pub mod cert;
pub mod crl;
pub mod ext;
pub mod name;
pub mod netscape;
pub mod qualified;
pub mod sigi;
