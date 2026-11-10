# Test vectors

| File | Source | Notes |
| --- | --- | --- |
| `rfc8410.der` | RFC 8410 §10.2, the example X25519 certificate | Self-issued, signed with Ed25519, CN=IETF Test Demo, valid 2016-08-01 to 2040-12-31. Extensions: basicConstraints (critical, cA FALSE written out), keyUsage keyAgreement, subjectKeyIdentifier. BER rather than DER: two extensions write `critical FALSE` and basicConstraints writes its DEFAULT. Offsets: TBSCertificate `[4..230]`, Validity `[56..88]`, SubjectPublicKeyInfo `[115..159]`, Extensions `[161..230]`, signatureAlgorithm `[230..237]`, signatureValue `[237..304]`. |
| `spkac.der` | Bouncy Castle `SpkacTest`, `Spkac` | A browser SPKAC: an RSA key, an empty challenge, signed with MD5 and RSA. |
