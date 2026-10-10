# Changelog

All notable changes to this project.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned
- Full type annotations on public API
- `Name.from_string("CN=x, O=y, C=XX")` parser
- `Cert.from_url("https://...")` convenience
- `X25519Keys` for ECDH
- ACME (RFC 8555) compatibility
- Coverage reporting in CI

## [0.3.0] - 2026-10-10

First public release.

### Added

**Cryptography:**
- RSA PKCS#1 v1.5 + RSASSA-PSS with blinding and CRT
- Ed25519 (RFC 8032)
- ECDSA (P-256, P-384, P-521, secp256k1) with RFC 6979
- AES-256 (FIPS 197) and AES-256-GCM (NIST SP 800-38D), pure Python
- PKCS#8 EncryptedPrivateKeyInfo (PBES2 + PBKDF2 + AES-256-CBC/GCM)

**X.509 v3:**
- Full DER parser and encoder (strict, minimal-length, depth-limited)
- PEM codec
- All standard extensions: SAN, BasicConstraints, KeyUsage,
  Extended Key Usage, Name Constraints (with intersection), AKI/SKI,
  CRL Distribution Points, AIA
- RFC 4518 DN canonicalization
- RFC 6125 hostname validation

**Protocols:**
- PKCS#10 CertificationRequest (create, parse, verify)
- CRL (RFC 5280): builder, parser, verification
- OCSP (RFC 6960): request, response, nonce
- PKCS#12 (RFC 7292): export, import, MAC verification

**API:**
- Fluent builders: `CertificateBuilder`, `CSRBuilder`, `CRLBuilder`,
  `OCSPResponseBuilder`, `PKCS12Builder`
- `X509Error` with fix hints, `X509Warning` for non-fatal issues
- Crypto dispatcher: single point for all key-type logic
- SAN convenience accessors on `Cert` and `CSR`: `dns_names`,
  `ip_addresses`, `emails`, `uris`
- `Cert.crl_distribution_points` reader
- `__eq__` / `__hash__` for `Name`, `Cert`, `RSAKeys`, `Ed25519Keys`,
  `ECDSAKeys`, `CertBundle`, `CRL`, `CSR`

**Safety:**
- DoS limits: `_MAX_DER_SIZE = 512 KB`, `_MAX_PEM_SIZE = 1 MB`,
  `_MAX_DEPTH = 32`
- `_safe_parse` decorator wraps all parser constructors; malformed
  input raises `X509ParseError` instead of leaking `ValueError`,
  `TypeError`, `IndexError`
- `check_no_hidden.py` — AST-based proof of zero third-party imports

**Tests and tools:**
- `test_all.py` — ~210 test cases
- `fuzz_x509.py` — random input fuzzing
- `stress_x509kit.py` — heavy stress test (parser fuzz, mutation,
  crypto ops, GC churn)
- `compat_test.py` — cross-verify with `cryptography` (12/12)
- `test_live_ca.py` — full PKI cycle through OpenSSL CLI
- `examples/` — 12 runnable example scripts
- `check_docs.py`, `check_dispatcher.py`

**CI:**
- GitHub Actions: tests on Python 3.9–3.13
- Doc and dispatcher checks

### Cross-verified against
- `cryptography` (RSA, Ed25519, ECDSA, X.509 parsing)
- OpenSSL 3.6.5 CLI (`verify`, `s_client`, `crl_check`, `pkey`,
  `pkcs12`)
- RFC 8032 Ed25519 test vectors (byte-exact)
- RFC 6979 ECDSA test vectors (byte-exact)
- FIPS 197 AES-256 test vector
- NIST SP 800-38D GCM test vectors

### Known limitations
- Not constant-time (see `SECURITY.md`)
- No formal audit
- No production hardening
- Not for adversarial environments

## [0.2.0] - development

### Added
- Ed25519 keys
- ECDSA keys (P-256, P-384, P-521, secp256k1) with RFC 6979
- RSA blinding and CRT
- AES-256 (FIPS 197) and AES-256-GCM (NIST SP 800-38D)
- PKCS#8 EncryptedPrivateKeyInfo
- X.509 v3: SAN, BasicConstraints, KeyUsage, EKU, AKI/SKI
- CRL (RFC 5280)
- Fuzzing tests
- Live CA test with OpenSSL CLI
- mTLS test with PKCS#12

### Changed
- RSA minimum key size raised to 2048 bits
- `weak_hash` and `weak` flags added

## [0.1.0] - initial

### Added
- ASN.1 DER parser and encoder
- PEM codec
- X.509 v3 parsing and verification
- PKCS#10 CSR
- Basic chain validation with path_len
- RFC 6125 hostname validation
- Mini HTTP CA server
