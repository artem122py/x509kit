# Changelog

All notable changes to this project.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added (0.7.0)

- CMS (RFC 5652) SignedData (`x509kit.cms`) — parsing, signing, verification
  - `cms_sign(content, key, cert, chain=None, *, detached=False,
    digest='sha256', sig_scheme='pkcs1v15')` — RSA / Ed25519 / ECDSA
  - `CMSSignedData.verify(trust_anchor=None, detached_data=None,
    allow_weak_hash=False)` — signature + messageDigest + optional chain
  - `CMSSignedData`, `CMSSignerInfo`, `cms_load` — parsing
  - ContentInfo, attached / detached content
  - SignerIdentifier: IssuerAndSerialNumber и SubjectKeyIdentifier
  - Signed attributes: contentType, messageDigest, signingTime
  - X.509 certificates в `certificates [0]`, CRL в `crls [1]`
  - Round-trip: `to_der()` / `to_pem()` / `save()`
  - Проверено с OpenSSL CLI (`openssl cms -verify` → Verification successful)
- `AlgorithmIdentifier.digest_name` — читаемое имя чистого хэша
  (`sha256` вместо `2.16.840.1.101.3.4.2.1`)
- `AlgorithmIdentifier.name` теперь распознаёт чистые хэш-OID
  (используется в CMS `digestAlgorithms`)
- `examples/17_cms_sign.py` — sign / verify / detached / OpenSSL interop
- `test_all.py`: секции 23 (CMS parsing) и 24 (CMS sign/verify), 366/366

### Planned
- CLI: `x509kit info / verify / csr / acme-server`
- Full RFC 5280 §6 path validation
- Full type annotations on public API
- `X25519Keys` for ECDH
- Coverage reporting in CI

## [0.6.0] - 2026-10-10

### Added
- Network fetchers on `Cert`:
  - `Cert.fetch_crl(ca=None, timeout=10)` — download CRL via CRL DP
  - `Cert.fetch_ocsp(issuer, timeout=10)` — OCSP request to AIA responder
  - `Cert.fetch_issuer(timeout=10, max_depth=5, trust_anchor=None)` —
    AIA chasing up the chain
- `Cert.from_url(url, port=None, timeout=5, verify=False,
  client_cert=None, client_key=None)` — fetch peer certificate from
  an HTTPS server; supports mTLS via `client_cert` / `client_key`
  (path, PEM string, or x509kit object)
- `CertBundle.sort_chain()` — order certificates leaf → root
- New module `x509kit.revocation`:
  - `make_revocation_server(ca, host, port, crl_days=7,
    crl_cache_seconds=60)` — HTTP server serving CRL and OCSP
  - `make_revocation_handler(ca, ...)` — embeddable handler class
  - `RevocationHTTPServer`, `run_in_thread(srv)`
  - Endpoints: `GET /crl.pem`, `GET /crl.der`,
    `POST /ocsp`, `GET /` (HTML status)
- `acme.ACMEServer.load(..., base_url=...)` — explicit base URL when
  creating a fresh server from a missing state file

### Changed
- `_materialize_cert_pem` / `_materialize_key_pem` helpers are the single
  place for cert/key materialization in `Cert.from_url`
- Private key temp files are created with mode `0600` (mTLS path)

### Fixed
- `CertBundle.sort_chain()` picked self-signed CA as leaf instead of the
  actual end-entity (now prefers a non-self-signed cert whose issuer is
  in the bundle)
- `acme.ACMEServer.load()` no longer relies on a stray `dir()` check
  when the state file does not exist

### Tests
- `test_all.py`: 297 checks (up from 279 in 0.5.0)
- New section `22. Network revocation (CRL/OCSP HTTP)`:
  - fetch_crl / fetch_ocsp round-trips against a live
    `RevocationHTTPServer` on `127.0.0.1:0`
  - revoked status reflection via `ca.revoke(...)`
  - `CertBundle.sort_chain()` order verification
  - signature of `Cert.from_url` for mTLS parameters

## [0.5.0] - 2026-09-XX

### Added
- Certificate Transparency (RFC 6962 §3.3): SCT parsing
  - `Cert.sct_list`, `Cert.has_sct`, `OID_SCT`
- ACME persistence: `ACMEServer.save / load / to_dict / from_dict`

## [0.4.0] - 2026-09-XX

### Added
- ACME (RFC 8555): `ACMEServer` with `directory`, `new-account`,
  `new-order`, `authz`, http-01 challenge, `finalize`, certificate
  download
- JWS verification (RFC 7515): EdDSA, ES256/384/512, RS256
- JWK (RFC 7517) / thumbprint (RFC 7638)
- Verified end-to-end with certbot

## [0.3.2] - 2026-08-XX

### Added
- `Name.from_string("CN=x, O=y, C=XX")` (RFC 4514)
- `Cert.from_url("https://...")`
- `Cert.info()` — `openssl x509 -text`-style output
- `CertBundle.to_pkcs12(key, password=..., name=...)`
- `key.to_pkcs12(cert, chain=[...], password=..., name=...)` on all
  three key types (RSAKeys, Ed25519Keys, ECDSAKeys)

## [0.3.1] - 2026-07-XX

### Changed
- CI: Trusted Publishing to PyPI on `v*` tags
- Publish workflow only triggers on tags, main runs tests only

## [0.3.0] - 2026-07-XX

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
