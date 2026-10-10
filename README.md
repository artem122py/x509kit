# x509kit

![tests](https://github.com/artem122py/x509kit/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9+-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Pure-Python X.509 / PKCS#10 / CRL / OCSP / PKCS#12 toolkit.
**Standard library only.**

No third-party packages. No C extensions. No vendored code.

## Zero third-party dependencies

`x509kit` uses only the Python standard library. No `cryptography`,
no `pyOpenSSL`, no `asn1crypto`, no `pycryptodome`, no C extensions.

    $ pip show x509kit | grep "^Requires"
    Requires:

    $ grep -rhE "^\s*(import|from) " src/x509kit/ \
        | awk '{print $2}' | cut -d. -f1 | sort -u
    base64
    datetime
    hashlib
    hmac
    math
    os
    re
    secrets
    socket
    unicodedata
    warnings

All of these are in the Python standard library. Nothing else.

### Why stdlib only

- **No transitive CVEs.** Fewer packages — fewer places for something
  to go wrong.
- **Embedded / restricted environments** where you cannot install
  third-party packages.
- **Air-gapped systems** — drop a single package and run.
- **Readable.** The whole implementation is in one place.
- **Auditable.** The attack surface is exactly one package.

### What is implemented from scratch

Every protocol and primitive is our own Python code:

- ASN.1 DER parser and encoder (strict, minimal-length)
- RSA PKCS#1 v1.5 and RSASSA-PSS (with blinding and CRT)
- Ed25519 (RFC 8032)
- ECDSA (RFC 6979 deterministic nonces)
- AES-256 block cipher (FIPS 197) and GCM mode (NIST SP 800-38D)
- PBKDF2 and PKCS#12 KDF
- Every X.509 v3, PKCS#10, PKCS#12, CRL, OCSP structure
- RFC 4518 DN canonicalization

Hashing (`hashlib`), MAC (`hmac`), and randomness (`secrets`) come from
the standard library — writing a custom SHA-256 in Python would be
slower and less tested than what the interpreter already ships.

`cryptography` and the `openssl` binary appear only in tests, as
independent verifiers of our output.

## Verify in 30 seconds

Not asking you to trust me — asking you to run this:

    git clone https://github.com/artem122py/x509kit
    cd x509kit
    pip install -e .
    python flask/test_live_ca.py

In one go, this script:

- Generates Root CA + Intermediate in memory (nothing on disk)
- Issues a server leaf certificate for a Flask server
- Starts Flask on HTTPS with the leaf + intermediate chain
- Calls the real OpenSSL CLI to generate a key and a CSR
- POSTs the CSR to the server, gets a leaf back
- Runs `openssl verify -CAfile root -untrusted inter leaf.pem`
  → expected output: `leaf.pem: OK`
- Revokes the leaf via `/revoke`
- Runs `openssl verify -CRLfile crl.pem -crl_check`
  → expected output: `error 23 at 0 depth lookup: certificate revoked`

The verification step is done by OpenSSL 3.x, called via subprocess.
It is not our own verify() method. If our DER encoding were wrong,
OpenSSL would reject it — and it doesn't.

## Cross-verify matrix

The library is not self-tested. It is tested against external
implementations, in both directions:

| Component | Independent verifier | Result |
|-----------|---------------------|--------|
| RSA (PKCS#1 v1.5, PSS) | cryptography + openssl pkeyutl | both ways |
| Ed25519 | RFC 8032 test vectors (byte-exact), cryptography | both ways |
| ECDSA (P-256/384/521/secp256k1) | RFC 6979 test vectors (byte-exact), cryptography | both ways |
| AES-256-CBC | FIPS 197 test vector | byte-exact |
| AES-256-GCM | NIST SP 800-38D test vectors | byte-exact |
| X.509 v3 certificates | openssl x509 -text, openssl verify | OK |
| Chains (root → intermediate → leaf) | Python ssl TLS handshake | OK |
| CRL | openssl crl -text, openssl verify -crl_check | error 23 |
| PKCS#12 (.p12) | openssl pkcs12 -info -nodes | 3 blocks extracted |
| PKCS#8 EncryptedPrivateKeyInfo | openssl pkey | OK |
| mTLS | openssl s_client -cert -key | handshake OK |

Run it yourself:

    python test_all.py

## What this is

A learning project that turned into a working implementation. It exists
to answer the question: what actually happens inside an X.509
certificate — by writing it from scratch, on the standard library, and
checking the result against OpenSSL until they agree.

## What this is not

Not a replacement for OpenSSL or cryptography in production. See
[SECURITY.md](SECURITY.md) for the full list of what is covered and
what is not. Short version: no constant-time guarantees, no formal
audit, no production hardening.

If you need production-grade crypto: use cryptography.
If you want to understand X.509 by reading Python that OpenSSL agrees
with: this is for you.

## Install

    pip install x509kit

## Quick example

    from x509kit import CertificateBuilder, Ed25519Keys, RSAKeys

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "XX", "O": "MyOrg", "CN": "MyOrg Root CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))

    leaf_key = RSAKeys.generate(2048)
    leaf = (CertificateBuilder()
        .add_subject({"C": "XX", "O": "MyOrg", "CN": "example.com"})
        .add_issuer(ca).add_public_key(leaf_key)
        .add_serial_random().add_validity(days=365)
        .add_san_dns("example.com", "www.example.com")
        .add_extended_key_usage("serverAuth")
        .sign(ca_key))

    assert ca.verify_chain([leaf])

## Features

- ASN.1 DER parser and encoder (strict, minimal-length)
- PEM codec
- RSA PKCS#1 v1.5 + RSASSA-PSS (blinding + CRT)
- Ed25519 (RFC 8032), ECDSA (P-256/384/521/secp256k1, RFC 6979)
- X.509 v3: SAN, BasicConstraints, KeyUsage, Extended Key Usage,
  Name Constraints (with intersection), AKI/SKI, CRL Distribution Points, AIA
- PKCS#10 CSR, CRL (RFC 5280), OCSP (RFC 6960), PKCS#12 (RFC 7292)
- PKCS#8 EncryptedPrivateKeyInfo (PBES2 + PBKDF2 + AES-256-CBC/GCM)
- RFC 4518 DN canonicalization
- Fluent builders: CertificateBuilder, CSRBuilder, CRLBuilder,
  OCSPResponseBuilder, PKCS12Builder
- X509Error with fix hints, X509Warning for non-fatal issues

## Status

Alpha (0.3.0). Educational. Not for production. See
[SECURITY.md](SECURITY.md).

## License

MIT
