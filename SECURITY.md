# Security Policy

## What x509kit is

x509kit is a pure-Python implementation of X.509, PKCS#10, PKCS#12, CRL,
and OCSP. It has zero third-party dependencies — only the Python standard
library.

It is a learning project. It is not a replacement for OpenSSL,
cryptography, or pyOpenSSL in any context where real security matters.
The fact that it is cross-verified against OpenSSL means the code is
functionally correct — not that it is safe for adversarial environments.

## What is covered

- ASN.1 DER parser and encoder (strict, minimal-length, depth-limited)
- RSA PKCS#1 v1.5 and RSASSA-PSS (with blinding and CRT)
- Ed25519 (RFC 8032)
- ECDSA (P-256, P-384, P-521, secp256k1) with RFC 6979 deterministic nonces
- AES-256-CBC and AES-256-GCM (pure Python)
- X.509 v3 certificate parsing, verification, and chain validation
- PKCS#10 CSR creation and verification
- CRL (RFC 5280) and OCSP (RFC 6960)
- PKCS#12 (RFC 7292) container format
- PKCS#8 EncryptedPrivateKeyInfo (PBES2 + PBKDF2 + AES-256-CBC/GCM)
- RFC 4518 DN canonicalization
- RFC 6125 hostname validation

## What is NOT covered

Be honest with yourself about these before using x509kit anywhere
non-trivial.

### Not constant-time

Python big-integer arithmetic is not constant-time. RSA uses blinding to
reduce timing leakage; ECDSA uses RFC 6979 to remove nonce reuse. But
pow(), scalar multiplication, and comparisons still leak timing
information. If an adversary can measure wall-clock time of your
private-key operations with nanosecond precision, they can potentially
recover the key.

Use OpenSSL for anything exposed to a remote attacker.

### Not fuzzed continuously

fuzz_x509.py exists and runs, but is not part of CI. Parsers handle
random bytes without crashing, but the corpus is not exhaustive.

### Not independently audited

The code has been cross-verified against cryptography and OpenSSL 3.6.5,
which means it produces compatible output. This is not the same as a
security audit. No third party has reviewed the code for logic errors,
side channels, or attack surface.

### No formal PKI validation

The library parses and verifies certificates. It does not implement full
RFC 5280 Section 6 path validation: no policy constraints, no
name-constraints intersection across the entire path in the strictest
sense, no AIA chasing, no CRL/OCSP fetching over the network.

### No platform security integration

No HSM support, no OS keystore, no key attestation, no TPM. Keys live in
Python memory as plain integers.

### No memory safety guarantees

Python does not have buffer overflows, but it does have MemoryError on
adversarial input, and secrets may be copied by the interpreter before
your wipe() runs.

### PKCS#12 MAC uses HMAC-SHA-256

This is what OpenSSL 3.x accepts. Older implementations (Windows 7, some
Java keystores) may require HMAC-SHA-1. If you need broad compatibility,
generate the .p12 with OpenSSL directly.

## If you find a vulnerability

Please do not open a public GitHub issue for security problems.

Report privately:

- Email: artemkamirn@mail.ru
- Or via GitHub Security Advisories:
  https://github.com/artem122py/x509kit/security/advisories/new

Include:

1. What is wrong (short description)
2. Minimal reproduction (code that demonstrates the problem)
3. Impact — what can an attacker do
4. Version (python -c "import x509kit; print(x509kit.__version__)")

## What I promise

- A reply within 7 days (usually faster)
- Coordinated disclosure after a fix is published
- Credit in the release notes (unless you prefer to stay anonymous)

## What I do NOT promise

- SLA on fixes
- Backports to older versions
- Responses on weekends or holidays
- Audit-level scrutiny of every commit

This is a project maintained by one person in their free time. There is
no team, no company, no funding, no bug bounty.

## Recommendations if you use x509kit

If you decide to use this library for anything beyond learning:

1. Cross-verify with OpenSSL yourself. Do not trust our verify() method.
   Use openssl verify, openssl pkcs12 -info, openssl crl -text. If they
   disagree with us, we are wrong.

2. Bound your inputs. When accepting certificates, CSRs, or PKCS#12
   files from outside, enforce size limits (the library enforces 10 MB
   on PEM input by default; add your own on top).

3. Do not use for long-lived private keys under load. RSA at 10,000
   signatures/hour in pure Python — use OpenSSL instead.

4. Watch for updates. We track OpenSSH/OpenSSL security advisories, but
   we are not always fast.

## Supported versions

Only the latest release is supported. 0.3.0 is current. Once 1.0.0 is
released, the API freezes and semantic versioning applies strictly.

## License

MIT. See LICENSE.
