# x509kit

Pure-Python X.509 / PKCS#10 / CRL / OCSP / PKCS#12 toolkit.
**Zero dependencies — standard library only.**

## Example

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

## Install

    pip install x509kit

## Status

Alpha (0.3.0). Учебная библиотека. Не предназначена для production
без тщательной проверки в вашем контексте. См. SECURITY.md.

## Features

- ASN.1 DER (strict), PEM codec
- RSA (PKCS#1 v1.5 + PSS, blinding + CRT), Ed25519, ECDSA (P-256/384/521/secp256k1)
- X.509 v3: SAN, BasicConstraints, KeyUsage, EKU, Name Constraints, AKI/SKI, CRL DP, AIA
- PKCS#10 CSR, CRL (RFC 5280), OCSP (RFC 6960), PKCS#12 (RFC 7292)
- PKCS#8 EncryptedPrivateKeyInfo (PBES2 + PBKDF2 + AES-256-CBC/GCM)
- RFC 4518 DN canonicalization
- Cross-verified with `cryptography` and OpenSSL 3.6.5

## License

MIT
