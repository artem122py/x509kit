# Examples

Runnable examples for x509kit. Each is self-contained, no external
dependencies, prints what it does, and can be run directly:

    python examples/01_root_ca.py

## Index

| # | File | What it shows |
|---|------|---------------|
| 01 | `01_root_ca.py`              | Create a self-signed root CA |
| 02 | `02_issue_from_csr.py`       | Issue a leaf certificate from a CSR |
| 03 | `03_self_signed_server.py`   | HTTPS server with a self-signed cert |
| 04 | `04_mtls_server.py`          | Mutual TLS (server requires client cert) |
| 05 | `05_crl_revocation.py`       | Revoke a certificate, generate a CRL |
| 06 | `06_ocsp_responder.py`       | Issue an OCSP response |
| 07 | `07_pkcs12_export.py`        | Export key + cert to `.p12` |
| 08 | `08_parse_real_cert.py`      | Fetch and parse a real HTTPS certificate |
| 09 | `09_encrypted_key.py`        | Encrypted PKCS#8 private keys (RSA/Ed/EC) |
| 10 | `10_verify_chain.py`         | Chain verification: what passes, what fails |
| 11 | `11_name_canonicalization.py`| RFC 4518 DN canonicalization |
| 12 | `12_extensions.py`           | Certificate with every extension |
| 13 | `13_acme_server.py`          | Minimal ACME server (RFC 8555) |
| 14 | `14_acme_client.py`          | ACME client (run while 13 is running) |
| 15 | `15_ct_sct.py`               | Parse embedded SCT from a real cert |
| 16 | `16_revocation.py`           | Full revocation stack: CRL + OCSP over HTTP |

## Recommended order

Start with **01**, **02**, **10**. They cover 90% of what the library
does. Then **03**–**07** for specific protocols. **08** if you want to
parse real certificates. **09**–**12** for smaller features.

## Note

These examples write files (`*.pem`, `*.p12`, `*.der`) into the current
directory. Run them in a scratch folder if you don't want litter:

    mkdir /tmp/x509-demo && cd /tmp/x509-demo
    python /path/to/examples/01_root_ca.py
