"""02 - Issue a leaf certificate from a CSR.

Run: python examples/02_issue_from_csr.py
"""
from x509kit import CertificateBuilder, CSRBuilder, Ed25519Keys

# ---------- CA (offline in real life) ----------
ca_key = Ed25519Keys.generate()
ca = (CertificateBuilder(is_ca=True)
    .add_subject({"C": "XX", "O": "MyOrg", "CN": "MyOrg Root CA"})
    .add_public_key(ca_key)
    .add_serial_random().add_validity(days=3650)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed().sign(ca_key))

# ---------- Client side: key + CSR ----------
# The private key NEVER leaves the client.
leaf_key = Ed25519Keys.generate()

csr = (CSRBuilder()
    .add_subject({"C": "XX", "O": "MyOrg", "CN": "example.com"})
    .add_public_key(leaf_key)
    .add_san_dns("example.com", "www.example.com")
    .sign(leaf_key))          # signed with the leaf key = proof of possession

print(f"CSR self-signature valid: {csr.verify_signature()}")
print(f"CSR subject: {csr.subject}")
print(f"CSR SAN:     {csr.dns_names}")
print()

# ---------- CA side: verify CSR, issue leaf ----------
leaf = (CertificateBuilder.from_csr(csr)         # copies subject + SPKI + SAN
    .add_issuer(ca)
    .add_serial_random()
    .add_validity(days=90)
    .sign(ca_key))                                # signed by CA key

print(f"Leaf subject: {leaf.subject}")
print(f"Leaf issuer:  {leaf.issuer}")
print(f"Leaf SAN:     {leaf.dns_names}")
print(f"Chain valid:  {ca.verify_chain([leaf])}")
