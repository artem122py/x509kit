"""07 - Export key + cert to PKCS#12 (.p12).

Run: python examples/07_pkcs12_export.py
Writes: alice.p12
"""
from x509kit import CertificateBuilder, Ed25519Keys, PKCS12, PKCS12Builder

# --- CA ---
ca_key = Ed25519Keys.generate()
ca = (CertificateBuilder(is_ca=True)
    .add_subject({"CN": "P12 Demo CA"})
    .add_public_key(ca_key)
    .add_serial_random().add_validity(days=3650)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed().sign(ca_key))

# --- Leaf ---
leaf_key = Ed25519Keys.generate()
leaf = (CertificateBuilder()
    .add_subject({"CN": "alice"})
    .add_issuer(ca).add_public_key(leaf_key)
    .add_serial_random().add_validity(days=90)
    .add_extended_key_usage("clientAuth")
    .sign(ca_key))

# --- Export to .p12 ---
path = (PKCS12Builder()
    .set_key(leaf_key)
    .set_cert(leaf)
    .add_chain(ca)
    .set_password("hunter2")
    .set_name("alice")
    .save("alice.p12"))

import os
print(f"Saved: alice.p12 ({os.path.getsize(path)} bytes)")

# --- Read it back ---
p12 = PKCS12.from_file("alice.p12", password="hunter2")
print()
print(f"Reloaded:")
print(f"  key matches:  {p12.key.pub == leaf_key.pub}")
print(f"  cert matches: {p12.cert.der == leaf.der}")
print(f"  MAC valid:    {p12.verify_mac()}")
print(f"  chain ok:     {p12.verify_chain(trust_anchor=ca)}")
print()
print("Verify with OpenSSL:")
print("  openssl pkcs12 -in alice.p12 -passin pass:hunter2 -info -noout")
