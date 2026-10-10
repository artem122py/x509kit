"""01 - Create a self-signed root CA.

Run: python examples/01_root_ca.py
Writes: root_ca.pem, root_ca_key.pem
"""
from x509kit import CertificateBuilder, Ed25519Keys

# Root CA key (Ed25519 - fast generation, small signatures)
key = Ed25519Keys.generate()

# Build the root certificate
ca = (CertificateBuilder(is_ca=True)
    .add_subject({"C": "XX", "O": "MyOrg", "CN": "MyOrg Root CA"})
    .add_public_key(key)
    .add_serial_random()
    .add_validity(days=3650)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed()
    .sign(key))

# Save to disk
open("root_ca.pem", "w").write(ca.to_pem())
open("root_ca_key.pem", "w").write(key.to_private_pem())

print(ca)
print()
print(f"Files written: root_ca.pem, root_ca_key.pem")
print(f"Self-signed: {ca.is_self_signed()}")
