"""05 - Revoke a certificate and generate a CRL.

Run: python examples/05_crl_revocation.py
Writes: demo.crl.pem, demo_ca.pem
"""
from x509kit import CertificateBuilder, Ed25519Keys

# --- CA ---
ca_key = Ed25519Keys.generate()
ca = (CertificateBuilder(is_ca=True)
    .add_subject({"CN": "CRL Demo CA"})
    .add_public_key(ca_key)
    .add_serial_random().add_validity(days=3650)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed().sign(ca_key))

# --- Issue 3 leaves ---
leaves = []
for cn in ("a.test", "b.test", "c.test"):
    leaf = (CertificateBuilder()
        .add_subject({"CN": cn})
        .add_issuer(ca).add_public_key(Ed25519Keys.generate())
        .add_serial_random().add_validity(days=30)
        .add_san_dns(cn)
        .sign(ca_key))
    leaves.append(leaf)

# --- Revoke the middle one ---
ca.revoke(leaves[1], reason="keyCompromise")

# --- Build CRL ---
crl = ca.to_crl(days=7)
open("demo.crl.pem", "w").write(crl.to_pem())
open("demo_ca.pem", "w").write(ca.to_pem())

print(f"CRL issued: {len(crl.revoked)} revoked entries")
for serial, when, code in crl.revoked:
    print(f"  serial=0x{serial:x}  reason={crl.revoke_reason(serial)}")
print()
print(f"a.test revoked: {crl.is_revoked(leaves[0])}")
print(f"b.test revoked: {crl.is_revoked(leaves[1])}")
print()
print(f"verify_cert(a, crl): {ca.verify_cert(leaves[0], crl=crl)}")
print(f"verify_cert(b, crl): {ca.verify_cert(leaves[1], crl=crl)}")
print()
print("Saved: demo.crl.pem, demo_ca.pem")
print()
print("Verify with OpenSSL:")
print("  openssl crl -in demo.crl.pem -CAfile demo_ca.pem -noout")
