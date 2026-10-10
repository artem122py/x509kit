"""10 - Chain verification: what passes and what fails.

Run: python examples/10_verify_chain.py
"""
from x509kit import CertificateBuilder, CACert, Ed25519Keys

# ---------- Root ----------
root_key = Ed25519Keys.generate()
root = (CertificateBuilder(is_ca=True)
    .add_subject({"CN": "Root CA"})
    .add_public_key(root_key)
    .add_serial_random().add_validity(days=3650)
    .add_basic_constraints(path_len=1)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed().sign(root_key))

# ---------- Intermediate ----------
inter_key = Ed25519Keys.generate()
inter_cert = (CertificateBuilder(is_ca=True)
    .add_subject({"CN": "Intermediate CA"})
    .add_issuer(root).add_public_key(inter_key)
    .add_serial_random().add_validity(days=1825)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .sign(root_key))
inter = CACert.from_cert(inter_cert, signing_key=inter_key)

# ---------- Leaf ----------
leaf_key = Ed25519Keys.generate()
leaf = (CertificateBuilder()
    .add_subject({"CN": "leaf.test"})
    .add_issuer(inter).add_public_key(leaf_key)
    .add_serial_random().add_validity(days=30)
    .add_san_dns("leaf.test")
    .sign(inter_key))

# ---------- Verification scenarios ----------
print("Chain verification scenarios:")
print()
print(f"  root.verify_chain([leaf, inter]):  {root.verify_chain([leaf, inter])}")
print(f"  root.verify_chain([inter, leaf]):  {root.verify_chain([inter, leaf])}  (wrong order)")
print(f"  root.verify_chain([leaf]):         {root.verify_chain([leaf])}  (missing intermediate)")
print(f"  inter.verify_chain([leaf]):        {inter.verify_chain([leaf])}")
print()
print(f"  leaf.verify_signature(inter):      {leaf.verify_signature(inter)}")
print(f"  inter.verify_signature(root):      {inter.verify_signature(root)}")
print(f"  leaf.is_self_signed():             {leaf.is_self_signed()}")
