"""06 - Issue an OCSP response.

Run: python examples/06_ocsp_responder.py
Writes: demo.ocsp.der
"""
from x509kit import CertificateBuilder, OCSPRequest, Ed25519Keys

# --- CA ---
ca_key = Ed25519Keys.generate()
ca = (CertificateBuilder(is_ca=True)
    .add_subject({"CN": "OCSP Demo CA"})
    .add_public_key(ca_key)
    .add_serial_random().add_validity(days=3650)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed().sign(ca_key))

# --- Leaf ---
leaf = (CertificateBuilder()
    .add_subject({"CN": "leaf.test"})
    .add_issuer(ca).add_public_key(Ed25519Keys.generate())
    .add_serial_random().add_validity(days=30)
    .add_san_dns("leaf.test")
    .sign(ca_key))

# --- Client makes an OCSP request ---
req = OCSPRequest.create(issuer=ca, cert=leaf)
print(f"OCSP request:")
print(f"  serial: 0x{req.serial:x}")
print(f"  nonce:  {req.nonce.hex()[:16]}...")

# --- CA responds ---
resp = ca.respond_ocsp(req, status="good", days=1)
print()
print(f"OCSP response:")
print(f"  status:        {resp.status}")
print(f"  is_fresh:      {resp.is_fresh()}")
print(f"  sig valid:     {resp.verify_signature(ca)}")
print(f"  nonce echo:    {resp.nonce == req.nonce}")
print(f"  leaf status:   {resp.get_status(leaf)}")

# --- Save for OpenSSL ---
open("demo.ocsp.der", "wb").write(resp.der)
print()
print("Saved: demo.ocsp.der")
print()
print("Verify with OpenSSL:")
print("  openssl ocsp -respin demo.ocsp.der -text -noverify")
