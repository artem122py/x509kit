# -*- coding: utf-8 -*-
"""
compat_test.py - prove x509kit ↔ cryptography compatibility (both ways).

Requires: pip install cryptography

Exit code 0 = all checks passed, 1 = something failed.
"""
import sys
import datetime

from x509kit import RSAKeys, Ed25519Keys, ECDSAKeys, Cert, CertificateBuilder

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗\033[0m {name}")


try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        rsa as crsa, ed25519 as ced, ec as cec, padding as cpad)
    from cryptography import x509 as cx509
except ImportError:
    print("[!] cryptography not installed - run: pip install cryptography")
    sys.exit(2)

print("=" * 60)
print("  x509kit ↔ cryptography")
print("=" * 60)

# ---------- 1. RSA ----------
print()
print("1. RSA PKCS#1 v1.5")
k = RSAKeys.generate(2048)
msg = b"cross-verify"
sig = k.sign_pkcs1v15(msg, "sha256")

their_pub = serialization.load_pem_public_key(k.to_public_pem().encode())
try:
    their_pub.verify(sig, msg, cpad.PKCS1v15(), hashes.SHA256())
    check("наш RSA sign → их verify", True)
except Exception as e:
    check(f"наш RSA sign → их verify: {e}", False)

their_priv = serialization.load_pem_private_key(
    k.to_private_pem().encode(), password=None)
their_sig = their_priv.sign(msg, cpad.PKCS1v15(), hashes.SHA256())
check("их RSA sign → наш verify",
      k.verify_pkcs1v15(msg, their_sig, "sha256"))

# ---------- 2. Ed25519 ----------
print()
print("2. Ed25519 (RFC 8032)")
seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                     "4449c5697b326919703bac031cae7f60")
our_ed = Ed25519Keys(seed=seed)
their_ed = ced.Ed25519PrivateKey.from_private_bytes(seed)
their_raw = their_ed.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)

check("seed → тот же pubkey", our_ed.pub == their_raw)

try:
    their_ed.public_key().verify(our_ed.sign(b"hi"), b"hi")
    check("наш Ed sign → их verify", True)
except Exception as e:
    check(f"наш Ed sign → их verify: {e}", False)

check("их Ed sign → наш verify",
      our_ed.verify(b"hi", their_ed.sign(b"hi")))

# ---------- 3. ECDSA ----------
print()
print("3. ECDSA P-256")
ec = ECDSAKeys.generate("P-256")
their_ec_pub = serialization.load_der_public_key(ec.to_public_der())
try:
    their_ec_pub.verify(ec.sign(b"msg", "sha256"), b"msg",
                        cec.ECDSA(hashes.SHA256()))
    check("наш EC sign → их verify", True)
except Exception as e:
    check(f"наш EC sign → их verify: {e}", False)

their_ec = cec.generate_private_key(cec.SECP256R1())
their_ec_der = their_ec.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo)
our_ec_pub = ECDSAKeys.from_public_der(their_ec_der)
check("их EC sign → наш verify",
      our_ec_pub.verify(b"msg",
                        their_ec.sign(b"msg", cec.ECDSA(hashes.SHA256())),
                        "sha256"))

# ---------- 4. X.509 ----------
print()
print("4. X.509 сертификат")
now = datetime.datetime.now(datetime.timezone.utc)
ca_k = Ed25519Keys.generate()
ca = (CertificateBuilder(is_ca=True)
    .add_subject({"C": "XX", "O": "Compat", "CN": "Compat Root"})
    .add_public_key(ca_k)
    .add_serial_random()
    .add_validity(days=365)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed()
    .sign(ca_k))

their_ca = cx509.load_pem_x509_certificate(ca.to_pem().encode())
check("наш PEM → их x509 парсер",
      their_ca.subject.rfc4514_string() == "CN=Compat Root,O=Compat,C=XX")
check("серийник совпадает", their_ca.serial_number == ca.serial)

their_priv_ca = ced.Ed25519PrivateKey.from_private_bytes(bytes(ca_k.seed))
their_cert = (cx509.CertificateBuilder()
    .subject_name(cx509.Name([
        cx509.NameAttribute(cx509.NameOID.COMMON_NAME, "their.example"),
    ]))
    .issuer_name(their_ca.subject)
    .public_key(their_ca.public_key())
    .serial_number(cx509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=30))
    .sign(their_priv_ca, None))

our_parsed = Cert(their_cert.public_bytes(serialization.Encoding.PEM))
check("их PEM → наш Cert парсер",
      our_parsed.subject.get("CN") == "their.example")

# ---------- 5. Full chain ----------
print()
print("5. Полная цепочка")
leaf_key = Ed25519Keys.generate()
leaf = (CertificateBuilder()
    .add_subject({"CN": "leaf.example"})
    .add_issuer(ca)
    .add_public_key(leaf_key)
    .add_serial_random()
    .add_validity(days=30)
    .add_san_dns("leaf.example")
    .sign(ca_k))

their_leaf = cx509.load_pem_x509_certificate(leaf.to_pem().encode())
check("их SAN читает наш leaf",
      their_leaf.extensions.get_extension_for_class(
          cx509.SubjectAlternativeName
      ).value.get_values_for_type(cx509.DNSName) == ["leaf.example"])

check("их CA парсится нашим CACert",
      Cert(ca.to_pem()).subject.get("CN") == "Compat Root")

# ---------- Итог ----------
print()
print("=" * 60)
color = "32" if fail == 0 else "31"
print(f"  \033[{color}m{ok}/{ok + fail} passed\033[0m")
print("=" * 60)

sys.exit(0 if fail == 0 else 1)
