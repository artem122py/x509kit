"""17 - CMS SignedData (RFC 5652): sign / verify / detached.

Run: python examples/17_cms_sign.py
Writes: message.p7s, message.p7s.sig

Показывает:
  * attached CMS (content внутри .p7s)
  * detached CMS (content отдельно)
  * verify() с trust_anchor
  * tampering detection
  * OpenSSL interop
"""
import os
import subprocess
import tempfile

from x509kit import CertificateBuilder, Ed25519Keys, cms_sign, CMSSignedData


def build_ca():
    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "XX", "O": "CMS Demo", "CN": "CMS Demo Root CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))
    return ca, ca_key


def main():
    content = b"Hello from x509kit CMS!\n"

    # --- CA + leaf ---
    ca, ca_key = build_ca()
    leaf_key = Ed25519Keys.generate()
    leaf = (CertificateBuilder()
        .add_subject({"C": "XX", "O": "CMS Demo", "CN": "signer@demo"})
        .add_issuer(ca).add_public_key(leaf_key)
        .add_serial_random().add_validity(days=365)
        .add_extended_key_usage("emailProtection")
        .sign(ca_key))
    print(f"CA:    {ca.subject}")
    print(f"Leaf:  {leaf.subject}")
    print()

    # ============================================================
    # 1. Attached CMS
    # ============================================================
    print("=== 1. Attached CMS ===")
    sd = cms_sign(content, key=leaf_key, cert=leaf, chain=[ca])
    sd.save("message.p7s")
    print(f"  saved message.p7s ({os.path.getsize('message.p7s')} bytes)")
    print(f"  signers:      {sd.signer_count}")
    print(f"  certificates: {len(sd.certificates)} (leaf + ca)")
    print(f"  attached:     {not sd.detached}")

    # Reload and verify
    sd2 = CMSSignedData.load("message.p7s")
    print(f"  verify():                     {sd2.verify()}")
    print(f"  verify(trust_anchor=ca):      {sd2.verify(trust_anchor=ca)}")

    other_ca, _ = build_ca()
    print(f"  verify(wrong_anchor):         {sd2.verify(trust_anchor=other_ca)}")

    # Inspect signer
    s = sd2.signers[0]
    print()
    print(f"  Signer digest:  {s.digest_algorithm.name}")
    print(f"  Signer sig:     {s.signature_algorithm.name}")
    print(f"  Signing time:   {s.signing_time.isoformat()}")
    print(f"  messageDigest:  {s.message_digest.hex()[:32]}...")
    print(f"  contentType:    {s.content_type_attr}")

    # ============================================================
    # 2. Detached CMS
    # ============================================================
    print()
    print("=== 2. Detached CMS ===")
    sd_det = cms_sign(content, key=leaf_key, cert=leaf, chain=[ca],
                       detached=True)
    sd_det.save("message.p7s.sig")
    print(f"  saved message.p7s.sig ({os.path.getsize('message.p7s.sig')} bytes)")

    sd_det2 = CMSSignedData.load("message.p7s.sig")
    print(f"  content:                      {sd_det2.content!r}")
    print(f"  detached:                     {sd_det2.detached}")
    print(f"  verify() без data:            {sd_det2.verify()}")
    print(f"  verify(detached_data):        "
          f"{sd_det2.verify(detached_data=content, trust_anchor=ca)}")
    print(f"  verify(tampered data):        "
          f"{sd_det2.verify(detached_data=b'evil', trust_anchor=ca)}")

    # ============================================================
    # 3. Tampering detection
    # ============================================================
    print()
    print("=== 3. Tampering detection ===")
    # Modify content, keep signature
    der = sd.to_der()
    # Find "Hello from x509kit CMS!" in DER and flip a byte
    marker = b"Hello from x509kit CMS"
    idx = der.find(marker)
    if idx > 0:
        tampered = bytearray(der)
        tampered[idx + 6] = ord("X")
        sd_tampered = CMSSignedData.load(bytes(tampered))
        print(f"  verify(tampered attached):   {sd_tampered.verify()}")
    else:
        print(f"  (marker not found in DER — skipping)")

    # ============================================================
    # 4. OpenSSL interop
    # ============================================================
    print()
    print("=== 4. OpenSSL interop ===")
    openssl = subprocess.run(["which", "openssl"],
                             capture_output=True, text=True).stdout.strip()
    if not openssl:
        print("  (openssl not in PATH — skipped)")
        return 0

    tmp = tempfile.mkdtemp()
    ca_path   = os.path.join(tmp, "ca.pem")
    data_path = os.path.join(tmp, "content.bin")
    sig_path  = os.path.join(tmp, "sig.p7s")

    with open(ca_path, "w") as f:
        f.write(ca.to_pem())
    with open(data_path, "wb") as f:
        f.write(content)
    with open(sig_path, "wb") as f:
        f.write(sd.to_der())

    r = subprocess.run(
        ["openssl", "cms", "-verify",
         "-inform", "DER", "-in", sig_path,
         "-CAfile", ca_path, "-purpose", "any", "-no_check_time"],
        capture_output=True, text=True)
    print(f"  openssl cms -verify rc:       {r.returncode}")
    print(f"  stdout:                       {r.stdout.strip()}")
    if r.stderr.strip():
        print(f"  stderr:                       {r.stderr.strip()[:120]}")

    print()
    print("Verify it yourself:")
    print(f"  openssl cms -verify -inform DER -in message.p7s \\")
    print(f"      -CAfile ca.pem -purpose any -no_check_time")
    print()
    print("  # For detached:")
    print(f"  openssl cms -verify -inform DER -in message.p7s.sig \\")
    print(f"      -content content.bin -CAfile ca.pem -purpose any")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
