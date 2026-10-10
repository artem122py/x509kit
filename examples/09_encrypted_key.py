"""09 - Encrypted PKCS#8 private keys (RSA / Ed25519 / ECDSA).

Run: python examples/09_encrypted_key.py
Writes: demo_enc.pem (Ed25519 encrypted key)
"""
from x509kit import Ed25519Keys, RSAKeys, ECDSAKeys

KEYS = [
    ("RSA-2048", RSAKeys.generate(2048)),
    ("Ed25519",  Ed25519Keys.generate()),
    ("EC-P256",  ECDSAKeys.generate("P-256")),
]

for label, key in KEYS:
    enc = key.to_private_pem(password="hunter2", cipher="aes-256-cbc")
    first_line = enc.strip().splitlines()[0]
    print(f"{label}:")
    print(f"  header:    {first_line}")

    loaded = type(key).from_pem(enc, private=True, password="hunter2")
    pub_match = loaded.to_public_pem() == key.to_public_pem()
    print(f"  reload ok: {pub_match}")

    try:
        type(key).from_pem(enc, private=True, password="wrong")
        print(f"  wrong pw:  NOT rejected (this would be a bug)")
    except Exception as e:
        print(f"  wrong pw:  rejected ({type(e).__name__})")
    print()

    if label == "Ed25519":
        open("demo_enc.pem", "w").write(enc)

print("Saved: demo_enc.pem")
print()
print("Decrypt with OpenSSL:")
print("  openssl pkey -in demo_enc.pem -passin pass:hunter2 -noout -text")
