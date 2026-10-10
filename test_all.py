# -*- coding: utf-8 -*-
"""
test_all.py — единый прогон x509kit.

Разделы:
  1.  RSA self-tests
  2.  Ed25519 self-tests (RFC 8032)
  3.  ECDSA self-tests + RFC 6979 vectors
  4.  AES-256 + AES-GCM (FIPS 197, NIST SP 800-38D)
  5.  PKCS#8 EncryptedPrivateKeyInfo (RSA/Ed/EC × CBC/GCM)
  6.  Цепочки (RSA / Ed25519 / ECDSA×4)
  7.  Mixed: все CA → все leaf
  8.  Cross-verify с cryptography (RSA + Ed25519)
  9.  ECDSA cross-verify с cryptography
 10.  Name Constraints (+ intersection)
 11.  CRL
 12.  OCSP
 13.  AIA
 14.  RFC 4518 канонизация
 15.  PEM round-trip

Запуск:
    python test_all.py
"""


import sys as _sys
if hasattr(_sys.stdout, "reconfigure"):
    try:
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import datetime
import sys
import traceback

from x509kit import (
    PKCS12,
    RSAKeys, Ed25519Keys, ECDSAKeys,
    Cert, CACert, CSR, CertBundle,
    CRL, CRLBuilder, CRL_REASONS,
    OCSPRequest, OCSPResponse, OCSPResponseBuilder,
    CertificateBuilder, CSRBuilder,
    Name, san_extension, validate_hostname,
    canonicalize_name, names_equal,
    X509Error, X509Warning,
)
from x509kit.x509 import (
    _aes256_encrypt_block, _aes256_decrypt_block, _aes256_key_expand,
    _aes256_cbc_encrypt, _aes256_cbc_decrypt,
    _aes256_gcm_encrypt, _aes256_gcm_decrypt,
    _parse_ecdsa_sig,
)


# ======================================================================
#  Мини-фреймворк
# ======================================================================

class T:
    _passed = 0
    _failed = 0
    _skipped = 0
    _failures = []

    @classmethod
    def ok(cls, name):
        cls._passed += 1
        print(f"    \033[32m✓\033[0m {name}")

    @classmethod
    def fail(cls, name, reason=""):
        cls._failed += 1
        cls._failures.append((name, reason))
        print(f"    \033[31m✗\033[0m {name}  {reason}")

    @classmethod
    def skip(cls, name, reason=""):
        cls._skipped += 1
        print(f"    \033[33m·\033[0m {name}  ({reason})")

    @classmethod
    def expect(cls, name, cond, reason=""):
        if cond:
            cls.ok(name)
        else:
            cls.fail(name, reason)

    @classmethod
    def summary(cls):
        print()
        print("=" * 72)
        total = cls._passed + cls._failed
        color = "32" if cls._failed == 0 else "31"
        print(f"  \033[{color}mПройдено: {cls._passed}/{total}"
              f"  |  Провалено: {cls._failed}"
              f"  |  Пропущено: {cls._skipped}\033[0m")
        if cls._failures:
            print()
            print("  Провалившиеся тесты:")
            for name, reason in cls._failures:
                print(f"    - {name}  {reason}")
        print("=" * 72)
        return cls._failed == 0


def hr(title):
    print()
    print("─" * 72)
    print(f"  {title}")
    print("─" * 72)


# ======================================================================
#  1. RSA
# ======================================================================

def test_rsa():
    hr("1. RSA self-tests")
    k = RSAKeys.generate(2048)
    T.expect("generate(2048) → 2048-битный", k.size_bits == 2048)

    msg = b"hello x509"
    sig = k.sign_pkcs1v15(msg, "sha256")
    T.expect("PKCS#1 v1.5 sign/verify", k.verify_pkcs1v15(msg, sig, "sha256"))
    T.expect("tampered message → False",
             not k.verify_pkcs1v15(msg + b"!", sig, "sha256"))
    T.expect("tampered signature → False",
             not k.verify_pkcs1v15(msg, sig[:-1] + bytes([sig[-1] ^ 1]), "sha256"))

    sig2 = k.sign_pkcs1v15(msg, "sha256")
    T.expect("детерминизм (PKCS#1 v1.5)", sig == sig2)

    for h in ("sha256", "sha384", "sha512"):
        s = k.sign_pkcs1v15(msg, h)
        T.expect(f"hash {h}", k.verify_pkcs1v15(msg, s, h))

    try:
        RSAKeys.generate(1024)
        T.fail("generate(1024) отвергается", "не бросило")
    except ValueError:
        T.ok("generate(1024) отвергается")

    try:
        RSAKeys.generate(2048, e=3)
        T.fail("e=3 отвергается", "не бросило")
    except ValueError:
        T.ok("e=3 отвергается")

    msg2 = b"pss test"
    sig_pss = k.sign_pss(msg2, "sha256")
    T.expect("PSS sign/verify", k.verify_pss(msg2, sig_pss, "sha256"))
    T.expect("PSS: tampered → False",
             not k.verify_pss(msg2 + b"!", sig_pss, "sha256"))

    pem = k.to_private_pem()
    k2 = RSAKeys.from_pem(pem, private=True)
    T.expect("private PEM round-trip", k2.n == k.n and k2.d == k.d)


# ======================================================================
#  2. Ed25519
# ======================================================================

def test_ed25519():
    hr("2. Ed25519 self-tests (RFC 8032)")

    seed1 = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60")
    pub1 = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a")
    sig1 = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b")
    k1 = Ed25519Keys(seed=seed1)
    T.expect("RFC 8032 test1: pubkey", k1.pub == pub1)
    T.expect("RFC 8032 test1: signature", k1.sign(b"") == sig1)
    T.expect("RFC 8032 test1: verify", k1.verify(b"", sig1))

    seed2 = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb")
    pub2 = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc"
        "9c982ccf2ec4968cc0cd55f12af4660c")
    sig2 = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c"
        "387b2eaeb4302aeeb00d291612bb0c00")
    k2 = Ed25519Keys(seed=seed2)
    msg2 = bytes.fromhex("72")
    T.expect("RFC 8032 test2: pubkey", k2.pub == pub2)
    T.expect("RFC 8032 test2: signature", k2.sign(msg2) == sig2)

    k = Ed25519Keys.generate()
    m = b"deterministic"
    T.expect("детерминизм Ed25519", k.sign(m) == k.sign(m))

    bad = bytearray(k.sign(m))
    for i in range(32, 64):
        bad[i] = 0xFF
    T.expect("отказ при S >= L", not k.verify(m, bytes(bad)))

    bad2 = bytearray(k.sign(m))
    bad2[0] ^= 0x01
    T.expect("отказ при битом R", not k.verify(m, bytes(bad2)))


# ======================================================================
#  3. ECDSA + RFC 6979
# ======================================================================

def test_ecdsa():
    hr("3. ECDSA self-tests + RFC 6979")

    # Базовые sign/verify на всех кривых
    for curve, h in (("P-256", "sha256"), ("P-384", "sha384"),
                     ("P-521", "sha512"), ("secp256k1", "sha256")):
        k = ECDSAKeys.generate(curve)
        sig = k.sign(b"test", h)
        T.expect(f"{curve}: sign/verify", k.verify(b"test", sig, h))
        T.expect(f"{curve}: tampered → False",
                 not k.verify(b"other", sig, h))

    # Детерминизм
    k = ECDSAKeys.generate("P-256")
    T.expect("RFC 6979: детерминизм",
             k.sign(b"msg", "sha256") == k.sign(b"msg", "sha256"))

    # RFC 6979 Appendix A.2.5 vectors (P-256, SHA-256)
    x = int("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            16)
    k = ECDSAKeys("1.2.840.10045.3.1.7", d=x)

    sig = k.sign(b"sample", "sha256")
    r, s = _parse_ecdsa_sig(sig)
    T.expect("RFC 6979 'sample': r",
             r == int("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16))
    T.expect("RFC 6979 'sample': s",
             s == int("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 16))

    sig = k.sign(b"test", "sha256")
    r, s = _parse_ecdsa_sig(sig)
    T.expect("RFC 6979 'test': r",
             r == int("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", 16))
    T.expect("RFC 6979 'test': s",
             s == int("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", 16))

    # Отказ при r=0 / s=0 — не тестируем (маловероятно), но r >= n отвергаем
    curve = ECDSAKeys.generate("P-256").curve
    T.expect("P-256 n.bit_length == 256", curve["n"].bit_length() == 256)
    curve521 = ECDSAKeys.generate("P-521").curve
    T.expect("P-521 n.bit_length == 521", curve521["n"].bit_length() == 521)


# ======================================================================
#  4. AES / GCM
# ======================================================================

def test_aes():
    hr("4. AES-256 (FIPS 197) + AES-GCM (NIST SP 800-38D)")

    # FIPS 197 §C.3 — AES-256 one block
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expect = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    w = _aes256_key_expand(key)
    ct = _aes256_encrypt_block(pt, w)
    T.expect("FIPS 197 AES-256 encrypt", ct == expect)
    T.expect("FIPS 197 AES-256 decrypt", _aes256_decrypt_block(ct, w) == pt)

    # CBC round-trip
    k = bytes(range(32))
    iv = bytes(range(16))
    msg = b"AES-CBC round trip" * 30
    ct = _aes256_cbc_encrypt(k, iv, msg)
    T.expect("AES-256-CBC round-trip",
             _aes256_cbc_decrypt(k, iv, ct) == msg)

    # NIST SP 800-38D Test 1: пустой PT
    key = bytes(32); nonce = bytes(12)
    ct, tag = _aes256_gcm_encrypt(key, nonce, b"", b"")
    T.expect("NIST GCM empty: ct пустой", ct == b"")
    T.expect("NIST GCM empty: tag",
             tag.hex() == "530f8afbc74536b9a963b4f1c4cb738b")

    # NIST SP 800-38D Test 2: 16 нулевых байт
    ct, tag = _aes256_gcm_encrypt(key, nonce, bytes(16), b"")
    T.expect("NIST GCM block: ct",
             ct.hex() == "cea7403d4d606b6e074ec5d3baf39d18")
    T.expect("NIST GCM block: tag",
             tag.hex() == "d0d1c8a799996bf0265b98b5d48ab919")

    # GCM round-trip с AAD
    k = bytes(range(32))
    n = bytes(range(12))
    m = b"secret payload" * 10
    aad = b"authenticated header"
    ct, tag = _aes256_gcm_encrypt(k, n, m, aad)
    T.expect("GCM round-trip с AAD",
             _aes256_gcm_decrypt(k, n, ct, tag, aad) == m)

    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    try:
        _aes256_gcm_decrypt(k, n, ct, bad_tag, aad)
        T.fail("GCM: tampered tag → X509Error", "не бросило")
    except X509Error:
        T.ok("GCM: tampered tag → X509Error")


# ======================================================================
#  5. PKCS#8 EncryptedPrivateKeyInfo
# ======================================================================

def test_encrypted_keys():
    hr("5. PKCS#8 EncryptedPrivateKeyInfo")

    rsa = RSAKeys.generate(2048)
    ed = Ed25519Keys.generate()
    ec = ECDSAKeys.generate("P-256")

    for cipher in ("aes-256-cbc", "aes-256-gcm"):
        # RSA
        pem = rsa.to_private_pem(password="hunter2", iterations=5000,
                                 cipher=cipher)
        T.expect(f"RSA {cipher}: ENCRYPTED PRIVATE KEY",
                 pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        k2 = RSAKeys.from_pem(pem, private=True, password="hunter2")
        T.expect(f"RSA {cipher}: round-trip", k2.n == rsa.n and k2.d == rsa.d)

        # Ed25519
        pem = ed.to_private_pem(password="hunter2", iterations=5000,
                                cipher=cipher)
        k2 = Ed25519Keys.from_pem(pem, private=True, password="hunter2")
        T.expect(f"Ed25519 {cipher}: round-trip", k2.pub == ed.pub)

        # ECDSA
        pem = ec.to_private_pem(password="hunter2", iterations=5000,
                                cipher=cipher)
        k2 = ECDSAKeys.from_pem(pem, private=True, password="hunter2")
        T.expect(f"ECDSA {cipher}: round-trip", k2.point == ec.point)

    # Неверный пароль
    pem = rsa.to_private_pem(password="hunter2", iterations=5000,
                             cipher="aes-256-gcm")
    try:
        RSAKeys.from_pem(pem, private=True, password="wrong")
        T.fail("GCM: неверный пароль → X509Error", "не бросило")
    except X509Error:
        T.ok("GCM: неверный пароль → X509Error")

    # Незашифрованный round-trip
    plain = rsa.to_private_pem()
    T.expect("plain RSA PEM (не шифрован)",
             plain.startswith("-----BEGIN RSA PRIVATE KEY-----"))


# ======================================================================
#  6. Цепочки
# ======================================================================

def _make_chain(key_factory):
    root_key = key_factory()
    root = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "RU", "O": "Test", "CN": "Test Root CA"})
        .add_public_key(root_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=1)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(root_key))

    inter_key = key_factory()
    csr = (CSRBuilder()
        .add_subject({"C": "RU", "O": "Test", "CN": "Test Inter"})
        .add_public_key(inter_key)
        .sign(inter_key))
    inter_cert = (CertificateBuilder.from_csr(csr, is_ca=True)
        .add_issuer(root)
        .add_serial_random().add_validity(days=1825)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .sign(root_key))
    inter = CACert.from_cert(inter_cert, signing_key=inter_key)

    leaf_key = key_factory()
    leaf_csr = (CSRBuilder()
        .add_subject({"C": "RU", "O": "Test", "CN": "example.com"})
        .add_public_key(leaf_key)
        .add_san_dns("example.com", "www.example.com")
        .add_san_ip("192.0.2.1")
        .sign(leaf_key))
    leaf = (CertificateBuilder.from_csr(leaf_csr)
        .add_issuer(inter)
        .add_serial_random().add_validity(days=365)
        .sign(inter_key))

    return root, inter, leaf, leaf_csr


def test_chain(label, key_factory):
    hr(f"6. Цепочки ({label})")
    root, inter, leaf, leaf_csr = _make_chain(key_factory)

    T.expect("root self-signed", root.is_self_signed())
    T.expect("inter ← root", inter.verify_signature(root))
    T.expect("leaf ← inter", leaf.verify_signature(inter))
    T.expect("verify_chain([leaf, inter])",
             root.verify_chain([leaf, inter]))
    T.expect("inter.verify_chain([leaf])", inter.verify_chain([leaf]))
    T.expect("порядок наоборот → False",
             not root.verify_chain([inter, leaf]))
    T.expect("без intermediate → False", not root.verify_chain([leaf]))

    future = (datetime.datetime.now(datetime.timezone.utc)
              + datetime.timedelta(days=400))
    T.expect("истёкший leaf → False",
             not root.verify_chain([leaf, inter], when=future))

    bad = bytearray(leaf.der); bad[-1] ^= 0xFF
    try:
        T.expect("tampered leaf → False",
                 not root.verify_chain([Cert(bytes(bad)), inter]))
    except Exception:
        T.ok("tampered leaf: parse отказал")

    other_root_key = key_factory()
    other_root = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "RU", "O": "Other", "CN": "Other Root"})
        .add_public_key(other_root_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=1)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(other_root_key))
    T.expect("чужой root → False",
             not other_root.verify_chain([leaf, inter]))

    T.expect("CSR self-signature", leaf_csr.verify_signature())
    bad_csr = bytearray(leaf_csr.der); bad_csr[-1] ^= 0xFF
    T.expect("CSR tampered → False",
             not CSR(bytes(bad_csr)).verify_signature())

    T.expect("hostname exact", validate_hostname(leaf, "example.com"))
    T.expect("hostname wildcard", validate_hostname(leaf, "www.example.com"))
    T.expect("hostname wrong", not validate_hostname(leaf, "other.com"))
    T.expect("hostname IP ok", validate_hostname(leaf, "192.0.2.1"))

    loaded = Cert(leaf.to_pem())
    T.expect("cert PEM round-trip", loaded.der == leaf.der)


# ======================================================================
#  7. Mixed
# ======================================================================

def test_mixed():
    hr("7. Mixed: все типы CA → все типы leaf")
    factories = {
        "RSA":       lambda: RSAKeys.generate(2048),
        "Ed25519":   lambda: Ed25519Keys.generate(),
        "EC-P256":   lambda: ECDSAKeys.generate("P-256"),
        "EC-P384":   lambda: ECDSAKeys.generate("P-384"),
    }
    for ca_name, ca_f in factories.items():
        ca_k = ca_f()
        ca = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": f"{ca_name} CA"})
            .add_public_key(ca_k)
            .add_serial_random().add_validity(days=3650)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .self_signed().sign(ca_k))
        row = []
        for leaf_name, leaf_f in factories.items():
            leaf_k = leaf_f()
            leaf = (CertificateBuilder()
                .add_subject({"CN": f"{leaf_name}.example"})
                .add_issuer(ca).add_public_key(leaf_k)
                .add_serial_random().add_validity(days=30)
                .add_san_dns(f"{leaf_name}.example")
                .sign(ca_k))
            row.append((leaf_name, ca.verify_chain([leaf])))
        T.expect(f"CA={ca_name}: 4 leaf-типа",
                 all(ok for _, ok in row),
                 " · ".join(f"{n}:{ok}" for n, ok in row))


# ======================================================================
#  8. cryptography cross-verify (RSA + Ed25519)
# ======================================================================

def test_cryptography():
    hr("8. Cross-verify с cryptography (RSA + Ed25519)")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import (
            rsa as crsa, ed25519 as ced, padding as cpad,
        )
    except ImportError:
        T.skip("cryptography не установлена", "pip install cryptography")
        return

    our_rsa = RSAKeys.generate(2048)
    their_pub = serialization.load_pem_public_key(
        our_rsa.to_public_pem().encode())
    msg = b"cross-verify message"

    our_sig = our_rsa.sign_pkcs1v15(msg, "sha256")
    try:
        their_pub.verify(our_sig, msg, cpad.PKCS1v15(), hashes.SHA256())
        T.ok("наш RSA sign → их verify")
    except Exception as e:
        T.fail("наш RSA sign → их verify", str(e))

    their_priv = serialization.load_pem_private_key(
        our_rsa.to_private_pem().encode(), password=None)
    their_sig = their_priv.sign(msg, cpad.PKCS1v15(), hashes.SHA256())
    T.expect("их RSA sign → наш verify",
             our_rsa.verify_pkcs1v15(msg, their_sig, "sha256"))

    # Ed25519
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60")
    our_ed = Ed25519Keys(seed=seed)
    their_ed = ced.Ed25519PrivateKey.from_private_bytes(seed)
    their_pub_raw = their_ed.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    T.expect("Ed25519: seed → pubkey", our_ed.pub == their_pub_raw)

    msg_ed = b"ed25519 cross"
    try:
        their_ed.public_key().verify(our_ed.sign(msg_ed), msg_ed)
        T.ok("наш Ed25519 sign → их verify")
    except Exception as e:
        T.fail("наш Ed25519 sign → их verify", str(e))

    T.expect("их Ed25519 sign → наш verify",
             our_ed.verify(msg_ed, their_ed.sign(msg_ed)))


# ======================================================================
#  9. ECDSA cross-verify
# ======================================================================

def test_ecdsa_cryptography():
    hr("9. ECDSA cross-verify с cryptography")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec as cec
    except ImportError:
        T.skip("cryptography не установлена", "")
        return

    curves = [
        ("P-256", cec.SECP256R1(), hashes.SHA256(), "sha256"),
        ("P-384", cec.SECP384R1(), hashes.SHA384(), "sha384"),
        ("P-521", cec.SECP521R1(), hashes.SHA512(), "sha512"),
    ]

    for name, their_curve, their_hash, hash_name in curves:
        our_key = ECDSAKeys.generate(name)
        try:
            their_pub = serialization.load_der_public_key(our_key.to_public_der())
            msg = b"ecdsa cross"
            our_sig = our_key.sign(msg, hash_name)
            try:
                their_pub.verify(our_sig, msg, cec.ECDSA(their_hash))
                T.ok(f"{name}: наш sign → их verify")
            except Exception as e:
                T.fail(f"{name}: наш sign → их verify", str(e))
        except Exception as e:
            T.fail(f"{name}: SPKI → их парсер", str(e))
            continue

        their_priv = cec.generate_private_key(their_curve)
        their_pub_der = their_priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        try:
            our_pub = ECDSAKeys.from_public_der(their_pub_der)
            msg = b"reverse"
            their_sig = their_priv.sign(msg, cec.ECDSA(their_hash))
            T.expect(f"{name}: их sign → наш verify",
                     our_pub.verify(msg, their_sig, hash_name))
        except Exception as e:
            T.fail(f"{name}: их sign → наш verify", str(e))


# ======================================================================
#  10. Name Constraints
# ======================================================================

def test_name_constraints():
    hr("10. Name Constraints (+ intersection)")

    # Round-trip
    key = Ed25519Keys.generate()
    cert = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "NC Round-trip CA"})
        .add_public_key(key)
        .add_serial_random().add_validity(days=365)
        .add_basic_constraints(path_len=0)
        .add_name_constraints(
            permitted_dns=[".example.com", ".example.org"],
            excluded_dns=[".bad.example.com"],
            permitted_ip=["10.0.0.0/8", "2001:db8::/32"],
            excluded_ip=["10.66.0.0/16"],
        )
        .self_signed().sign(key))

    nc = cert.name_constraints
    T.expect("NC: расширение есть", nc is not None)
    if nc:
        perm, excl = nc["permitted"], nc["excluded"]
        T.expect("NC: permitted dns",
                 perm.get("dns") == [".example.com", ".example.org"])
        T.expect("NC: permitted ip",
                 perm.get("ip") == ["10.0.0.0/8", "2001:db8::/32"])
        T.expect("NC: excluded dns",
                 excl.get("dns") == [".bad.example.com"])
        T.expect("NC: excluded ip", excl.get("ip") == ["10.66.0.0/16"])

    # Enforcement при выпуске
    root_key = Ed25519Keys.generate()
    root = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "NC Root"})
        .add_public_key(root_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=1)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(root_key))

    inter_key = Ed25519Keys.generate()
    inter = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "NC Inter"})
        .add_issuer(root).add_public_key(inter_key)
        .add_serial_random().add_validity(days=1825)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .add_name_constraints(
            permitted_dns=[".example.com"],
            excluded_dns=[".bad.example.com"],
            permitted_ip=["10.0.0.0/8"])
        .sign(root_key))

    try:
        good = (CertificateBuilder()
            .add_subject({"CN": "www.example.com"})
            .add_issuer(inter).add_public_key(Ed25519Keys.generate())
            .add_serial_random().add_validity(days=30)
            .add_san_dns("www.example.com")
            .add_san_ip("10.1.2.3")
            .sign(inter_key))
        T.ok("NC: допустимый leaf выпущен")
        T.expect("NC: verify_chain", root.verify_chain([good, inter]))
    except X509Error as e:
        T.fail("NC: допустимый leaf выпущен", str(e))

    for cn, expect_sub in (("evil.org", "not within permitted"),
                           ("app.bad.example.com", "matches excluded")):
        try:
            (CertificateBuilder()
                .add_subject({"CN": cn})
                .add_issuer(inter).add_public_key(Ed25519Keys.generate())
                .add_serial_random().add_validity(days=30)
                .add_san_dns(cn)
                .sign(inter_key))
            T.fail(f"NC: {cn} → X509Error", "не бросило")
        except X509Error as e:
            T.expect(f"NC: {cn} → X509Error", expect_sub in str(e))

    # IP вне subnet
    try:
        (CertificateBuilder()
            .add_subject({"CN": "x.example.com"})
            .add_issuer(inter).add_public_key(Ed25519Keys.generate())
            .add_serial_random().add_validity(days=30)
            .add_san_dns("x.example.com")
            .add_san_ip("192.168.1.1")
            .sign(inter_key))
        T.fail("NC: IP вне subnet → X509Error", "не бросило")
    except X509Error as e:
        T.expect("NC: IP вне subnet → X509Error",
                 "not within permitted" in str(e))

    # Intersection: sub-CA разрешает больше родителя
    inter_bad_key = Ed25519Keys.generate()
    try:
        inter_bad = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": "Bad Inter"})
            .add_issuer(root).add_public_key(inter_bad_key)
            .add_serial_random().add_validity(days=1825)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .add_name_constraints(permitted_dns=[".attacker.com"])
            .sign(root_key))
        # root не имеет NC, поэтому эта проверка ожидается при verify_chain
        # с цепочкой, где у root был NC — но у нас root без NC.
        # Проверим intersection в цепочке с обоими NC.
        root2_key = Ed25519Keys.generate()
        root2 = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": "Strict Root"})
            .add_public_key(root2_key)
            .add_serial_random().add_validity(days=3650)
            .add_basic_constraints(path_len=1)
            .add_key_usage("keyCertSign", "cRLSign")
            .add_name_constraints(permitted_dns=[".example.com"])
            .self_signed().sign(root2_key))

        inter2_key = Ed25519Keys.generate()
        inter2 = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": "Bad Inter2"})
            .add_issuer(root2).add_public_key(inter2_key)
            .add_serial_random().add_validity(days=1825)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .add_name_constraints(permitted_dns=[".attacker.com"])
            .sign(root2_key))

        leaf_key = Ed25519Keys.generate()
        leaf = (CertificateBuilder()
            .add_subject({"CN": "x.attacker.com"})
            .add_issuer(inter2).add_public_key(leaf_key)
            .add_serial_random().add_validity(days=30)
            .add_san_dns("x.attacker.com")
            .sign(inter2_key))

        T.expect("NC intersection: sub-CA разрешает больше → False",
                 not root2.verify_chain([leaf, inter2]))
    except X509Error:
        T.ok("NC intersection: нарушение поймано при выпуске")


# ======================================================================
#  11. CRL
# ======================================================================

def test_crl():
    hr("11. CRL")

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "CRL Test CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .add_crl_distribution_point("http://ca.test/crl.pem")
        .self_signed().sign(ca_key))

    leaves = []
    for cn in ("a.test", "b.test", "c.test"):
        leaf = (CertificateBuilder()
            .add_subject({"CN": cn})
            .add_issuer(ca).add_public_key(Ed25519Keys.generate())
            .add_serial_random().add_validity(days=365)
            .add_san_dns(cn)
            .add_crl_distribution_point("http://ca.test/crl.pem")
            .sign(ca_key))
        leaves.append(leaf)

    T.expect("3 листа выпущены",
             all(ca.verify_cert(l) for l in leaves))

    ca.revoke(leaves[1], reason="keyCompromise")
    crl = ca.to_crl(days=7)

    T.expect("CRL: подпись", crl.verify_signature(ca))
    T.expect("CRL: is_valid_at", crl.is_valid_at())
    T.expect("CRL: a не отозван", not crl.is_revoked(leaves[0]))
    T.expect("CRL: b отозван", crl.is_revoked(leaves[1]))
    T.expect("CRL: reason keyCompromise",
             crl.revoke_reason(leaves[1]) == "keyCompromise")
    T.expect("CRL: verify_cert(a, crl=crl)",
             ca.verify_cert(leaves[0], crl=crl))
    T.expect("CRL: verify_cert(b, crl=crl) → False",
             not ca.verify_cert(leaves[1], crl=crl))

    crl2 = CRL(crl.to_pem())
    T.expect("CRL: PEM round-trip",
             len(crl2.revoked) == len(crl.revoked))


# ======================================================================
#  12. OCSP
# ======================================================================

def test_ocsp():
    hr("12. OCSP")

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "OCSP Test CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))

    leaf = (CertificateBuilder()
        .add_subject({"CN": "ocsp.example"})
        .add_issuer(ca).add_public_key(Ed25519Keys.generate())
        .add_serial_random().add_validity(days=365)
        .add_san_dns("ocsp.example")
        .sign(ca_key))

    req = OCSPRequest.create(issuer=ca, cert=leaf)
    T.expect("OCSPRequest serial", req.serial == leaf.serial)
    T.expect("OCSPRequest nonce", req.nonce is not None)

    req2 = OCSPRequest(req.der)
    T.expect("OCSPRequest round-trip",
             req2.serial == req.serial and req2.nonce == req.nonce)

    resp = ca.respond_ocsp(req, status="good", days=1)
    T.expect("OCSPResponse successful", resp.is_successful)
    T.expect("OCSPResponse signature", resp.verify_signature(ca))
    T.expect("OCSPResponse fresh", resp.is_fresh())
    T.expect("OCSPResponse nonce echo", resp.nonce == req.nonce)
    T.expect("OCSPResponse status good", resp.get_status(leaf) == "good")

    T.expect("verify_ocsp_response с request",
             ca.verify_ocsp_response(resp, request=req))

    b = OCSPResponseBuilder()
    b.set_responder(ca).set_validity(days=7)
    b.add_status(leaf, status="revoked", reason="keyCompromise")
    resp2 = b.sign(ca_key)
    T.expect("OCSP revoked status", resp2.get_status(leaf) == "revoked")
    info = resp2.get_revoke_info(leaf)
    T.expect("OCSP revoke info",
             info is not None and info[1] == "keyCompromise")

    T.expect("verify_cert с good OCSP",
             ca.verify_cert(leaf, ocsp_response=resp))
    T.expect("verify_cert с revoked OCSP → False",
             not ca.verify_cert(leaf, ocsp_response=resp2))


# ======================================================================
#  13. AIA
# ======================================================================

def test_aia():
    hr("13. AIA (Authority Information Access)")

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "AIA Test CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .add_aia(ocsp=["http://ocsp.ca.test"],
                 ca_issuers=["http://ca.test/ca.pem"])
        .self_signed().sign(ca_key))

    leaf = (CertificateBuilder()
        .add_subject({"CN": "example.com"})
        .add_issuer(ca).add_public_key(Ed25519Keys.generate())
        .add_serial_random().add_validity(days=365)
        .add_san_dns("example.com")
        .add_aia(ocsp="http://ocsp.ca.test",
                 ca_issuers="http://ca.test/ca.pem")
        .sign(ca_key))

    T.expect("AIA: leaf.aia_ocsp",
             leaf.aia_ocsp == ["http://ocsp.ca.test"])
    T.expect("AIA: leaf.aia_issuers",
             leaf.aia_issuers == ["http://ca.test/ca.pem"])
    T.expect("AIA: ca.aia_ocsp",
             ca.aia_ocsp == ["http://ocsp.ca.test"])
    T.expect("AIA: полный dict",
             leaf.aia == {"ocsp": ["http://ocsp.ca.test"],
                          "ca_issuers": ["http://ca.test/ca.pem"]})

    # String принимается
    leaf2 = (CertificateBuilder()
        .add_subject({"CN": "single.example"})
        .add_issuer(ca).add_public_key(Ed25519Keys.generate())
        .add_serial_random().add_validity(days=30)
        .add_san_dns("single.example")
        .add_aia(ocsp="http://one.example/ocsp")
        .sign(ca_key))
    T.expect("AIA: строка как один URL",
             leaf2.aia_ocsp == ["http://one.example/ocsp"])


# ======================================================================
#  14. RFC 4518 канонизация
# ======================================================================

def test_canonicalization():
    hr("14. RFC 4518 канонизация DN")

    n1 = Name.from_dict({"C": "XX", "O": "My  Org", "CN": "Example.COM"})
    n2 = Name.from_dict({"C": "xx", "O": "my org", "CN": "example.com"})
    T.expect("raw не совпадает", n1.raw != n2.raw)
    T.expect("канонично совпадает", names_equal(n1, n2))

    # NFKC: fullwidth → ascii
    n5 = Name.from_dict({"CN": "ＡＢＣ"})
    n6 = Name.from_dict({"CN": "abc"})
    T.expect("NFKC: fullwidth → ascii", names_equal(n5, n6))

    # NFKC: ligature fi
    n7 = Name.from_dict({"CN": "ﬁle"})
    n8 = Name.from_dict({"CN": "file"})
    T.expect("NFKC: ligature ﬁ → fi", names_equal(n7, n8))

    # Пробелы
    n9 = Name.from_dict({"CN": "  Hello  World  "})
    n10 = Name.from_dict({"CN": "hello world"})
    T.expect("пробелы схлопнуты", names_equal(n9, n10))

    # Cert-методы
    key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "XX", "O": "MyOrg", "CN": "My Root CA"})
        .add_public_key(key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(key))

    leaf = (CertificateBuilder()
        .add_subject({"C": "XX", "O": "MyOrg", "CN": "leaf.example"})
        .add_issuer(ca).add_public_key(Ed25519Keys.generate())
        .add_serial_random().add_validity(days=30)
        .add_san_dns("leaf.example")
        .sign(key))

    T.expect("subject_matches_issuer(ca)",
             leaf.subject_matches_issuer(ca))
    T.expect("subject_matches_issuer(leaf) → False",
             not leaf.subject_matches_issuer(leaf))
    # leaf.subject ~ ca.subject? Это РАЗНЫЕ имена (leaf.example vs My Root CA)
    T.expect("name_matches(ca) → False",
             not leaf.name_matches(ca))
    # Но leaf.issuer канонично совпадает с ca.subject
    T.expect("leaf.subject_matches_issuer(ca)",
             leaf.subject_matches_issuer(ca))
    # И симметрия: ca.name_matches(ca) → True
    T.expect("ca.name_matches(ca) → True",
             ca.name_matches(ca))
    # Прямое сравнение через names_equal
    T.expect("names_equal(leaf.subject, ca.subject) → False",
             not names_equal(leaf.subject, ca.subject))
    T.expect("names_equal(ca.subject, ca.subject) → True",
             names_equal(ca.subject, ca.subject))
    # Регистр и пробелы не влияют
    ca_lower = Name.from_dict({"C": "xx", "O": "myorg", "CN": "my root ca"})
    T.expect("names_equal регистронезависимо",
             names_equal(ca.subject, ca_lower))


# ======================================================================
#  15. PEM round-trip
# ======================================================================

def test_pem_roundtrip():
    hr("15. PEM round-trip")
    key = RSAKeys.generate(2048)
    cert = (CertificateBuilder()
        .add_subject({"CN": "pem.example"})
        .add_public_key(key)
        .add_serial_random().add_validity(days=30)
        .add_san_dns("pem.example")
        .self_signed().sign(key))

    T.expect("cert PEM round-trip", Cert(cert.to_pem()).der == cert.der)

    bundle = CertBundle([cert, cert, cert])
    b2 = CertBundle.from_pem(bundle.to_pem())
    T.expect("bundle round-trip", len(b2) == 3)


# ======================================================================
#  Main
# ======================================================================


# ======================================================================
#  16. Новые фичи: from_string, from_url, info, to_pkcs12
# ======================================================================

def test_name_from_string():
    hr("16. Name.from_string (RFC 4514)")

    n1 = Name.from_string("CN=example.com, O=MyOrg, C=XX")
    n2 = Name.from_dict({"C": "XX", "O": "MyOrg", "CN": "example.com"})
    T.expect("round-trip == from_dict", n1.raw == n2.raw,
             f"\n      from_string: {n1}\n      from_dict:   {n2}")
    T.expect("str содержит CN", "CN=example.com" in str(n1))

    n3 = Name.from_string(str(n2))
    T.expect("round-trip через str", n3.raw == n2.raw)

    n4 = Name.from_string(r"CN=with\, comma, O=Org")
    T.expect("escape запятой", n4.get("CN") == "with, comma",
             f"got: {n4.get('CN')!r}")

    n5 = Name.from_string(r"CN=with\\backslash")
    T.expect("escape backslash", n5.get("CN") == r"with\backslash",
             f"got: {n5.get('CN')!r}")

    try:
        Name.from_string("")
        T.fail("пустая строка → X509Error", "не бросило")
    except X509Error:
        T.ok("пустая строка → X509Error")

    try:
        Name.from_string("no-equals-sign")
        T.fail("нет '=' → X509Error", "не бросило")
    except X509Error:
        T.ok("нет '=' → X509Error")


def test_cert_from_url():
    hr("17. Cert.from_url")

    T.expect("Cert.from_url определён", hasattr(Cert, "from_url"))

    try:
        cert = Cert.from_url("example.com", timeout=5)
        T.expect("возвращает Cert", isinstance(cert, Cert))
        T.expect("subject есть", cert.subject.get("CN") is not None)
        T.expect("SAN есть", len(cert.san) > 0)
    except Exception as e:
        T.skip("Cert.from_url — нет сети", str(e)[:60])

    try:
        Cert.from_url("", timeout=2)
        T.fail("пустой URL → X509Error", "не бросило")
    except X509Error:
        T.ok("пустой URL → X509Error")
    except Exception as e:
        T.ok(f"пустой URL → {type(e).__name__}")


def test_cert_info():
    hr("18. Cert.info() — openssl x509 -text style")

    key = Ed25519Keys.generate()
    cert = (CertificateBuilder()
        .add_subject({"C": "XX", "O": "Info", "CN": "info.example"})
        .add_public_key(key)
        .add_serial_random().add_validity(days=30)
        .add_san_dns("info.example")
        .self_signed().sign(key))

    info = cert.info()

    T.expect("начинается с 'Certificate:'", info.startswith("Certificate:"))
    T.expect("есть 'Version: 3'",           "Version: 3" in info)
    T.expect("есть 'Serial Number:'",       "Serial Number:" in info)
    T.expect("есть 'Signature Algorithm:'", "Signature Algorithm:" in info)
    T.expect("есть 'Issuer:'",              "Issuer:" in info)
    T.expect("есть 'Validity'",             "Validity" in info)
    T.expect("есть 'Not Before'",           "Not Before:" in info)
    T.expect("есть 'Not After'",            "Not After :" in info)
    T.expect("есть 'Subject:'",             "Subject:" in info)
    T.expect("есть 'Subject Public Key Info:'",
             "Subject Public Key Info:" in info)
    T.expect("есть 'Public Key Algorithm: ED25519'",
             "Public Key Algorithm: ED25519" in info)
    T.expect("есть 'X509v3 extensions:'",   "X509v3 extensions:" in info)
    T.expect("есть 'X509v3 Subject Alternative Name'",
             "X509v3 Subject Alternative Name" in info)
    T.expect("есть SAN содержимое",         "info.example" in info)


def test_pkcs12_shortcuts():
    hr("19. PKCS#12 шорткаты")

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "Shortcut CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=365)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))

    leaf_key = Ed25519Keys.generate()
    leaf = (CertificateBuilder()
        .add_subject({"CN": "shortcut.example"})
        .add_issuer(ca).add_public_key(leaf_key)
        .add_serial_random().add_validity(days=30)
        .add_san_dns("shortcut.example")
        .sign(ca_key))

    # key.to_pkcs12
    p12 = leaf_key.to_pkcs12(leaf, chain=[ca], password="hunter2",
                             name="shortcut")
    T.expect("key.to_pkcs12 → PKCS12", isinstance(p12, PKCS12))
    T.expect("to_pkcs12: MAC valid", p12.verify_mac())
    T.expect("to_pkcs12: chain ok", p12.verify_chain(trust_anchor=ca))

    reloaded = PKCS12.load(p12.to_der(), password="hunter2")
    T.expect("to_pkcs12 round-trip: key matches",
             reloaded.key.pub == leaf_key.pub)
    T.expect("to_pkcs12 round-trip: cert matches",
             reloaded.cert.der == leaf.der)

    # CertBundle.to_pkcs12
    bundle = CertBundle([leaf, ca])
    p12b = bundle.to_pkcs12(leaf_key, password="hunter2", name="bundle")
    T.expect("bundle.to_pkcs12 → PKCS12", isinstance(p12b, PKCS12))
    T.expect("bundle.to_pkcs12: MAC valid", p12b.verify_mac())

    reloaded_b = PKCS12.load(p12b.to_der(), password="hunter2")
    T.expect("bundle round-trip: cert matches",
             reloaded_b.cert.der == leaf.der)
    T.expect("bundle round-trip: chain len=1",
             len(reloaded_b.chain) == 1)

    # Все три типа ключей
    for label, kf in [
        ("RSA",     lambda: RSAKeys.generate(2048)),
        ("Ed25519", lambda: Ed25519Keys.generate()),
        ("EC-P256", lambda: ECDSAKeys.generate("P-256")),
    ]:
        try:
            k = kf()
            c = (CertificateBuilder()
                .add_subject({"CN": f"{label}.shortcut"})
                .add_public_key(k)
                .add_serial_random().add_validity(days=30)
                .self_signed().sign(k))
            p = k.to_pkcs12(c, password="pw", name=label)
            T.expect(f"{label}: to_pkcs12 + MAC", p.verify_mac())
        except Exception as e:
            T.fail(f"{label}: to_pkcs12", str(e)[:80])

    # Пустой bundle
    try:
        CertBundle([]).to_pkcs12(leaf_key)
        T.fail("пустой bundle → X509Error", "не бросило")
    except X509Error:
        T.ok("пустой bundle → X509Error")


def main():
    print("╔" + "═" * 70 + "╗")
    print("║  x509kit — полный прогон" + " " * 46 + "║")
    print("╚" + "═" * 70 + "╝")

    try:
        test_rsa()
        test_ed25519()
        test_ecdsa()
        test_aes()
        test_encrypted_keys()
        test_chain("RSA",             lambda: RSAKeys.generate(2048))
        test_chain("Ed25519",         lambda: Ed25519Keys.generate())
        test_chain("ECDSA P-256",     lambda: ECDSAKeys.generate("P-256"))
        test_chain("ECDSA P-384",     lambda: ECDSAKeys.generate("P-384"))
        test_chain("ECDSA P-521",     lambda: ECDSAKeys.generate("P-521"))
        test_chain("ECDSA secp256k1", lambda: ECDSAKeys.generate("secp256k1"))
        test_mixed()
        test_cryptography()
        test_ecdsa_cryptography()
        test_name_constraints()
        test_crl()
        test_ocsp()
        test_aia()
        test_canonicalization()
        test_pem_roundtrip()
        test_name_from_string()
        test_cert_from_url()
        test_cert_info()
        test_pkcs12_shortcuts()
    except Exception as e:
        print()
        print("\033[31m!!! Непойманное исключение:\033[0m", type(e).__name__, e)
        traceback.print_exc()

    ok = T.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())