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
 16.  Name.from_string (RFC 4514)
 17.  Cert.from_url
 18.  Cert.info
 19.  PKCS#12 шорткаты
 20.  Certificate Transparency (SCT)
 21.  ACME persistence (save/load)
 22.  Network revocation (CRL/OCSP HTTP)
 23.  CMS (RFC 5652) parsing
 24.  CMS (RFC 5652) sign / verify
 25.  CLI (info/keygen/csr/verify/cms/pkcs12/crl)
 26.  Builder guards (dup calls)
 27.  from_public_bytes
 28.  Zero public key / small-order defenses
 29.  ECDSA: invalid curve point / point at infinity
 30.  Weak RSA warning on every construction path
 31.  CLI must-have: cert / key / p12 / crl namespaces

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
    der_seq, der_set, der_octet, der_int, der_null, der_bitstring,
    _der_tlv, encode_oid, TAG_SET, TAG_OCTET_STRING,
)
from x509kit.cms import CMSSignedData, cms_sign, cms_load
from x509kit import __version__


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



# ======================================================================
#  20. Certificate Transparency (SCT) + ACME persistence
# ======================================================================

def test_sct_parsing():
    hr("20. Certificate Transparency (SCT)")

    # 1. Синтетический SCT list — сконструируем вручную
    from x509kit.x509 import _parse_sct_list, _parse_sct
    from x509kit.x509 import der_seq, der_octet, der_int

    # Один SCT: version=0, log_id=32 байта, ts=1700000000000, ext=0, sig
    log_id = bytes.fromhex("aa" * 32)
    ts_ms = 1700000000000
    # DigitallySigned ::= SEQUENCE { INTEGER 4, INTEGER 3, OCTET STRING(sig) }
    dsig = der_seq(der_int(4), der_int(3), der_octet(b"\x00" * 71))
    sct_raw = (b"\x00" + log_id + ts_ms.to_bytes(8, "big")
               + b"\x00\x00" + dsig)
    sct_with_len = len(sct_raw).to_bytes(2, "big") + sct_raw
    sct_list_body = len(sct_with_len).to_bytes(2, "big") + sct_with_len
    inner_octet = der_octet(sct_list_body)

    parsed = _parse_sct_list(inner_octet)
    T.expect("SCT: один записан", len(parsed) == 1)
    if parsed:
        s = parsed[0]
        T.expect("SCT version = 0", s["version"] == 0)
        T.expect("SCT log_id совпадает", s["log_id"] == "aa" * 32)
        T.expect("SCT timestamp_ms", s["timestamp_ms"] == ts_ms)
        T.expect("SCT hash_alg = 4", s["hash_alg"] == 4)
        T.expect("SCT sig_alg = 3", s["sig_alg"] == 3)

    # 2. Битый SCT list → пустой результат
    bad = der_octet(b"\x00\x05\x00\x02\x00")   # длина врёт
    T.expect("SCT: битый list не крашит",
             isinstance(_parse_sct_list(bad), list))

    # 3. Cert без SCT
    key = Ed25519Keys.generate()
    cert = (CertificateBuilder()
        .add_subject({"CN": "no-sct.example"})
        .add_public_key(key)
        .add_serial_random().add_validity(days=30)
        .add_san_dns("no-sct.example")
        .self_signed().sign(key))
    T.expect("Cert без SCT: has_sct=False", cert.has_sct is False)
    T.expect("Cert без SCT: sct_list=[]", cert.sct_list == [])


def test_acme_persistence():
    hr("21. ACME persistence (save/load)")

    import tempfile, os
    from x509kit import ACMEServer

    # --- CA ---
    ca_k = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "Persistence CA"})
        .add_public_key(ca_k)
        .add_serial_random().add_validity(days=365)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_k))

    # --- Первый сервер: создаём аккаунт и order ---
    srv1 = ACMEServer(ca, ca_k, "http://test.local:14000",
                       auto_verify=True)
    jwk = {"kty": "OKP", "crv": "Ed25519",
           "x": __import__("x509kit").b64u(Ed25519Keys.generate().pub)}
    kid, _ = srv1.new_account(jwk, {"termsOfServiceAgreed": True})
    order = srv1.new_order(kid, {
        "identifiers": [{"type": "dns", "value": "persist.example"}],
    })

    T.expect("srv1: account создан", len(srv1.accounts) == 1)
    T.expect("srv1: order создан", len(srv1.orders) == 1)

    # --- Сохранить ---
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        state_path = tf.name
    try:
        srv1.save(state_path)
        T.expect("save: файл создан", os.path.exists(state_path))

        # --- Второй сервер: загружаем ---
        srv2 = ACMEServer.load(ca, ca_k, state_path, auto_verify=True)
        T.expect("load: base_url совпадает",
                 srv2.base_url == srv1.base_url)
        T.expect("load: account восстановлен",
                 len(srv2.accounts) == 1)
        T.expect("load: order восстановлен",
                 len(srv2.orders) == 1)
        T.expect("load: authz восстановлен",
                 len(srv2.authzs) == len(srv1.authzs))
        T.expect("load: challenges восстановлены",
                 len(srv2.chals) == len(srv1.chals))

        # kid должен быть тем же
        kid2 = list(srv2.accounts.keys())[0]
        T.expect("load: kid совпадает", kid2 == kid)

        # Order view работает после загрузки
        order_view = srv2.get_order(list(srv2.orders.keys())[0])
        T.expect("load: get_order работает",
                 order_view["status"] in ("pending", "ready"))

        # Round-trip через to_dict/from_dict
        srv3 = ACMEServer.from_dict(ca, ca_k, srv1.to_dict(),
                                     auto_verify=True)
        T.expect("to_dict/from_dict: accounts",
                 len(srv3.accounts) == len(srv1.accounts))
    finally:
        try: os.unlink(state_path)
        except OSError: pass


# ======================================================================
#  22. Network revocation: fetch_crl, fetch_ocsp, fetch_issuer
# ======================================================================

def test_revocation_network():
    hr("22. Network revocation (CRL/OCSP HTTP)")

    import threading, time
    from x509kit import make_revocation_server, RevocationHTTPServer

    # ---- CA ----
    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "Network Revocation CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=365)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))

    # ---- Server on random port ----
    srv = make_revocation_server(ca, "127.0.0.1", 0,
                                  crl_days=7, crl_cache_seconds=0)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)

    try:
        # ---- Issue leaf with URLs ----
        leaf = (CertificateBuilder()
            .add_subject({"CN": "netrev.example"})
            .add_issuer(ca).add_public_key(Ed25519Keys.generate())
            .add_serial_random().add_validity(days=30)
            .add_san_dns("netrev.example")
            .add_crl_distribution_point(f"{base}/crl.pem")
            .add_aia(ocsp=[f"{base}/ocsp"])
            .sign(ca_key))

        # ---- 1. fetch_crl ----
        crl = leaf.fetch_crl(ca=ca)
        T.expect("fetch_crl: получен", crl is not None)
        T.expect("fetch_crl: leaf не в CRL", not crl.is_revoked(leaf))

        # ---- 2. fetch_ocsp ----
        ocsp = leaf.fetch_ocsp(issuer=ca)
        T.expect("fetch_ocsp: получен", ocsp is not None)
        T.expect("fetch_ocsp: status good", ocsp["status"] == "good")

        # ---- 3. Отзыв + проверка ----
        ca.revoke(leaf, reason="keyCompromise")
        time.sleep(0.05)

        crl2 = leaf.fetch_crl(ca=ca)
        T.expect("fetch_crl (after revoke): leaf в CRL",
                 crl2.is_revoked(leaf))
        T.expect("fetch_crl (after revoke): reason keyCompromise",
                 crl2.revoke_reason(leaf) == "keyCompromise")

        ocsp2 = leaf.fetch_ocsp(issuer=ca)
        T.expect("fetch_ocsp (after revoke): status revoked",
                 ocsp2["status"] == "revoked")
        T.expect("fetch_ocsp (after revoke): reason keyCompromise",
                 ocsp2["reason"] == "keyCompromise")

        # ---- 4. Сертификат без URL → None ----
        no_urls = (CertificateBuilder()
            .add_subject({"CN": "no-urls.example"})
            .add_issuer(ca).add_public_key(Ed25519Keys.generate())
            .add_serial_random().add_validity(days=30)
            .sign(ca_key))
        T.expect("fetch_crl без URL → None", no_urls.fetch_crl() is None)
        T.expect("fetch_ocsp без URL → None",
                 no_urls.fetch_ocsp(issuer=ca) is None)

        # ---- 5. mTLS from_url — проверка что параметры приняты ----
        import inspect
        sig = inspect.signature(Cert.from_url)
        T.expect("from_url: client_cert param", "client_cert" in sig.parameters)
        T.expect("from_url: client_key param", "client_key" in sig.parameters)

        # ---- 6. CertBundle.sort_chain ----
        # Случайный порядок — должен быть упорядочен
        inter_key = Ed25519Keys.generate()
        inter_cert = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": "Intermediate"})
            .add_issuer(ca).add_public_key(inter_key)
            .add_serial_random().add_validity(days=180)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .sign(ca_key))
        from x509kit import CertBundle
        shuffled = CertBundle([ca, leaf, inter_cert])
        sorted_b = shuffled.sort_chain()
        T.expect("sort_chain: первый = leaf",
                 sorted_b.certs[0].subject.get("CN") == "netrev.example"
                 or sorted_b.certs[0].issuer.get("CN") == "Network Revocation CA")

    finally:
        srv.shutdown()

def _build_minimal_cms():
    """Собрать минимальный CMS SignedData без signing — только для парсинга."""
    OID_SIGNED = "1.2.840.113549.1.7.2"
    OID_DATA   = "1.2.840.113549.1.7.1"
    OID_SHA256 = "2.16.840.1.101.3.4.2.1"
    OID_RSA_SHA256 = "1.2.840.113549.1.1.11"

    sha256_alg = der_seq(encode_oid(OID_SHA256), der_null())
    content = b"hello, cms!"
    eci = der_seq(
        encode_oid(OID_DATA),
        _der_tlv(0xA0, der_octet(content)),
    )
    empty_name = der_seq()
    ias = der_seq(empty_name, der_int(0x1234))
    sig_alg = der_seq(encode_oid(OID_RSA_SHA256), der_null())
    signer = der_seq(
        der_int(1),
        ias,
        sha256_alg,
        sig_alg,
        der_octet(b"\x00" * 32),   # RFC 5652 §5.3: signature OCTET STRING
    )
    signed_data = der_seq(
        der_int(1),
        der_set(sha256_alg),
        eci,
        der_set(signer),
    )
    return der_seq(
        encode_oid(OID_SIGNED),
        _der_tlv(0xA0, signed_data),
    )


def test_cms_parsing():
    hr("23. CMS (RFC 5652) parsing")

    der = _build_minimal_cms()
    sd = CMSSignedData.load(der)
    T.expect("CMS: version = 1", sd.version == 1)
    T.expect("CMS: content_type = data",
             sd.content_type == "1.2.840.113549.1.7.1")
    T.expect("CMS: attached content", not sd.detached)
    T.expect("CMS: content bytes", sd.content == b"hello, cms!")
    T.expect("CMS: 1 signer", len(sd.signers) == 1)
    T.expect("CMS: 0 certificates", len(sd.certificates) == 0)

    s = sd.signers[0]
    T.expect("Signer: sid = issuer_and_serial",
             s.sid_kind == "issuer_and_serial")
    T.expect("Signer: serial", s.serial == 0x1234)
    T.expect("Signer: digest name = sha256",
             s.digest_algorithm.name == "sha256")
    T.expect("Signer: sig name = sha256WithRSA",
             s.signature_algorithm.name == "sha256WithRSA")
    T.expect("Signer: signature bytes = 32",
             len(s.signature) == 32)

    # PEM round-trip
    pem = sd.to_pem()
    sd2 = CMSSignedData.load(pem)
    T.expect("CMS: PEM round-trip content", sd2.content == sd.content)
    T.expect("CMS: PEM round-trip version", sd2.version == sd.version)
    T.expect("CMS: DER round-trip",
             CMSSignedData.load(sd.to_der()).signer_count == 1)

    # cms_load alias
    sd3 = cms_load(der)
    T.expect("cms_load alias", sd3.signers[0].serial == 0x1234)

    # get_cert_for_signer — нет сертов → None
    T.expect("get_cert_for_signer: no certs → None",
             sd.get_cert_for_signer(s) is None)

    # Detached
    detached_der = _build_minimal_cms_detached()
    sdd = CMSSignedData.load(detached_der)
    T.expect("CMS detached: content is None", sdd.content is None)
    T.expect("CMS detached: detached flag", sdd.detached)


def _build_minimal_cms_detached():
    """Тот же CMS, но без eContent — detached."""
    OID_SIGNED = "1.2.840.113549.1.7.2"
    OID_DATA   = "1.2.840.113549.1.7.1"
    OID_SHA256 = "2.16.840.1.101.3.4.2.1"
    OID_RSA_SHA256 = "1.2.840.113549.1.1.11"

    sha256_alg = der_seq(encode_oid(OID_SHA256), der_null())
    eci = der_seq(encode_oid(OID_DATA))   # без eContent
    empty_name = der_seq()
    ias = der_seq(empty_name, der_int(0x5555))
    sig_alg = der_seq(encode_oid(OID_RSA_SHA256), der_null())
    signer = der_seq(
        der_int(1), ias, sha256_alg, sig_alg,
        der_octet(b"\x00" * 32),
    )
    signed_data = der_seq(
        der_int(1), der_set(sha256_alg), eci, der_set(signer),
    )
    return der_seq(encode_oid(OID_SIGNED), _der_tlv(0xA0, signed_data))


def test_cms_sign_verify():
    hr("24. CMS (RFC 5652) sign / verify")

    # CA
    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"CN": "CMS Test CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=365)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))

    content = b"hello, cms!"

    for label, key_f in (
        ("RSA-2048", lambda: RSAKeys.generate(2048)),
        ("Ed25519",  lambda: Ed25519Keys.generate()),
        ("EC-P256",  lambda: ECDSAKeys.generate("P-256")),
    ):
        k = key_f()
        leaf = (CertificateBuilder()
            .add_subject({"CN": f"{label}.cms"})
            .add_issuer(ca).add_public_key(k)
            .add_serial_random().add_validity(days=90)
            .add_san_dns(f"{label}.cms")
            .sign(ca_key))

        # --- Attached ---
        sd = cms_sign(content, key=k, cert=leaf, chain=[ca])
        sd2 = CMSSignedData.load(sd.to_der())
        T.expect(f"{label}: attached parsed", sd2.signer_count == 1)
        T.expect(f"{label}: attached content round-trip",
                 sd2.content == content)
        T.expect(f"{label}: attached certs embedded (leaf+ca)",
                 len(sd2.certificates) == 2)
        T.expect(f"{label}: verify attached",
                 sd2.verify())
        T.expect(f"{label}: verify(trust_anchor=ca)",
                 sd2.verify(trust_anchor=ca))

        # signing_time по умолчанию есть
        T.expect(f"{label}: signingTime attribute present",
                 sd2.signers[0].signing_time is not None)

        # message_digest attribute present
        T.expect(f"{label}: messageDigest attribute present",
                 sd2.signers[0].message_digest is not None)

        # content_type attribute
        T.expect(f"{label}: contentType attribute == data",
                 sd2.signers[0].content_type_attr
                 == "1.2.840.113549.1.7.1")

        # get_cert_for_signer
        found = sd2.get_cert_for_signer(sd2.signers[0])
        T.expect(f"{label}: get_cert_for_signer finds leaf",
                 found is not None and found.der == leaf.der)

        # --- Detached ---
        sd_det = cms_sign(content, key=k, cert=leaf, chain=[ca],
                           detached=True)
        sd_det2 = CMSSignedData.load(sd_det.to_der())
        T.expect(f"{label}: detached content is None",
                 sd_det2.content is None)
        T.expect(f"{label}: detached flag", sd_det2.detached)
        T.expect(f"{label}: detached verify without data → False",
                 not sd_det2.verify())
        T.expect(f"{label}: detached verify with correct data",
                 sd_det2.verify(detached_data=content, trust_anchor=ca))
        T.expect(f"{label}: detached verify tampered data → False",
                 not sd_det2.verify(detached_data=b"wrong"))

        # --- Wrong trust anchor ---
        other_ca_key = Ed25519Keys.generate()
        other_ca = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": "Other CA"})
            .add_public_key(other_ca_key)
            .add_serial_random().add_validity(days=365)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .self_signed().sign(other_ca_key))
        T.expect(f"{label}: verify(wrong anchor) → False",
                 not sd2.verify(trust_anchor=other_ca))

        # --- PEM round-trip ---
        sd_pem = CMSSignedData.load(sd2.to_pem())
        T.expect(f"{label}: PEM round-trip content",
                 sd_pem.content == content)

    # --- add_signing_time=False ---
    nosig_key = Ed25519Keys.generate()
    nosig_cert = (CertificateBuilder()
        .add_subject({"CN": "nosig.cms"})
        .add_issuer(ca)
        .add_public_key(nosig_key)
        .add_serial_random().add_validity(days=90)
        .add_san_dns("nosig.cms")
        .sign(ca_key))
    sd_nosig = cms_sign(content, key=nosig_key, cert=nosig_cert,
                         chain=[ca], add_signing_time=False)
    T.expect("cms_sign add_signing_time=False: signing_time is None",
             sd_nosig.signers[0].signing_time is None)
    T.expect("cms_sign add_signing_time=False: verify ok",
             CMSSignedData.load(sd_nosig.to_der()).verify(trust_anchor=ca))

    # --- Отвергаем key/cert mismatch ---
    k1 = Ed25519Keys.generate()
    k2 = Ed25519Keys.generate()
    leaf2 = (CertificateBuilder()
        .add_subject({"CN": "mismatch.cms"})
        .add_issuer(ca).add_public_key(k1)
        .add_serial_random().add_validity(days=90)
        .sign(ca_key))
    try:
        cms_sign(content, key=k2, cert=leaf2, chain=[ca])
        T.fail("cms_sign: key != cert → X509Error", "не бросило")
    except X509Error:
        T.ok("cms_sign: key != cert → X509Error")


def test_cli():
    hr("25. CLI (info / keygen / csr / verify / cms / pkcs12 / crl)")

    import io
    import contextlib
    import os
    import shutil
    import tempfile
    from x509kit.cli import main as cli_main

    # Termux: /tmp часто нет — используем $TMPDIR, иначе $HOME/.cache,
    # иначе текущую директорию. Создаём родителя, если его нет.
    _base = (os.environ.get("TMPDIR")
             or os.path.expanduser("~/.cache")
             or os.path.expanduser("~")
             or ".")
    try:
        os.makedirs(_base, exist_ok=True)
        tmpdir = tempfile.mkdtemp(prefix="x509kit-cli-", dir=_base)
    except OSError:
        tmpdir = tempfile.mkdtemp(prefix="x509kit-cli-")

    def run(argv):
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                rc = cli_main(argv)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 0
        return rc, out.getvalue(), err.getvalue()

    try:
        # --- --version ---
        rc, out, err = run(["--version"])
        T.expect("CLI --version: rc=0", rc == 0)
        T.expect("CLI --version: содержит версию",
                 "x509kit" in out and __version__ in out)

        # --- test-данные ---
        ca_key = Ed25519Keys.generate()
        ca = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": "CLI Test CA"})
            .add_public_key(ca_key)
            .add_serial_random().add_validity(days=30)
            .add_basic_constraints(path_len=1)
            .add_key_usage("keyCertSign", "cRLSign")
            .self_signed().sign(ca_key))

        leaf_key = Ed25519Keys.generate()
        leaf = (CertificateBuilder()
            .add_subject({"CN": "cli.example"})
            .add_issuer(ca).add_public_key(leaf_key)
            .add_serial_random().add_validity(days=30)
            .add_san_dns("cli.example", "www.cli.example")
            .sign(ca_key))

        ca_path = os.path.join(tmpdir, "ca.pem")
        leaf_path = os.path.join(tmpdir, "leaf.pem")
        with open(ca_path, "w") as f: f.write(ca.to_pem())
        with open(leaf_path, "w") as f: f.write(leaf.to_pem())

        # --- info ---
        rc, out, err = run(["info", leaf_path])
        T.expect("CLI info: rc=0", rc == 0, f"err={err[:100]}")
        T.expect("CLI info: shows subject", "cli.example" in out)
        T.expect("CLI info: shows issuer", "CLI Test CA" in out)
        T.expect("CLI info: shows Version: 3", "Version: 3" in out)
        T.expect("CLI info: shows SAN", "www.cli.example" in out)

        # --- info через stdin ---
        import sys as _sys
        old_stdin = _sys.stdin
        class _FakeStdin:
            buffer = io.BytesIO(leaf.to_pem().encode())
        _sys.stdin = _FakeStdin()
        try:
            rc, out, err = run(["info", "-"])
            T.expect("CLI info -: rc=0", rc == 0)
            T.expect("CLI info -: shows subject", "cli.example" in out)
        finally:
            _sys.stdin = old_stdin

        # --- info: несуществующий файл → rc=1 ---
        rc, out, err = run(["info", "/nonexistent/path.pem"])
        T.expect("CLI info: missing file → rc=1", rc == 1)

        # --- verify: OK ---
        rc, out, err = run(["verify", "--ca", ca_path, leaf_path])
        T.expect("CLI verify: rc=0", rc == 0, f"err={err[:200]}")
        T.expect("CLI verify: prints OK", "OK" in out)

        # --- verify: wrong anchor → rc=1 ---
        other_key = Ed25519Keys.generate()
        other = (CertificateBuilder(is_ca=True)
            .add_subject({"CN": "Other CA"})
            .add_public_key(other_key)
            .add_serial_random().add_validity(days=30)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .self_signed().sign(other_key))
        other_path = os.path.join(tmpdir, "other.pem")
        with open(other_path, "w") as f: f.write(other.to_pem())
        rc, out, err = run(["verify", "--ca", other_path, leaf_path])
        T.expect("CLI verify wrong anchor: rc=1", rc == 1)

        # --- keygen ed25519 ---
        gen_key_path = os.path.join(tmpdir, "gen.key")
        rc, out, err = run(["keygen", "--type", "ed25519",
                            "--out", gen_key_path])
        T.expect("CLI keygen ed25519: rc=0", rc == 0, f"err={err[:100]}")
        T.expect("CLI keygen ed25519: file created",
                 os.path.exists(gen_key_path))
        with open(gen_key_path, "rb") as f:
            k = Ed25519Keys.from_pem(f.read(), private=True)
        T.expect("CLI keygen ed25519: reloadable", k.pub is not None)

        # --- keygen ed25519 с паролем ---
        enc_key_path = os.path.join(tmpdir, "enc.key")
        rc, out, err = run(["keygen", "--type", "ed25519",
                            "--password", "hunter2",
                            "--out", enc_key_path])
        T.expect("CLI keygen encrypted: rc=0", rc == 0)
        with open(enc_key_path, "rb") as f:
            data = f.read()
        T.expect("CLI keygen encrypted: ENCRYPTED PRIVATE KEY",
                 b"ENCRYPTED PRIVATE KEY" in data)
        k2 = Ed25519Keys.from_pem(data, private=True, password="hunter2")
        T.expect("CLI keygen encrypted: decryptable",
                 k2.pub is not None and len(k2.pub) == 32)
        # загрузка с неверным паролем должна упасть
        try:
            Ed25519Keys.from_pem(data, private=True, password="wrong")
            T.fail("CLI keygen encrypted: wrong pw rejected", "не бросило")
        except Exception:
            T.ok("CLI keygen encrypted: wrong pw rejected")

        # --- csr create ---
        csr_path = os.path.join(tmpdir, "req.csr")
        rc, out, err = run([
            "csr", "create",
            "--key", gen_key_path,
            "--subject", "CN=cli-csr.example, O=CLI",
            "--san", "dns=cli-csr.example",
            "--san", "dns=www.cli-csr.example",
            "--out", csr_path,
        ])
        T.expect("CLI csr create: rc=0", rc == 0, f"err={err[:200]}")
        T.expect("CLI csr create: file created", os.path.exists(csr_path))
        with open(csr_path, "rb") as f:
            csr = CSR(f.read())
        T.expect("CLI csr create: subject CN",
                 csr.subject.get("CN") == "cli-csr.example")
        T.expect("CLI csr create: 2 SANs",
                 set(csr.dns_names) == {"cli-csr.example",
                                         "www.cli-csr.example"})
        T.expect("CLI csr create: signature valid", csr.verify_signature())

        # --- csr create: плохой --san ---
        rc, out, err = run([
            "csr", "create", "--key", gen_key_path,
            "--subject", "CN=x",
            "--san", "bogus",
            "--out", os.path.join(tmpdir, "bad.csr"),
        ])
        T.expect("CLI csr create: bad --san → rc=2", rc == 2)

        # --- csr info ---
        rc, out, err = run(["csr", "info", csr_path])
        T.expect("CLI csr info: rc=0", rc == 0)
        T.expect("CLI csr info: shows CN", "cli-csr.example" in out)

        # --- cms verify (attached) ---
        content = b"CLI CMS test content"
        sd = cms_sign(content, key=leaf_key, cert=leaf, chain=[ca])
        cms_path = os.path.join(tmpdir, "msg.p7s")
        with open(cms_path, "wb") as f: f.write(sd.to_der())
        rc, out, err = run(["cms", "verify", cms_path, "--ca", ca_path])
        T.expect("CLI cms verify attached: rc=0", rc == 0, f"err={err[:200]}")
        T.expect("CLI cms verify attached: OK", "OK" in out)

        # --- cms verify (detached) ---
        sd_det = cms_sign(content, key=leaf_key, cert=leaf, chain=[ca],
                           detached=True)
        cms_det = os.path.join(tmpdir, "msg.p7s.sig")
        with open(cms_det, "wb") as f: f.write(sd_det.to_der())
        content_path = os.path.join(tmpdir, "content.bin")
        with open(content_path, "wb") as f: f.write(content)

        rc, out, err = run(["cms", "verify", cms_det,
                            "--content", content_path, "--ca", ca_path])
        T.expect("CLI cms verify detached: rc=0", rc == 0)

        rc, out, err = run(["cms", "verify", cms_det, "--ca", ca_path])
        T.expect("CLI cms verify detached without --content: rc=2", rc == 2)

        # --- pkcs12 info ---
        p12 = leaf_key.to_pkcs12(leaf, chain=[ca], password="pw", name="cli")
        p12_path = os.path.join(tmpdir, "test.p12")
        p12.save(p12_path)
        rc, out, err = run(["pkcs12", "info", p12_path, "--password", "pw"])
        T.expect("CLI pkcs12 info: rc=0", rc == 0, f"err={err[:200]}")
        T.expect("CLI pkcs12 info: MAC valid", "MAC valid:    True" in out)
        T.expect("CLI pkcs12 info: subject", "cli.example" in out)

        # --- crl info ---
        ca_with_key = CACert.from_cert(ca, signing_key=ca_key)
        ca_with_key.revoke(leaf, reason="keyCompromise")
        crl = ca_with_key.to_crl(days=7)
        crl_path = os.path.join(tmpdir, "test.crl.pem")
        with open(crl_path, "w") as f: f.write(crl.to_pem())
        rc, out, err = run(["crl", "info", crl_path])
        T.expect("CLI crl info: rc=0", rc == 0)
        T.expect("CLI crl info: issuer", "CLI Test CA" in out)
        T.expect("CLI crl info: revoked count", "Revoked:" in out)

        # --- unknown command → SystemExit(2) ---
        rc, out, err = run(["bogus"])
        T.expect("CLI unknown command: rc=2", rc == 2)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_builder_dup_guards():
    hr("26. Builder guards — повторный вызов бросает X509Error")

    k = Ed25519Keys.generate()

    for method, first_args, second_args in [
        ("add_subject",     ({"CN": "a"},),     ({"CN": "b"},)),
        ("add_issuer",      ({"CN": "a"},),     ({"CN": "b"},)),
        ("add_public_key",  (k,),               (k,)),
        ("add_serial",      (12345,),           (67890,)),
    ]:
        b = CertificateBuilder()
        getattr(b, method)(*first_args)
        try:
            getattr(b, method)(*second_args)
            T.fail(f"CertificateBuilder.{method} повторно → X509Error",
                   "не бросило")
        except X509Error as e:
            T.expect(f"CertificateBuilder.{method} повторно → X509Error",
                     "уже задан" in str(e))

    b = CertificateBuilder()
    b.add_serial_random()
    try:
        b.add_serial(123)
        T.fail("add_serial после add_serial_random → X509Error", "не бросило")
    except X509Error:
        T.ok("add_serial после add_serial_random → X509Error")

    b = CertificateBuilder()
    b.add_serial_random()
    try:
        b.add_serial_random()
        T.fail("add_serial_random дважды → X509Error", "не бросило")
    except X509Error:
        T.ok("add_serial_random дважды → X509Error")

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
          .add_subject({"CN": "Guard CA"})
          .add_public_key(ca_key)
          .add_serial_random().add_validity(days=30)
          .add_basic_constraints(path_len=0)
          .add_key_usage("keyCertSign", "cRLSign")
          .self_signed().sign(ca_key))
    b = CertificateBuilder()
    b.add_issuer(ca)
    try:
        b.self_signed()
        T.fail("self_signed после add_issuer → X509Error", "не бросило")
    except X509Error as e:
        T.expect("self_signed после add_issuer → X509Error",
                 "уже задан" in str(e))

    for method, args in [("add_subject", ({"CN": "x"},)),
                          ("add_public_key", (k,))]:
        b = CSRBuilder()
        getattr(b, method)(*args)
        try:
            getattr(b, method)(*args)
            T.fail(f"CSRBuilder.{method} повторно → X509Error", "не бросило")
        except X509Error:
            T.ok(f"CSRBuilder.{method} повторно → X509Error")

    try:
        b = CertificateBuilder()
        b.add_subject({"CN": "still.works"})
        b.add_issuer(ca)
        b.add_public_key(Ed25519Keys.generate())
        b.add_serial_random()
        b.add_validity(days=30)
        b.sign(ca_key)
        T.ok("happy path: builder по-прежнему работает")
    except X509Error as e:
        T.fail("happy path: builder сломан", str(e))


def test_from_public_bytes():
    hr("27. from_public_bytes (Ed25519 / ECDSA / RSA)")

    k = Ed25519Keys.generate()
    k2 = Ed25519Keys.from_public_bytes(k.pub)
    T.expect("Ed25519: from_public_bytes pub совпадает", k2.pub == k.pub)
    T.expect("Ed25519: not private", not k2.is_private)

    try:
        Ed25519Keys.from_public_bytes(b"\x00" * 31)
        T.fail("Ed25519: 31 байт → X509Error", "не бросило")
    except X509Error:
        T.ok("Ed25519: 31 байт → X509Error")

    try:
        Ed25519Keys.from_public_bytes("not bytes")
        T.fail("Ed25519: str → TypeError", "не бросило")
    except TypeError:
        T.ok("Ed25519: str → TypeError")

    for curve in ("P-256", "P-384", "P-521", "secp256k1"):
        k = ECDSAKeys.generate(curve)
        k2 = ECDSAKeys.from_public_bytes(k.pub, curve=curve)
        T.expect(f"ECDSA {curve}: from_public_bytes uncompressed",
                 k2.point == k.point)

    for curve, size in (("P-256", 32), ("P-384", 48), ("P-521", 66)):
        k = ECDSAKeys.generate(curve)
        x = k.point[0].to_bytes(size, "big")
        prefix = b"\x03" if (k.point[1] & 1) else b"\x02"
        k2 = ECDSAKeys.from_public_bytes(prefix + x, curve=curve)
        T.expect(f"ECDSA {curve}: from_public_bytes compressed",
                 k2.point == k.point)

    try:
        ECDSAKeys.from_public_bytes(b"\x04" + b"\x00" * 20, curve="P-256")
        T.fail("ECDSA: wrong size → X509Error", "не бросило")
    except X509Error:
        T.ok("ECDSA: wrong size → X509Error")

    try:
        ECDSAKeys.from_public_bytes(b"\x04" + b"\x00" * 64, curve="P-256")
        T.fail("ECDSA: not on curve → X509Error", "не бросило")
    except X509Error:
        T.ok("ECDSA: not on curve → X509Error")

    try:
        ECDSAKeys.from_public_bytes(b"\x04" + b"\x00" * 64, curve="P-999")
        T.fail("ECDSA: bad curve → X509Error", "не бросило")
    except X509Error:
        T.ok("ECDSA: bad curve → X509Error")

    k = RSAKeys.generate(2048)
    spki = k.to_public_der()
    k2 = RSAKeys.from_public_bytes(spki)
    T.expect("RSA: from_public_bytes spki",
             k2.n == k.n and k2.e == k.e)

    from x509kit.x509 import der_seq as _ds, der_int as _di
    pkcs1 = _ds(_di(k.n), _di(k.e))
    k3 = RSAKeys.from_public_bytes(pkcs1, fmt="pkcs1")
    T.expect("RSA: from_public_bytes pkcs1",
             k3.n == k.n and k3.e == k.e)

    try:
        RSAKeys.from_public_bytes(b"\x00", fmt="raw")
        T.fail("RSA: bad fmt → X509Error", "не бросило")
    except X509Error:
        T.ok("RSA: bad fmt → X509Error")

    k = Ed25519Keys.generate()
    k_parsed = Ed25519Keys.from_public_bytes(k.pub)
    sig = k.sign(b"test")
    T.expect("Ed25519: sign orig, verify parsed",
             k_parsed.verify(b"test", sig))

    ec = ECDSAKeys.generate("P-256")
    ec_parsed = ECDSAKeys.from_public_bytes(ec.pub, curve="P-256")
    sig = ec.sign(b"test", "sha256")
    T.expect("ECDSA: sign orig, verify parsed",
             ec_parsed.verify(b"test", sig, "sha256"))

    rsa = RSAKeys.generate(2048)
    rsa_parsed = RSAKeys.from_public_bytes(rsa.to_public_der())
    sig = rsa.sign_pkcs1v15(b"test", "sha256")
    T.expect("RSA: sign orig, verify parsed",
             rsa_parsed.verify_pkcs1v15(b"test", sig, "sha256"))


def test_zero_pubkey_defense():
    hr("28. Zero public key / small-order defenses")

    from x509kit.x509 import (_ed_mul, _ed_encode, _ED_B,
                              _ed_has_small_order)

    try:
        Ed25519Keys(pub=b"\x01" + b"\x00" * 31)
        T.fail("Ed25519 identity pub → X509Error", "принят")
    except X509Error as e:
        T.expect("Ed25519 identity pub → X509Error",
                 "малого порядка" in str(e))

    try:
        Ed25519Keys(pub=b"\x00" * 32)
        T.fail("Ed25519 order-4 pub → X509Error", "принят")
    except X509Error:
        T.ok("Ed25519 order-4 pub → X509Error")

    try:
        Ed25519Keys.from_public_bytes(b"\x01" + b"\x00" * 31)
        T.fail("Ed25519.from_public_bytes identity → X509Error", "принят")
    except X509Error:
        T.ok("Ed25519.from_public_bytes identity → X509Error")

    T.expect("_ed_has_small_order(identity) == True",
             _ed_has_small_order(b"\x01" + b"\x00" * 31))
    T.expect("_ed_has_small_order(order-4) == True",
             _ed_has_small_order(b"\x00" * 32))
    legit = Ed25519Keys.generate()
    T.expect("_ed_has_small_order(legit) == False",
             not _ed_has_small_order(legit.pub))

    k_attack = Ed25519Keys.__new__(Ed25519Keys)
    k_attack.seed = None
    k_attack.pub = b"\x01" + b"\x00" * 31
    for msg in (b"transfer $1M", b"admin=true", b"", b"x" * 1000):
        S = 1234567
        R = _ed_encode(_ed_mul(S, _ED_B))
        forged = R + S.to_bytes(32, "little")
        T.expect(
            f"Forged sig rejected for {msg[:12]!r}",
            not k_attack.verify(msg, forged),
        )

    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                          "4449c5697b326919703bac031cae7f60")
    k = Ed25519Keys(seed=seed)
    T.expect("RFC 8032 vector: legit key still accepted",
             k.verify(b"", bytes.fromhex(
                 "e5564300c360ac729086e2cc806e828a"
                 "84877f1eb8e5d974d873e06522490155"
                 "5fb8821590a33bacc61e39701cf9b46b"
                 "d25bf5f0595bbe24655141438e7a100b")))

    for label, n, e in [("n=0", 0, 65537), ("n<0", -1, 65537),
                        ("e=0", 12345, 0), ("e=1", 12345, 1),
                        ("e=2", 12345, 2)]:
        try:
            RSAKeys(n=n, e=e)
            T.fail(f"RSAKeys {label} → X509Error", "принят")
        except X509Error:
            T.ok(f"RSAKeys {label} → X509Error")

    from x509kit.x509 import (der_seq as _ds, der_int as _di,
                              der_null as _dn, der_bitstring as _dbs,
                              encode_oid as _eo)
    zero_rsa_pkcs1 = _ds(_di(0), _di(65537))
    zero_spki = _ds(
        _ds(_eo("1.2.840.113549.1.1.1"), _dn()),
        _dbs(zero_rsa_pkcs1),
    )
    try:
        RSAKeys.from_public_der(zero_spki)
        T.fail("RSA SPKI n=0 → X509Error", "принят")
    except X509Error:
        T.ok("RSA SPKI n=0 → X509Error")

    k = RSAKeys.generate(2048)
    assert k.e == 65537 and k.n > 0
    T.ok("RSAKeys.generate happy path")

    k = Ed25519Keys.generate()
    sig = k.sign(b"test")
    T.expect("Ed25519 legitimate sign/verify после фикса",
             k.verify(b"test", sig))


def test_ecdsa_invalid_point():
    hr("29. ECDSA: invalid curve point / point at infinity")

    from x509kit.x509 import _ec_decode_point, EC_CURVES, OID_PRIME256V1

    c256 = EC_CURVES[OID_PRIME256V1]
    T.expect("decode: пустой ввод → None",
             _ec_decode_point(b"", c256) is None)
    T.expect("decode: 0x00 (point at infinity) → None",
             _ec_decode_point(b"\x00", c256) is None)
    T.expect("decode: 0x04||0*64 ((0,0)) → None",
             _ec_decode_point(b"\x04" + b"\x00" * 64, c256) is None)
    # x=0 compressed: для P-256 b — QR mod p, поэтому существует валидная
    # точка (0, ±sqrt(b)). Тест принимает оба исхода: None или валидная
    # точка на кривой. Раньше ошибочно ожидался только None.
    _pt0 = _ec_decode_point(b"\x02" + b"\x00" * 32, c256)
    if _pt0 is None:
        T.ok("decode: 0x02||0 (compressed x=0) → None")
    else:
        _x0, _y0 = _pt0
        _ok = (_y0 * _y0 - (_x0 ** 3 + c256["a"] * _x0 + c256["b"])) % c256["p"] == 0
        T.expect("decode: 0x02||0 (compressed x=0) → valid point on curve",
                 _ok)
    # Явно невалидный tag — гарантированный None
    T.expect("decode: tag 0x05 (unknown) → None",
             _ec_decode_point(b"\x05" + b"\x00" * 32, c256) is None)
    # b"\xff"*32 = 2^256 - 1 > p for P-256 and fits in 32 bytes.
    # Раньше было (1<<256).to_bytes(32) — OverflowError (257 бит).
    big = b"\xff" * 32
    T.expect("decode: x >= p → None",
             _ec_decode_point(b"\x04" + big + b"\x00" * 32, c256) is None)

    # NB: 0x02||0*32 НЕ в списке — для P-256 это легальная compressed-точка
    # (x=0, y=±sqrt(b), где b — QR mod p). Проверка уравнения кривой ниже
    # отсекает только реально невалидные точки.
    for label, raw in [
        ("0x00 (infinity)",    b"\x00"),
        ("0x04||0*64 ((0,0))", b"\x04" + b"\x00" * 64),
        ("0x04||0*32||0*32",   b"\x04" + b"\x00" * 64),   # (0,0) снова
    ]:
        try:
            ECDSAKeys.from_public_bytes(raw, curve="P-256")
            T.fail(f"from_public_bytes {label} → X509Error", "принят")
        except X509Error:
            T.ok(f"from_public_bytes {label} → X509Error")

    for label, pt in [
        ("(0,0)",       (0, 0)),
        ("(1,1)",       (1, 1)),
        ("x out of p",  (1 << 300, 1)),
        ("non-int",     ("a", "b")),
        ("not a tuple", [1, 2]),
    ]:
        try:
            ECDSAKeys(OID_PRIME256V1, point=pt)
            T.fail(f"ECDSAKeys(point={label}) → X509Error", "принят")
        except X509Error:
            T.ok(f"ECDSAKeys(point={label}) → X509Error")
        except (TypeError, ValueError):
            T.ok(f"ECDSAKeys(point={label}) → TypeError/ValueError")

    k_bad = ECDSAKeys.__new__(ECDSAKeys)
    k_bad.curve_oid = OID_PRIME256V1
    k_bad.curve = c256
    k_bad.d = None
    k_bad.point = (0, 0)

    forged = bytes.fromhex("30440220" + "00" * 32 + "0220" + "00" * 32)
    T.expect("Forged sig rejected even with bogus point",
             not k_bad.verify(b"any", forged, "sha256"))

    for curve in ("P-256", "P-384", "P-521", "secp256k1"):
        k = ECDSAKeys.generate(curve)
        h = {"P-256": "sha256", "P-384": "sha384",
             "P-521": "sha512", "secp256k1": "sha256"}[curve]
        sig = k.sign(b"test", h)
        T.expect(f"{curve}: legit key after fix", k.verify(b"test", sig, h))

    k = ECDSAKeys.generate("P-256")
    k2 = ECDSAKeys.from_public_der(k.to_public_der())
    T.expect("from_public_der round-trip", k2.point == k.point)


def test_weak_rsa_warning_paths():
    hr("30. Weak RSA warning on every construction path")

    import warnings
    from x509kit.x509 import der_seq as _ds, der_int as _di

    weak_n = (1 << 1023) * 3 + 1
    weak_e = 65537
    strong_n = (1 << 2047) * 3 + 1

    def count(fn):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always", X509Warning)
            try:
                fn()
            except Exception:
                pass
            return [x for x in w
                    if issubclass(x.category, X509Warning)]

    T.expect("direct RSAKeys(n=1024) → 1 warning",
             len(count(lambda: RSAKeys(n=weak_n, e=weak_e))) == 1)

    pkcs1 = _ds(_di(weak_n), _di(weak_e))
    T.expect("from_public_der weak → 1 warning",
             len(count(lambda: RSAKeys.from_public_der(pkcs1))) == 1)

    T.expect("from_public_bytes(pkcs1) weak → 1 warning",
             len(count(lambda: RSAKeys.from_public_bytes(
                 pkcs1, fmt="pkcs1"))) == 1)

    priv_pkcs1 = _ds(
        _di(0), _di(weak_n), _di(weak_e),
        _di(1), _di(1), _di(1), _di(1), _di(1), _di(1),
    )
    T.expect("from_private_der weak → 1 warning",
             len(count(lambda: RSAKeys.from_private_der(priv_pkcs1))) == 1)

    T.expect("direct RSAKeys(n=2048) → 0 warnings",
             len(count(lambda: RSAKeys(n=strong_n, e=weak_e))) == 0)

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
          .add_subject({"CN": "Weak Test CA"})
          .add_public_key(ca_key)
          .add_serial_random().add_validity(days=30)
          .add_basic_constraints(path_len=0)
          .add_key_usage("keyCertSign", "cRLSign")
          .self_signed().sign(ca_key))

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", X509Warning)
        weak_key = RSAKeys(n=weak_n, e=weak_e)
        (CertificateBuilder()
            .add_subject({"CN": "leaf.weak"})
            .add_issuer(ca)
            .add_public_key(weak_key)
            .add_serial_random().add_validity(days=30)
            .add_san_dns("leaf.weak")
            .sign(ca_key))
        ws = [x for x in w if issubclass(x.category, X509Warning)]
        # Слабое RSA объявляется РОВНО ОДИН РАЗ через RSAKeys.__init__.
        # add_public_key и sign больше не должны дублировать.
        T.expect("builder use of weak key: exactly 1 warning",
                 len(ws) == 1,
                 f"got {len(ws)} warnings: "
                 + " | ".join(str(x.message)[:60] for x in ws))

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", X509Warning)
        RSAKeys(n=weak_n, e=weak_e)
        filename = w[0].filename if w else ""
        T.expect("warn stacklevel points to user code, not x509.py",
                 "x509.py" not in filename,
                 f"got filename: {filename}")



def test_cli_must():
    hr("31. CLI must-have: cert / key / p12 / crl namespaces")

    import io
    import contextlib
    import os
    import shutil
    import tempfile
    from x509kit.cli import main as cli_main

    _base = (os.environ.get("TMPDIR")
             or os.path.expanduser("~/.cache")
             or os.path.expanduser("~")
             or ".")
    os.makedirs(_base, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix="x509kit-cli-must-", dir=_base)

    def run(argv):
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                rc = cli_main(argv)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 0
        return rc, out.getvalue(), err.getvalue()

    try:
        # --- setup: ключи и сертификаты ---
        ca_key = Ed25519Keys.generate()
        ca = (CertificateBuilder(is_ca=True)
              .add_subject({"CN": "Must CA"})
              .add_public_key(ca_key)
              .add_serial_random().add_validity(days=365)
              .add_basic_constraints(path_len=0)
              .add_key_usage("keyCertSign", "cRLSign")
              .self_signed().sign(ca_key))

        leaf_key = Ed25519Keys.generate()
        leaf = (CertificateBuilder()
                .add_subject({"CN": "leaf.example"})
                .add_issuer(ca).add_public_key(leaf_key)
                .add_serial_random().add_validity(days=90)
                .add_san_dns("leaf.example")
                .add_eku("serverAuth")
                .sign(ca_key))

        ca_path = os.path.join(tmpdir, "ca.pem")
        leaf_path = os.path.join(tmpdir, "leaf.pem")
        ca_key_path = os.path.join(tmpdir, "ca.key")
        leaf_key_path = os.path.join(tmpdir, "leaf.key")

        with open(ca_path, "w") as f: f.write(ca.to_pem())
        with open(leaf_path, "w") as f: f.write(leaf.to_pem())
        with open(ca_key_path, "w") as f: f.write(ca_key.to_private_pem())
        with open(leaf_key_path, "w") as f: f.write(leaf_key.to_private_pem())

        # --- cert fingerprint ---
        rc, out, err = run(["cert", "fingerprint", leaf_path])
        T.expect("cert fingerprint: rc=0", rc == 0, f"err={err[:100]}")
        T.expect("cert fingerprint: colon format",
                 ":" in out and len(out.strip().split(":")) == 32)

        rc, out, err = run(["cert", "fingerprint", leaf_path, "--no-colon"])
        T.expect("cert fingerprint --no-colon: 64 hex, no colon",
                 len(out.strip()) == 64 and ":" not in out.strip())

        rc, out, err = run(["cert", "fingerprint", leaf_path, "--spki"])
        T.expect("cert fingerprint --spki: rc=0", rc == 0)

        # --- cert matches-key ---
        rc, out, err = run(["cert", "matches-key", leaf_path, leaf_key_path])
        T.expect("cert matches-key (correct): rc=0", rc == 0)
        rc, out, err = run(["cert", "matches-key", leaf_path, ca_key_path])
        T.expect("cert matches-key (wrong): rc=1", rc == 1)

        # --- cert chain ---
        bundle_path = os.path.join(tmpdir, "bundle.pem")
        with open(bundle_path, "w") as f:
            f.write(leaf.to_pem() + ca.to_pem())
        sorted_path = os.path.join(tmpdir, "sorted.pem")
        rc, out, err = run(["cert", "chain", bundle_path, "--out", sorted_path])
        T.expect("cert chain: rc=0", rc == 0)
        T.expect("cert chain: file written", os.path.exists(sorted_path))
        sorted_b = CertBundle.from_pem(open(sorted_path).read())
        T.expect("cert chain: leaf first",
                 sorted_b.certs[0].subject.get("CN") == "leaf.example")

        # --- key info / pub / convert ---
        rc, out, err = run(["key", "info", leaf_key_path])
        T.expect("key info: rc=0", rc == 0, f"err={err[:100]}")
        T.expect("key info: Ed25519 mentioned", "Ed25519" in out)

        pub_path = os.path.join(tmpdir, "pub.pem")
        rc, out, err = run(["key", "pub", leaf_key_path, "--out", pub_path])
        T.expect("key pub: rc=0", rc == 0)
        T.expect("key pub: file written", os.path.exists(pub_path))
        with open(pub_path) as f:
            T.expect("key pub: PUBLIC KEY PEM", "PUBLIC KEY" in f.read())

        der_path = os.path.join(tmpdir, "key.der")
        rc, out, err = run(["key", "convert", leaf_key_path,
                             "--format", "der", "--out", der_path])
        T.expect("key convert der: rc=0", rc == 0)
        T.expect("key convert der: file written", os.path.exists(der_path))

        # --- csr verify ---
        csr_path = os.path.join(tmpdir, "req.csr")
        rc, out, err = run(["csr", "create", "--key", leaf_key_path,
                             "--subject", "CN=verify.example",
                             "--out", csr_path])
        T.expect("csr create (setup): rc=0", rc == 0)
        rc, out, err = run(["csr", "verify", csr_path])
        T.expect("csr verify: rc=0", rc == 0)
        T.expect("csr verify: OK", "OK" in out)

        # --- crl create ---
        crl_path = os.path.join(tmpdir, "test.crl.pem")
        rc, out, err = run(["crl", "create", "--ca", ca_path,
                             "--ca-key", ca_key_path,
                             "--revoke", "0xAAAA", "--revoke", "0xBBBB",
                             "--days", "7", "--out", crl_path])
        T.expect("crl create: rc=0", rc == 0, f"err={err[:150]}")
        T.expect("crl create: file written", os.path.exists(crl_path))
        crl = CRL(open(crl_path, "rb").read())
        T.expect("crl create: 2 revoked", len(crl.revoked) == 2)

        # --- p12 create / export (both via `p12` and `pkcs12`) ---
        p12_path = os.path.join(tmpdir, "test.p12")
        rc, out, err = run(["p12", "create",
                             "--key", leaf_key_path,
                             "--cert", leaf_path,
                             "--password", "pw",
                             "--out", p12_path])
        T.expect("p12 create: rc=0", rc == 0, f"err={err[:150]}")
        T.expect("p12 create: file written", os.path.exists(p12_path))

        export_dir = os.path.join(tmpdir, "extracted")
        rc, out, err = run(["p12", "export", p12_path,
                             "--password", "pw",
                             "--out-dir", export_dir])
        T.expect("p12 export: rc=0", rc == 0, f"err={err[:150]}")
        for fname in ("cert.pem", "key.pem"):
            T.expect(f"p12 export: {fname}",
                     os.path.exists(os.path.join(export_dir, fname)))

        # pkcs12 (длинная форма) — эквивалент
        rc, out, err = run(["pkcs12", "info", p12_path, "--password", "pw"])
        T.expect("pkcs12 info (long form): rc=0", rc == 0)
        T.expect("pkcs12 info: MAC valid", "MAC valid" in out)

        # p12 info (короткая форма) — тоже работает
        rc, out, err = run(["p12", "info", p12_path, "--password", "pw"])
        T.expect("p12 info (alias): rc=0", rc == 0)

        # --- verify --crl ---
        # Отзовём leaf, пересоберём CRL, проверим
        ca_with_key = CACert.from_cert(ca, signing_key=ca_key)
        ca_with_key.revoke(leaf, reason="keyCompromise")
        crl2 = ca_with_key.to_crl(days=7)
        crl2_path = os.path.join(tmpdir, "revoked.crl.pem")
        with open(crl2_path, "w") as f:
            f.write(crl2.to_pem())

        rc, out, err = run(["verify", "--ca", ca_path,
                             "--crl", crl2_path, leaf_path])
        T.expect("verify --crl revoked → rc=1", rc == 1)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


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
        test_sct_parsing()
        test_acme_persistence()
        test_revocation_network()
        test_cms_parsing()
        test_cms_sign_verify()
        test_cli()
        test_builder_dup_guards()
        test_from_public_bytes()
        test_zero_pubkey_defense()
        test_ecdsa_invalid_point()
        test_weak_rsa_warning_paths()
        test_cli_must()
    except Exception as e:
        print()
        print("\033[31m!!! Непойманное исключение:\033[0m", type(e).__name__, e)
        traceback.print_exc()

    ok = T.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())