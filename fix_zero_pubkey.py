from pathlib import Path

def edit(path, old, new, label, required=True):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    if old not in s:
        print(f"{'FAIL' if required else 'SKIP'}: {path} — {label}")
        return False
    p.write_text(s.replace(old, new, 1), encoding="utf-8")
    print(f"OK: {path} — {label}")
    return True


# ==================================================================
# 1. Helper: _ed_is_identity + _ed_has_small_order
# ==================================================================
edit(
    "src/x509kit/x509.py",
    '''def _ed_clamp(h):''',
    '''def _ed_is_identity(P):
    """P = (X, Y, Z, T) в расширенных координатах — это identity?

    Projectively, (X:Y:Z:T) представляет (X/Z, Y/Z). Identity = (0, 1).
    Значит identity ⇔ X ≡ 0 (mod p) и Y ≡ Z (mod p).
    """
    X, Y, Z, _T = P
    return (X % _ED_P == 0) and ((Y - Z) % _ED_P == 0)


def _ed_has_small_order(pub_bytes):
    """True, если pub — точка малого порядка (1, 2, 4 или 8).

    Уязвимость zero public key:
    если A имеет порядок, делящий кофактор 8, то [k]A пробегает
    маленькое множество. Для A = identity (b'\\\\x01' + b'\\\\x00'*31)
    уравнение проверки Ed25519 ([S]B = R + [k]A) сводится к
    [S]B = R, что позволяет подделать подпись без знания ключа.

    Проверка: [8]A == identity. Кофактор кривой Ed25519 = 8,
    L — простое, поэтому 8-кручение исчерпывается этими точками.
    """
    if len(pub_bytes) != 32:
        return True
    A = _ed_decode(pub_bytes)
    if A is None:
        return True     # вообще не точка на кривой
    return _ed_is_identity(_ed_mul(8, A))


def _ed_clamp(h):''',
    "_ed_is_identity + _ed_has_small_order",
)


# ==================================================================
# 2. Ed25519Keys.__init__ — reject small-order pub
# ==================================================================
edit(
    "src/x509kit/x509.py",
    '''    def __init__(self, seed=None, pub=None):
        if seed is not None:
            if len(seed) != 32:
                raise X509Error("Ed25519 seed must be 32 bytes")
            self.seed = bytes(seed)
            self.pub = _ed_pubkey(self.seed)
        elif pub is not None:
            if len(pub) != 32:
                raise X509Error("Ed25519 pub must be 32 bytes")
            self.seed = None
            self.pub = bytes(pub)
        else:
            raise ValueError("need seed or pub")''',
    '''    def __init__(self, seed=None, pub=None):
        if seed is not None:
            if len(seed) != 32:
                raise X509Error("Ed25519 seed must be 32 bytes")
            self.seed = bytes(seed)
            self.pub = _ed_pubkey(self.seed)
        elif pub is not None:
            if len(pub) != 32:
                raise X509Error("Ed25519 pub must be 32 bytes")
            pub_b = bytes(pub)
            if _ed_has_small_order(pub_b):
                _fail(
                    "Ed25519Keys: публичный ключ — точка малого порядка.",
                    "нулевые байты (b'\\\\x01' + b'\\\\x00'*31) и другие "
                    "точки порядка 1/2/4/8 позволяют подделать подпись "
                    "без знания приватного ключа. Такой ключ невалиден."
                )
            self.seed = None
            self.pub = pub_b
        else:
            raise ValueError("need seed or pub")''',
    "Ed25519Keys.__init__ reject small-order",
)


# ==================================================================
# 3. _ed_verify — reject small-order A и R (defense in depth)
# ==================================================================
edit(
    "src/x509kit/x509.py",
    '''def _ed_verify(pub, msg, sig):
    if len(sig) != 64 or len(pub) != 32:
        return False
    A = _ed_decode(pub)
    if A is None:
        return False
    R_enc = sig[:32]
    S = int.from_bytes(sig[32:], "little")
    if S >= _ED_Q:
        return False
    R = _ed_decode(R_enc)
    if R is None:
        return False''',
    '''def _ed_verify(pub, msg, sig):
    if len(sig) != 64 or len(pub) != 32:
        return False
    # Zero public key / малый порядок A: подпись подделывается без ключа.
    if _ed_has_small_order(pub):
        return False
    A = _ed_decode(pub)
    if A is None:
        return False
    R_enc = sig[:32]
    S = int.from_bytes(sig[32:], "little")
    if S >= _ED_Q:
        return False
    R = _ed_decode(R_enc)
    if R is None:
        return False
    # R тоже должен быть не малого порядка (иначе подпись принимается
    # при подобранном k ≡ 0 mod order(A))
    if _ed_has_small_order(R_enc):
        return False''',
    "_ed_verify reject small-order A and R",
)


# ==================================================================
# 4. RSAKeys.from_public_der — reject n <= 0, e < 3, e even
# ==================================================================
edit(
    "src/x509kit/x509.py",
    '''        if node.tag != TAG_SEQUENCE or len(node.children) < 2:
            raise X509ParseError("not a PKCS#1 RSAPublicKey")
        k = cls(n=node.children[0].as_uint(), e=node.children[1].as_uint())
        _check_rsa_key(k, "RSAKeys.from_public_der")
        return k''',
    '''        if node.tag != TAG_SEQUENCE or len(node.children) < 2:
            raise X509ParseError("not a PKCS#1 RSAPublicKey")
        n = node.children[0].as_uint()
        e = node.children[1].as_uint()
        _validate_rsa_pub(n, e, "RSAKeys.from_public_der")
        k = cls(n=n, e=e)
        _check_rsa_key(k, "RSAKeys.from_public_der")
        return k''',
    "RSAKeys.from_public_der validate",
)


# ==================================================================
# 5. RSAKeys.from_public_bytes — то же
# ==================================================================
edit(
    "src/x509kit/x509.py",
    '''            k = cls(n=node.children[0].as_uint(),
                    e=node.children[1].as_uint())
            _check_rsa_key(k, "RSAKeys.from_public_bytes")
            return k''',
    '''            n = node.children[0].as_uint()
            e = node.children[1].as_uint()
            _validate_rsa_pub(n, e, "RSAKeys.from_public_bytes")
            k = cls(n=n, e=e)
            _check_rsa_key(k, "RSAKeys.from_public_bytes")
            return k''',
    "RSAKeys.from_public_bytes validate",
)


# ==================================================================
# 6. RSAKeys.__init__ — hard guard на n/e
# ==================================================================
edit(
    "src/x509kit/x509.py",
    '''    def __init__(self, n, e, d=None, p=None, q=None, dp=None, dq=None, qinv=None):
        self.n = n; self.e = e; self.d = d''',
    '''    def __init__(self, n, e, d=None, p=None, q=None, dp=None, dq=None, qinv=None):
        if not isinstance(n, int) or not isinstance(e, int):
            raise TypeError("RSAKeys: n and e must be int")
        if n <= 0 or e <= 0:
            raise X509Error(
                "RSAKeys: n и e должны быть положительными. "
                "n=0 или e=0 — невалидный ключ (zero public key attack)."
            )
        if e < 3 or (e & 1) == 0:
            raise X509Error(
                f"RSAKeys: недопустимая публичная экспонента e={e}. "
                "e должен быть нечётным и >= 3."
            )
        self.n = n; self.e = e; self.d = d''',
    "RSAKeys.__init__ hard guard",
)


# ==================================================================
# 7. Helper _validate_rsa_pub перед классом RSAKeys
# ==================================================================
edit(
    "src/x509kit/x509.py",
    '''class RSAKeys:
    __slots__ = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")''',
    '''def _validate_rsa_pub(n, e, context):
    """Отвергнуть n=0, e=0, e=1, e even.

    Zero public key attack: pow(m, e, n) с e=1 даёт sig = m,
    с n=0 бросает ZeroDivisionError, с e=0 даёт 1.
    """
    if n <= 0:
        _fail(
            f"{context}: n <= 0",
            "нулевой/отрицательный модуль — невалидный RSA-ключ",
        )
    if e <= 0:
        _fail(
            f"{context}: e <= 0",
            "нулевая/отрицательная экспонента — невалидный RSA-ключ",
        )
    if e < 3 or (e & 1) == 0:
        _fail(
            f"{context}: e={e} недопустима",
            "e должен быть нечётным и >= 3 (стандарт — 65537)",
        )


class RSAKeys:
    __slots__ = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")''',
    "_validate_rsa_pub helper",
)


# ==================================================================
# 8. CSR/Cert парсинг SPKI — уже вызывает RSAKeys.from_public_der,
#    так что покрыт через #4. ECDSA — уже проверяет точку на кривой.
# ==================================================================

print()
print("=" * 72)
print("Zero public key fix applied.")
print("Run:")
print("  python -c \\\"from x509kit import Ed25519Keys; "
      "Ed25519Keys(pub=b'\\\\x01'+b'\\\\x00'*31)\\\"")
print("  # ожидание: X509Error")
print("  python test_all.py 2>&1 | tail -6")
print("=" * 72)
