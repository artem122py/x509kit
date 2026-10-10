# -*- coding: utf-8 -*-
"""
x509kit.x509 — X.509 / PKCS#10 / RSA / Ed25519 / CertificateBuilder.
Только стандартная библиотека Python.

Сборка сертификата через Builder:

    from x509kit import CertificateBuilder, RSAKeys

    ca_key  = RSAKeys.generate(2048)
    leaf_key = RSAKeys.generate(2048)

    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "RU", "O": "Org", "CN": "My Root CA"})
        .add_public_key(ca_key)
        .add_serial_random()
        .add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed()
        .sign(ca_key))

    leaf = (CertificateBuilder()
        .add_subject({"CN": "example.com"})
        .add_issuer(ca)
        .add_public_key(leaf_key)
        .add_serial_random()
        .add_validity(days=365)
        .add_san(dns=["example.com"])
        .sign(ca_key))
"""

from __future__ import annotations
import os

import base64
import datetime
import hashlib
import hmac
import math
import re
import secrets
import socket
import unicodedata
import warnings as _warnings

__version__ = "0.3.2"


# ======================================================================
#  Исключения
# ======================================================================

class X509Error(Exception):        pass
class X509ParseError(X509Error):   pass
class X509VerifyError(X509Error):  pass


class X509Warning(UserWarning):
    """Не-фатальная проблема: код работает, но что-то подозрительно.

    Сделать warnings ошибками:
        import warnings
        warnings.simplefilter("error", X509Warning)

    Игнорировать warnings:
        warnings.simplefilter("ignore", X509Warning)
    """
    pass


def _warn(what, how=None, stacklevel=3):
    if how:
        what = what + "  (подсказка: " + how + ")"
    _warnings.warn(what, X509Warning, stacklevel=stacklevel)


def _check_rsa_key(key, context):
    """RSA-ключ < 2048 бит — предупреждение."""
    if isinstance(key, RSAKeys) and key.weak:
        _warn(
            f"{context}: RSA-ключ {key.size_bits} бит слишком слаб",
            "нужно >= 2048 бит для production",
        )


def _check_hash(hash_name, context):
    """SHA-1 / MD5 — предупреждение."""
    if hash_name in WEAK_HASHES:
        _warn(
            f"{context}: слабый хэш {hash_name}",
            "используй sha256, sha384 или sha512",
        )


def _check_san_value(kind, value, context):
    """Пустой или слишком длинный SAN — предупреждение."""
    if not value or not value.strip():
        _warn(
            f"{context}: пустое SAN-значение {kind}",
            "пропусти или задай реальное значение",
        )
    elif len(value) > 253:
        _warn(
            f"{context}: {kind} длиной {len(value)} — слишком длинное",
            "RFC 5280 ограничивает dNSName 253 символами",
        )


# ======================================================================
#  ASN.1 / DER
# ======================================================================

TAG_BOOLEAN          = 0x01
TAG_INTEGER          = 0x02
TAG_BIT_STRING       = 0x03
TAG_OCTET_STRING     = 0x04
TAG_NULL             = 0x05
TAG_OID              = 0x06
TAG_UTF8_STRING      = 0x0C
TAG_PRINTABLE_STRING = 0x13
TAG_T61_STRING       = 0x14
TAG_IA5_STRING       = 0x16
TAG_UTC_TIME         = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_VISIBLE_STRING   = 0x1A
TAG_BMP_STRING       = 0x1E
TAG_SEQUENCE         = 0x30
TAG_SET              = 0x31

_MAX_DEPTH = 32
_MAX_PEM_SIZE = 1 * 1024 * 1024   # 1 MB (base64 от 512 KB DER + запас)
_MAX_DER_SIZE = 512 * 1024   # 512 KB (макс. реального X.509 ~50 KB)


def _safe_parse(func):
    """Превращает TypeError/AttributeError/IndexError/ValueError/KeyError
    в X509ParseError. Защищает парсеры от крашей на битых DER.

    Применяется к __init__ парсеров. Гарантирует, что наружу
    выходит только X509Error (или наследник).
    """
    import functools
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except X509Error:
            raise
        except (TypeError, AttributeError, IndexError, ValueError,
                KeyError, UnicodeDecodeError, StopIteration) as e:
            raise X509ParseError(
                f"{func.__qualname__}: malformed DER: "
                f"{type(e).__name__}: {e}"
            ) from None
    return wrapper


class ASN1:
    __slots__ = ("tag", "value", "children", "raw")

    def __init__(self, tag, value, children=None, raw=None):
        self.tag = tag; self.value = value
        self.children = children; self.raw = raw

    @classmethod
    def parse(cls, data, offset=0, _depth=0):
        if len(data) > _MAX_DER_SIZE:
            raise X509ParseError(
                f"DER input too large: {len(data)} bytes "
                f"(limit {_MAX_DER_SIZE})"
            )
        if _depth > _MAX_DEPTH:
            raise X509ParseError("DER nesting too deep")
        start = offset
        if offset >= len(data):
            raise X509ParseError("truncated DER (tag)")
        tag = data[offset]; offset += 1
        if tag & 0x1F == 0x1F:
            raise X509ParseError("high-tag-number form unsupported")
        if offset >= len(data):
            raise X509ParseError("truncated DER (length)")
        lb = data[offset]; offset += 1
        if lb & 0x80:
            n = lb & 0x7F
            if n == 0:
                raise X509ParseError("indefinite length not allowed in DER")
            if n > 4:
                raise X509ParseError("length too large")
            if offset + n > len(data):
                raise X509ParseError("truncated DER (long length)")
            length = int.from_bytes(data[offset:offset + n], "big")
            offset += n
            if length < 0x80:
                raise X509ParseError("non-minimal DER length")
            if n > 1 and data[offset - n] == 0x00:
                raise X509ParseError("non-minimal DER length (leading zero)")
        else:
            length = lb
        end = offset + length
        if end > len(data):
            raise X509ParseError("truncated DER (content)")
        content = bytes(data[offset:end])
        children = None
        if tag & 0x20:
            children = []
            p = offset
            while p < end:
                child, p = cls.parse(data, p, _depth + 1)
                children.append(child)
            if p != end:
                raise X509ParseError("constructed length mismatch")
        return cls(tag, content, children, bytes(data[start:end])), end

    def as_int(self):  return int.from_bytes(self.value, "big", signed=True)
    def as_uint(self): return int.from_bytes(self.value, "big", signed=False)
    def as_bool(self): return self.value != b"\x00"
    def as_oid(self):  return decode_oid(self.value)

    def as_str(self):
        t, v = self.tag, self.value
        if t == TAG_UTF8_STRING:
            return v.decode("utf-8", "replace")
        if t in (TAG_PRINTABLE_STRING, TAG_IA5_STRING, TAG_VISIBLE_STRING):
            return v.decode("ascii", "replace")
        if t == TAG_BMP_STRING:
            return v.decode("utf-16-be", "replace")
        if t == TAG_T61_STRING:
            return v.decode("latin-1", "replace")
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.decode("latin-1", "replace")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def der_int(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative INTEGER not supported")
    if n == 0:
        return _der_tlv(TAG_INTEGER, b"\x00")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _der_tlv(TAG_INTEGER, b)


def der_seq(*parts): return _der_tlv(TAG_SEQUENCE, b"".join(parts))
def der_set(*parts): return _der_tlv(TAG_SET, b"".join(parts))
def der_null():      return _der_tlv(TAG_NULL, b"")
def der_octet(d):    return _der_tlv(TAG_OCTET_STRING, d)
def der_bool(v):     return _der_tlv(TAG_BOOLEAN, b"\xff" if v else b"\x00")
def der_bitstring(data, unused=0):
    if not (0 <= unused <= 7):
        raise ValueError("bad unused bits count")
    return _der_tlv(TAG_BIT_STRING, bytes([unused]) + data)


# ======================================================================
#  OID
# ======================================================================

def decode_oid(data: bytes) -> str:
    if not data:
        raise X509ParseError("empty OID")
    parts, val = [], 0
    at_start = True
    for b in data:
        if at_start and b == 0x80:
            raise X509ParseError("non-minimal OID encoding")
        at_start = False
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val); val = 0; at_start = True
    if val or not parts:
        raise X509ParseError("truncated OID")
    first = parts[0]
    if first < 40:   head = (0, first)
    elif first < 80: head = (1, first - 40)
    else:            head = (2, first - 80)
    return ".".join(str(x) for x in (head + tuple(parts[1:])))


def encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    if len(parts) < 2:
        raise ValueError("OID needs >= 2 arcs")
    if any(p < 0 for p in parts):
        raise ValueError("OID arcs must be non-negative")
    if not (0 <= parts[0] <= 2):
        raise ValueError("first OID arc must be 0..2")
    if parts[0] < 2 and parts[1] >= 40:
        raise ValueError("second OID arc must be < 40 when first < 2")
    body = bytearray()
    values = [40 * parts[0] + parts[1]] + parts[2:]
    for v in values:
        if v == 0:
            body.append(0); continue
        stack = []
        while v:
            stack.append(v & 0x7F); v >>= 7
        for i in range(len(stack) - 1, -1, -1):
            body.append(stack[i] | (0x80 if i else 0))
    return _der_tlv(TAG_OID, bytes(body))


OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_ED25519        = "1.3.101.112"

# ECDSA
OID_EC_PUBLIC_KEY  = "1.2.840.10045.2.1"        # id-ecPublicKey
OID_ECDSA_SHA256   = "1.2.840.10045.4.3.2"      # ecdsa-with-SHA256
OID_ECDSA_SHA384   = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA512   = "1.2.840.10045.4.3.4"

# Кривые
OID_PRIME256V1     = "1.2.840.10045.3.1.7"      # P-256 / secp256r1
OID_SECP384R1      = "1.3.132.0.34"             # P-384
OID_SECP521R1      = "1.3.132.0.35"             # P-521
OID_SECP256K1      = "1.3.132.0.10"             # secp256k1 (Bitcoin)

OID_SAN           = "2.5.29.17"
OID_KEY_USAGE     = "2.5.29.15"
OID_BASIC_CONSTR  = "2.5.29.19"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SUBJ_KEY_ID   = "2.5.29.14"
OID_AUTH_KEY_ID   = "2.5.29.35"
OID_EXT_REQUEST   = "1.2.840.113549.1.9.14"
OID_NAME_CONSTR   = "2.5.29.30"
OID_OCSP          = "1.3.6.1.5.5.7.48.1"
OID_OCSP_BASIC    = "1.3.6.1.5.5.7.48.1.1"
OID_OCSP_NONCE    = "1.3.6.1.5.5.7.48.1.2"

# AIA (Authority Information Access)
OID_AIA           = "1.3.6.1.5.5.7.1.1"
OID_AD_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"

# CRL / revocation
OID_CRL_REASON    = "2.5.29.21"
OID_CRL_DP        = "2.5.29.31"
OID_CRL_NUMBER    = "2.5.29.20"
OID_CRL_ISSUER    = "2.5.29.29"
OID_INVALIDITY    = "2.5.29.24"

KNOWN_EXTENSION_OIDS = {
    OID_SAN, OID_KEY_USAGE, OID_BASIC_CONSTR,
    OID_EXT_KEY_USAGE, OID_SUBJ_KEY_ID, OID_AUTH_KEY_ID,
    OID_CRL_REASON, OID_CRL_DP, OID_CRL_NUMBER,
    OID_CRL_ISSUER, OID_INVALIDITY,
    OID_NAME_CONSTR,
    OID_AIA,
}


EXT_NAMES = {
    "2.5.29.17":         "X509v3 Subject Alternative Name",
    "2.5.29.19":         "X509v3 Basic Constraints",
    "2.5.29.15":         "X509v3 Key Usage",
    "2.5.29.37":         "X509v3 Extended Key Usage",
    "2.5.29.30":         "X509v3 Name Constraints",
    "2.5.29.14":         "X509v3 Subject Key Identifier",
    "2.5.29.35":         "X509v3 Authority Key Identifier",
    "2.5.29.31":         "X509v3 CRL Distribution Points",
    "2.5.29.20":         "X509v3 CRL Number",
    "2.5.29.21":         "X509v3 CRL Reason Code",
    "1.3.6.1.5.5.7.1.1": "Authority Information Access",
}

# RFC 5280 §5.3.1 reason codes
CRL_REASONS = {
    "unspecified":          0,
    "keyCompromise":        1,
    "cACompromise":         2,
    "affiliationChanged":   3,
    "superseded":           4,
    "cessationOfOperation": 5,
    "certificateHold":      6,
    "removeFromCRL":        8,
    "privilegeWithdrawn":   9,
    "aACompromise":         10,
}
CRL_REASONS_REV = {v: k for k, v in CRL_REASONS.items()}

ATTR_NAMES = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber",
    "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "street",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
    "2.5.4.42": "GN", "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
}
ATTR_OIDS = {v: k for k, v in ATTR_NAMES.items()}

SIG_ALG_RSA_HASH = {
    "1.2.840.113549.1.1.5":  "sha1",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
_RSA_HASH_TO_SIG_OID = {v: k for k, v in SIG_ALG_RSA_HASH.items()}

ECDSA_SIG_OID_TO_HASH = {
    OID_ECDSA_SHA256: "sha256",
    OID_ECDSA_SHA384: "sha384",
    OID_ECDSA_SHA512: "sha512",
}
_ECDSA_HASH_TO_SIG_OID = {v: k for k, v in ECDSA_SIG_OID_TO_HASH.items()}

SIG_ALG_NAMES = {
    "1.2.840.113549.1.1.5":  "sha1WithRSA",
    "1.2.840.113549.1.1.14": "sha224WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    OID_ED25519:             "Ed25519",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    OID_ECDSA_SHA256:        "ecdsa-with-SHA256",
    OID_ECDSA_SHA384:        "ecdsa-with-SHA384",
    OID_ECDSA_SHA512:        "ecdsa-with-SHA512",
}

WEAK_HASHES = {"sha1", "md5"}

# Extended Key Usage — типичные назначения (RFC 5280 §4.2.1.12 + RFC 6960)
EKU_OIDS = {
    "serverAuth":       "1.3.6.1.5.5.7.3.1",
    "clientAuth":       "1.3.6.1.5.5.7.3.2",
    "codeSigning":      "1.3.6.1.5.5.7.3.3",
    "emailProtection":  "1.3.6.1.5.5.7.3.4",
    "timeStamping":     "1.3.6.1.5.5.7.3.8",
    "OCSPSigning":      "1.3.6.1.5.5.7.3.9",
    "ipsecEndSystem":   "1.3.6.1.5.5.7.3.5",
    "ipsecTunnel":      "1.3.6.1.5.5.7.3.6",
    "ipsecUser":        "1.3.6.1.5.5.7.3.7",
    "anyExtendedKeyUsage": "2.5.29.37.0",
}
EKU_OIDS_REV = {v: k for k, v in EKU_OIDS.items()}

_DIGEST_INFO_PREFIX = {
    "sha1":   bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


# ---- RSA-PSS (RFC 8017 §8.1) ----

OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1    = "1.2.840.113549.1.1.8"

_HASH_OIDS = {
    "sha1":   "1.3.14.3.2.26",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
_HASH_OIDS_REV = {v: k for k, v in _HASH_OIDS.items()}


# ======================================================================
#  Name
# ======================================================================

_DN_ESCAPE = set(',+"\\<>;')


def _escape_dn(v: str) -> str:
    if not v:
        return ""
    out, n = [], len(v)
    for i, ch in enumerate(v):
        if ch in _DN_ESCAPE:          out.append("\\" + ch)
        elif ch == " " and (i == 0 or i == n - 1): out.append("\\ ")
        elif ch == "#" and i == 0:    out.append("\\#")
        else:                          out.append(ch)
    return "".join(out)


def _unescape_dn(s: str) -> str:
    """RFC 4514: убрать escape-последовательности в значении DN."""
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _encode_rdn(short_or_oid: str, value: str) -> bytes:
    oid = ATTR_OIDS.get(short_or_oid, short_or_oid)
    if not isinstance(value, str):
        value = str(value)
    try:
        ascii_bytes = value.encode("ascii")
        use_printable = all(32 <= b < 127 for b in ascii_bytes)
    except UnicodeEncodeError:
        ascii_bytes = b""
        use_printable = False
    val_der = (_der_tlv(TAG_PRINTABLE_STRING, ascii_bytes) if use_printable
               else _der_tlv(TAG_UTF8_STRING, value.encode("utf-8")))
    return der_set(der_seq(encode_oid(oid), val_der))


class Name:
    __slots__ = ("rdns", "raw")

    @_safe_parse
    def __init__(self, node: ASN1):
        self.raw = node.raw
        self.rdns = []
        for rdn in node.children:
            attrs = []
            for atv in rdn.children:
                attrs.append((atv.children[0].as_oid(), atv.children[1].as_str()))
            self.rdns.append(attrs)

    def __str__(self):
        chunks = []
        for rdn in reversed(self.rdns):
            chunks.append("+".join(
                f"{ATTR_NAMES.get(oid, oid)}={_escape_dn(v)}" for oid, v in rdn
            ))
        return ", ".join(chunks)

    def __repr__(self):
        return f"<Name {self}>"

    def get(self, short_name):
        for rdn in self.rdns:
            for oid, v in rdn:
                if ATTR_NAMES.get(oid) == short_name:
                    return v
        return None

    def as_dict(self):
        d = {}
        for rdn in self.rdns:
            for oid, v in rdn:
                d.setdefault(ATTR_NAMES.get(oid, oid), v)
        return d

    @classmethod
    def from_dict(cls, d):
        rdn_list = []
        for short, val in d.items():
            if isinstance(val, list):
                for v in val:
                    rdn_list.append(_encode_rdn(short, v))
            else:
                rdn_list.append(_encode_rdn(short, val))
        node, _ = ASN1.parse(der_seq(*rdn_list))
        return cls(node)

    def name_matches(self, other):
        """Каноничное сравнение (RFC 4518). Принимает Name, Cert, CSR."""
        if isinstance(other, Name):
            other_name = other
        elif isinstance(other, (Cert, CSR)):
            other_name = other.subject
        else:
            raise TypeError(
                f"Name.name_matches: ожидался Name/Cert/CSR, "
                f"получен {type(other).__name__}"
            )
        return names_equal(self, other_name)

    def equals(self, other):
        """Алиас для name_matches."""
        return self.name_matches(other)


# ======================================================================
#  AlgorithmIdentifier
# ======================================================================


    def __eq__(self, other):
        return isinstance(other, Name) and self.raw == other.raw

    def __hash__(self):
        return hash(self.raw)

    @classmethod
    def from_string(cls, s):
        r"""RFC 4514: разобрать строку DN в Name.

        Порядок в строке — от конкретного к общему:
            "CN=example.com, O=MyOrg, C=XX"

        Эквивалентно Name.from_dict({"C": "XX", "O": "MyOrg", "CN": "example.com"}).

        Поддерживает escape-последовательности:
            CN=with\, comma, O=Org
            CN=with\backslash
        """
        if not s or not s.strip():
            raise X509ParseError("Name.from_string: empty string")

        # Разбить по неэкранированным запятым
        parts, cur, i = [], [], 0
        while i < len(s):
            c = s[i]
            if c == "\\" and i + 1 < len(s):
                cur.append(c)
                cur.append(s[i + 1])
                i += 2
                continue
            if c == ",":
                parts.append("".join(cur))
                cur = []
                i += 1
                continue
            cur.append(c)
            i += 1
        if cur:
            parts.append("".join(cur))

        rdns = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            key_b, val_b, in_val, j = [], [], False, 0
            while j < len(part):
                c = part[j]
                if c == "\\" and j + 1 < len(part):
                    (val_b if in_val else key_b).append(c)
                    (val_b if in_val else key_b).append(part[j + 1])
                    j += 2
                    continue
                if c == "=" and not in_val:
                    in_val = True
                    j += 1
                    continue
                (val_b if in_val else key_b).append(c)
                j += 1
            if not in_val:
                raise X509ParseError(f"Name.from_string: missing '=' in {part!r}")
            k = "".join(key_b).strip()
            v = _unescape_dn("".join(val_b).strip())
            oid = ATTR_OIDS.get(k, k)
            rdns.append((oid, v))

        rdn_list = [_encode_rdn(oid, val) for oid, val in reversed(rdns)]
        node, _ = ASN1.parse(der_seq(*rdn_list))
        return cls(node)

class AlgorithmIdentifier:
    __slots__ = ("oid", "params", "raw")

    @_safe_parse
    def __init__(self, node):
        if not node.children:
            raise X509ParseError("AlgorithmIdentifier must have children")
        self.oid = node.children[0].as_oid()
        self.params = node.children[1] if len(node.children) > 1 else None
        self.raw = node.raw

    @property
    def name(self):
        return SIG_ALG_NAMES.get(self.oid, self.oid)

    def __repr__(self):
        return f"<AlgId {self.oid}>"


# ======================================================================
#  RSAKeys — blinding + CRT
# ======================================================================

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)

RSA_MIN_GENERATE_BITS = 2048
RSA_WEAK_BITS         = 2048


def _is_probable_prime(n, rounds=32):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _rand_prime(bits):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(n):
            return n


# ---- RSA-PSS: MGF1 + EMSA-PSS ----

def _mgf1(seed, length, hash_name):
    """MGF1 (RFC 8017 B.2.1)."""
    h_len = hashlib.new(hash_name).digest_size
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _emsa_pss_encode(msg, em_bits, hash_name, salt_len):
    """EMSA-PSS-ENCODE (RFC 8017 §9.1.1)."""
    h_len = hashlib.new(hash_name).digest_size
    em_len = (em_bits + 7) // 8
    if em_len < h_len + salt_len + 2:
        raise ValueError(f"RSA key too small: em_len={em_len}, "
                         f"need >= {h_len + salt_len + 2}")
    m_hash = hashlib.new(hash_name, msg).digest()
    salt = secrets.token_bytes(salt_len)
    h_val = hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest()
    ps = b"\x00" * (em_len - salt_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1(h_val, em_len - h_len - 1, hash_name)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    unused_bits = 8 * em_len - em_bits
    if unused_bits > 0:
        masked_db = bytes([masked_db[0] & (0xFF >> unused_bits)]) + masked_db[1:]
    return masked_db + h_val + b"\xbc"


def _emsa_pss_verify(msg, em, em_bits, hash_name, salt_len):
    """EMSA-PSS-VERIFY (RFC 8017 §9.1.2)."""
    h_len = hashlib.new(hash_name).digest_size
    em_len = len(em)
    if em_len < h_len + salt_len + 2:
        return False
    if em[-1] != 0xbc:
        return False
    masked_db = em[:em_len - h_len - 1]
    h_val = em[em_len - h_len - 1:em_len - 1]
    unused_bits = 8 * em_len - em_bits
    if unused_bits > 0:
        if masked_db[0] & (0xFF << (8 - unused_bits) & 0xFF):
            return False
    db_mask = _mgf1(h_val, em_len - h_len - 1, hash_name)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    if unused_bits > 0:
        db = bytes([db[0] & (0xFF >> unused_bits)]) + db[1:]
    ps_len = em_len - h_len - salt_len - 2
    if db[:ps_len] != b"\x00" * ps_len:
        return False
    if db[ps_len] != 0x01:
        return False
    salt = db[-salt_len:] if salt_len > 0 else b""
    m_hash = hashlib.new(hash_name, msg).digest()
    h_prime = hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest()
    return hmac.compare_digest(h_prime, h_val)


def _build_pss_alg_id(hash_name, salt_len=None):
    """AlgorithmIdentifier для RSASSA-PSS."""
    if salt_len is None:
        salt_len = hashlib.new(hash_name).digest_size
    hash_oid = _HASH_OIDS[hash_name]
    hash_alg = _der_tlv(0xA0, der_seq(encode_oid(hash_oid), der_null()))
    mgf_alg = _der_tlv(0xA1, der_seq(
        encode_oid(OID_MGF1),
        der_seq(encode_oid(hash_oid), der_null()),
    ))
    salt_alg = _der_tlv(0xA2, der_int(salt_len))
    params = der_seq(hash_alg, mgf_alg, salt_alg)
    return der_seq(encode_oid(OID_RSA_PSS), params)


def _parse_pss_params(params_node):
    """Из AlgorithmIdentifier.params → (hash_name, salt_len)."""
    # По RFC 4055 defaults: SHA-1 + salt 20, если параметры опущены
    if params_node is None or params_node.tag != TAG_SEQUENCE:
        return ("sha1", 20)
    hash_name = "sha1"
    salt_len = 20
    for child in params_node.children:
        if child.tag == 0xA0:                    # [0] hashAlgorithm
            inner = child.children[0]
            if inner.tag == TAG_SEQUENCE and inner.children:
                oid = inner.children[0].as_oid()
                hash_name = _HASH_OIDS_REV.get(oid, hash_name)
        elif child.tag == 0xA1:                  # [1] maskGenAlgorithm
            inner = child.children[0]
            if inner.tag == TAG_SEQUENCE and len(inner.children) >= 2:
                mgf_oid = inner.children[0].as_oid()
                if mgf_oid != OID_MGF1:
                    raise X509ParseError(f"unsupported MGF: {mgf_oid}")
                p = inner.children[1]
                if p.tag == TAG_SEQUENCE and p.children:
                    h_oid = p.children[0].as_oid()
                    hash_name = _HASH_OIDS_REV.get(h_oid, hash_name)
        elif child.tag == 0xA2:                  # [2] saltLength
            salt_len = child.children[0].as_int()
    return (hash_name, salt_len)

class RSAKeys:
    __slots__ = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")

    def __init__(self, n, e, d=None, p=None, q=None, dp=None, dq=None, qinv=None):
        self.n = n; self.e = e; self.d = d
        self.p = p; self.q = q
        self.dp = dp; self.dq = dq; self.qinv = qinv

    @property
    def is_private(self): return self.d is not None
    @property
    def size_bits(self):  return self.n.bit_length()
    @property
    def size_bytes(self): return (self.size_bits + 7) // 8
    @property
    def weak(self):       return self.size_bits < RSA_WEAK_BITS

    def __repr__(self):
        kind = "private" if self.is_private else "public"
        w = " [WEAK]" if self.weak else ""
        return f"<RSAKeys {kind} {self.size_bits}bit e={self.e}{w}>"

    @classmethod
    def generate(cls, bits=RSA_MIN_GENERATE_BITS, e=65537):
        if bits < RSA_MIN_GENERATE_BITS or bits % 2:
            raise ValueError(f"bits must be even and >= {RSA_MIN_GENERATE_BITS}")
        if e < 65537 or e % 2 == 0:
            raise ValueError("public exponent must be odd and >= 65537")
        half = bits // 2
        min_diff = 1 << (half - 100)
        while True:
            p = _rand_prime(half); q = _rand_prime(half)
            if p == q: continue
            if p < q: p, q = q, p
            if p - q < min_diff: continue
            n = p * q
            if n.bit_length() != bits: continue
            phi = (p - 1) * (q - 1)
            if math.gcd(e, phi) != 1: continue
            d = pow(e, -1, phi)
            return cls(n=n, e=e, d=d, p=p, q=q,
                       dp=d % (p - 1), dq=d % (q - 1),
                       qinv=pow(q, -1, p))

    @classmethod
    def from_public_der(cls, der):
        node, _ = ASN1.parse(der)
        if (node.tag == TAG_SEQUENCE and len(node.children) == 2
                and node.children[0].tag == TAG_SEQUENCE
                and node.children[1].tag == TAG_BIT_STRING):
            bits = node.children[1].value
            if not bits or bits[0] != 0:
                raise X509ParseError("bad BIT STRING in SPKI")
            return cls.from_public_der(bits[1:])
        if node.tag != TAG_SEQUENCE or len(node.children) < 2:
            raise X509ParseError("not a PKCS#1 RSAPublicKey")
        k = cls(n=node.children[0].as_uint(), e=node.children[1].as_uint())
        _check_rsa_key(k, "RSAKeys.from_public_der")
        return k

    @classmethod
    def from_private_der(cls, der):
        node, _ = ASN1.parse(der)
        if (node.tag == TAG_SEQUENCE and len(node.children) == 3
                and node.children[0].tag == TAG_INTEGER
                and node.children[1].tag == TAG_SEQUENCE
                and node.children[2].tag == TAG_OCTET_STRING):
            node, _ = ASN1.parse(node.children[2].value)
        ch = node.children
        if len(ch) < 9:
            raise X509ParseError("not a PKCS#1 RSAPrivateKey")
        return cls(n=ch[1].as_uint(), e=ch[2].as_uint(), d=ch[3].as_uint(),
                   p=ch[4].as_uint(), q=ch[5].as_uint(),
                   dp=ch[6].as_uint(), dq=ch[7].as_uint(), qinv=ch[8].as_uint())

    @classmethod
    def from_pem(cls, data, private=False, password=None):
        if isinstance(data, str): data = data.encode("ascii")
        want = {"PRIVATE KEY", "RSA PRIVATE KEY"} if private else {"PUBLIC KEY", "RSA PUBLIC KEY"}
        for label, der in pem_decode(data):
            if "ENCRYPTED PRIVATE KEY" in label:
                if password is None:
                    raise X509Error(
                        "PEM зашифрован, нужен password",
                        )
                der = _pkcs8_decrypt(der, password)
                return cls.from_private_der(der)
            if label in want:
                return cls.from_private_der(der) if private else cls.from_public_der(der)
        raise X509ParseError(f"no {'private' if private else 'public'} RSA key in PEM")

    def to_public_der(self):
        return der_seq(
            der_seq(encode_oid(OID_RSA_ENCRYPTION), der_null()),
            der_bitstring(der_seq(der_int(self.n), der_int(self.e))),
        )

    def to_private_der(self):
        if not self.is_private:
            raise X509Error("private key required")
        return der_seq(
            der_int(0), der_int(self.n), der_int(self.e), der_int(self.d),
            der_int(self.p), der_int(self.q),
            der_int(self.dp), der_int(self.dq), der_int(self.qinv),
        )

    def to_public_pem(self):  return pem_encode("PUBLIC KEY", self.to_public_der())

    def to_private_pem(self, password=None, *, iterations=100000,
                       cipher="aes-256-cbc"):
        if password is None:
            return pem_encode("RSA PRIVATE KEY", self.to_private_der())
        # Оборачиваем PKCS#1 в PKCS#8 перед шифрованием
        pkcs1 = self.to_private_der()
        alg = der_seq(encode_oid(OID_RSA_ENCRYPTION), der_null())
        pkcs8 = der_seq(der_int(0), alg, der_octet(pkcs1))
        enc = _pkcs8_encrypt(pkcs8, password, iterations=iterations,
                             cipher=cipher)
        return pem_encode("ENCRYPTED PRIVATE KEY", enc)

    def _private_op(self, m):
        """m^d mod n. Blinding + CRT."""
        n = self.n
        while True:
            r = secrets.randbelow(n - 2) + 2
            if math.gcd(r, n) == 1:
                break
        re = pow(r, self.e, n)
        m_blind = (m * re) % n
        if self.p and self.q and self.dp and self.dq and self.qinv:
            m1 = pow(m_blind, self.dp, self.p)
            m2 = pow(m_blind, self.dq, self.q)
            h = (self.qinv * (m1 - m2)) % self.p
            s_blind = m2 + h * self.q
        else:
            s_blind = pow(m_blind, self.d, n)
        rinv = pow(r, -1, n)
        return (s_blind * rinv) % n

    def sign_pkcs1v15(self, data, hash_name="sha256"):
        if not self.is_private:
            raise X509Error("private key required")
        if hash_name not in _DIGEST_INFO_PREFIX:
            raise ValueError(f"unsupported hash: {hash_name}")
        k = self.size_bytes
        digest = hashlib.new(hash_name, data).digest()
        t = _DIGEST_INFO_PREFIX[hash_name] + digest
        if k < len(t) + 11:
            raise ValueError("RSA key too small for this hash")
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        m = int.from_bytes(em, "big")
        return self._private_op(m).to_bytes(k, "big")

    def verify_pkcs1v15(self, data, signature, hash_name="sha256", allow_weak=False):
        if self.weak and not allow_weak:
            return False
        if hash_name not in _DIGEST_INFO_PREFIX:
            return False
        k = self.size_bytes
        if len(signature) != k:
            return False
        m = pow(int.from_bytes(signature, "big"), self.e, self.n)
        em = m.to_bytes(k, "big")
        if em[0] != 0x00 or em[1] != 0x01:
            return False
        i = 2
        while i < len(em) and em[i] == 0xFF:
            i += 1
        if i < 2 + 8 or i >= len(em) or em[i] != 0x00:
            return False
        expected = _DIGEST_INFO_PREFIX[hash_name] + hashlib.new(hash_name, data).digest()
        return hmac.compare_digest(em[i + 1:], expected)

    def sign_pss(self, data, hash_name="sha256", salt_len=None):
        """RSA-PSS подпись (RFC 8017 §8.1.1). salt_len по умолчанию = размер хэша."""
        if not self.is_private:
            raise X509Error("private key required")
        if hash_name not in _HASH_OIDS:
            raise ValueError(f"unsupported hash: {hash_name}")
        if salt_len is None:
            salt_len = hashlib.new(hash_name).digest_size
        em_bits = self.n.bit_length() - 1
        em = _emsa_pss_encode(data, em_bits, hash_name, salt_len)
        m = int.from_bytes(em, "big")
        s = self._private_op(m)
        return s.to_bytes(self.size_bytes, "big")

    def verify_pss(self, data, signature, hash_name="sha256",
                   salt_len=None, allow_weak=False):
        """RSA-PSS проверка."""
        if self.weak and not allow_weak:
            return False
        if hash_name not in _HASH_OIDS:
            return False
        if salt_len is None:
            salt_len = hashlib.new(hash_name).digest_size
        k = self.size_bytes
        if len(signature) != k:
            return False
        m = pow(int.from_bytes(signature, "big"), self.e, self.n)
        em_bits = self.n.bit_length() - 1
        em_len = (em_bits + 7) // 8
        em_full = m.to_bytes(k, "big")
        em = em_full[k - em_len:] if em_len <= k else em_full
        return _emsa_pss_verify(data, em, em_bits, hash_name, salt_len)

    def sign(self, data, hash_name="sha256"):
        return self.sign_pkcs1v15(data, hash_name)

    def verify(self, data, signature, hash_name="sha256"):
        return self.verify_pkcs1v15(data, signature, hash_name)

    def wipe(self):
        self.d = 0; self.p = 0; self.q = 0
        self.dp = 0; self.dq = 0; self.qinv = 0


    def to_pkcs12(self, cert, chain=None, password="", name=None,
                  iterations=2048, cipher="aes-256-cbc"):
        """Упаковать этот ключ + сертификат (+цепочку) в PKCS#12.

        Возвращает PKCS12. Для сохранения:
            key.to_pkcs12(cert, chain=[ca]).save("client.p12")
        """
        b = PKCS12Builder()
        b.set_key(self)
        b.set_cert(cert)
        if chain:
            b.add_chain(*chain)
        b.set_password(password)
        if name:
            b.set_name(name)
        b.set_iterations(iterations)
        if cipher != "aes-256-cbc":
            b.set_cipher(cipher)
        return b.build()


# ======================================================================
#  Ed25519Keys (RFC 8032)
# ======================================================================


    def __eq__(self, other):
        return (isinstance(other, RSAKeys)
                and self.n == other.n and self.e == other.e)

    def __hash__(self):
        return hash((self.n, self.e))
_ED_P = 2**255 - 19
_ED_Q = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, -1, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
_ED_Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_ED_By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_ED_B = (_ED_Bx, _ED_By, 1, _ED_Bx * _ED_By % _ED_P)


def _ed_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _ED_P
    B = (Y1 + X1) * (Y2 + X2) % _ED_P
    C = T1 * 2 * _ED_D * T2 % _ED_P
    D = Z1 * 2 * Z2 % _ED_P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _ED_P, G * H % _ED_P, F * G % _ED_P, E * H % _ED_P)


def _ed_dbl(P):
    X1, Y1, Z1, _ = P
    A = X1 * X1 % _ED_P
    B = Y1 * Y1 % _ED_P
    C = 2 * Z1 * Z1 % _ED_P
    D = -A % _ED_P
    E = ((X1 + Y1) ** 2 - A - B) % _ED_P
    G = D + B
    F = G - C
    H = D - B
    return (E * F % _ED_P, G * H % _ED_P, F * G % _ED_P, E * H % _ED_P)


def _ed_mul(k, P):
    R = (0, 1, 1, 0)
    while k:
        if k & 1:
            R = _ed_add(R, P)
        P = _ed_dbl(P)
        k >>= 1
    return R


def _ed_encode(P):
    X, Y, Z, _ = P
    zi = pow(Z, -1, _ED_P)
    x = X * zi % _ED_P
    y = Y * zi % _ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_recover_x(y, sign):
    if y >= _ED_P:
        return None
    y2 = y * y % _ED_P
    num = (y2 - 1) % _ED_P
    den = (_ED_D * y2 + 1) % _ED_P
    if den == 0:
        return None
    xx = num * pow(den, -1, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = x * _ED_I % _ED_P
    if (x * x - xx) % _ED_P != 0:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


def _ed_decode(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = (data[31] >> 7) & 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED_P)


def _ed_clamp(h):
    a = bytearray(h[:32])
    a[0] &= 248; a[31] &= 127; a[31] |= 64
    return int.from_bytes(a, "little")


def _ed_pubkey(seed):
    h = hashlib.sha512(seed).digest()
    return _ed_encode(_ed_mul(_ed_clamp(h), _ED_B))


def _ed_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = _ed_clamp(h)
    prefix = h[32:64]
    A = _ed_encode(_ed_mul(a, _ED_B))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _ED_Q
    R = _ed_encode(_ed_mul(r, _ED_B))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _ED_Q
    S = (r + k * a) % _ED_Q
    return R + S.to_bytes(32, "little")


def _ed_verify(pub, msg, sig):
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
        return False
    k = int.from_bytes(hashlib.sha512(R_enc + pub + msg).digest(), "little") % _ED_Q
    SB = _ed_mul(S, _ED_B)
    RkA = _ed_add(R, _ed_mul(k, A))
    return ((SB[0] * RkA[2] - RkA[0] * SB[2]) % _ED_P == 0 and
            (SB[1] * RkA[2] - RkA[1] * SB[2]) % _ED_P == 0)


class Ed25519Keys:
    __slots__ = ("seed", "pub")

    def __init__(self, seed=None, pub=None):
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
            raise ValueError("need seed or pub")

    @property
    def is_private(self): return self.seed is not None
    @property
    def size_bits(self):  return 256
    @property
    def weak(self):       return False

    def __repr__(self):
        kind = "private" if self.is_private else "public"
        return f"<Ed25519Keys {kind} pub={self.pub.hex()[:16]}…>"

    @classmethod
    def generate(cls):
        return cls(seed=secrets.token_bytes(32))

    def to_public_der(self):
        return der_seq(der_seq(encode_oid(OID_ED25519)), der_bitstring(self.pub))

    def to_private_der(self):
        if not self.is_private:
            raise X509Error("private key required")
        return der_seq(
            der_int(0),
            der_seq(encode_oid(OID_ED25519)),
            der_octet(der_octet(self.seed)),
        )

    @classmethod
    def from_public_der(cls, der):
        if len(der) == 32:
            return cls(pub=der)
        node, _ = ASN1.parse(der)
        if (node.tag == TAG_SEQUENCE and len(node.children) == 2
                and node.children[0].tag == TAG_SEQUENCE
                and node.children[1].tag == TAG_BIT_STRING):
            bits = node.children[1].value
            if not bits or bits[0] != 0:
                raise X509ParseError("bad BIT STRING in Ed25519 SPKI")
            return cls(pub=bits[1:])
        raise X509ParseError("not an Ed25519 public key")

    @classmethod
    def from_private_der(cls, der):
        node, _ = ASN1.parse(der)
        if (node.tag == TAG_SEQUENCE and len(node.children) == 3
                and node.children[0].tag == TAG_INTEGER
                and node.children[1].tag == TAG_SEQUENCE
                and node.children[2].tag == TAG_OCTET_STRING):
            inner = node.children[2].value
            if len(inner) == 32:
                return cls(seed=inner)
            inner_node, _ = ASN1.parse(inner)
            if inner_node.tag == TAG_OCTET_STRING and len(inner_node.value) == 32:
                return cls(seed=inner_node.value)
        raise X509ParseError("not an Ed25519 PKCS#8 private key")

    @classmethod
    def from_pem(cls, data, private=False, password=None):
        if isinstance(data, str): data = data.encode("ascii")
        want = {"PRIVATE KEY"} if private else {"PUBLIC KEY"}
        for label, der in pem_decode(data):
            if "ENCRYPTED PRIVATE KEY" in label:
                if password is None:
                    raise X509Error("PEM зашифрован, нужен password")
                der = _pkcs8_decrypt(der, password)
                return cls.from_private_der(der)
            if label in want:
                return cls.from_private_der(der) if private else cls.from_public_der(der)
        raise X509ParseError(f"no {'private' if private else 'public'} Ed25519 key in PEM")

    def to_public_pem(self):  return pem_encode("PUBLIC KEY", self.to_public_der())

    def to_private_pem(self, password=None, *, iterations=100000,
                       cipher="aes-256-cbc"):
        if password is None:
            return pem_encode("PRIVATE KEY", self.to_private_der())
        enc = _pkcs8_encrypt(self.to_private_der(), password,
                             iterations=iterations, cipher=cipher)
        return pem_encode("ENCRYPTED PRIVATE KEY", enc)

    def sign(self, data, hash_name=None):
        if not self.is_private:
            raise X509Error("private key required")
        return _ed_sign(self.seed, data)

    def verify(self, data, signature, hash_name=None):
        return _ed_verify(self.pub, data, signature)

    def wipe(self):
        self.seed = None


    def to_pkcs12(self, cert, chain=None, password="", name=None,
                  iterations=2048, cipher="aes-256-cbc"):
        """Упаковать этот ключ + сертификат (+цепочку) в PKCS#12.

        Возвращает PKCS12. Для сохранения:
            key.to_pkcs12(cert, chain=[ca]).save("client.p12")
        """
        b = PKCS12Builder()
        b.set_key(self)
        b.set_cert(cert)
        if chain:
            b.add_chain(*chain)
        b.set_password(password)
        if name:
            b.set_name(name)
        b.set_iterations(iterations)
        if cipher != "aes-256-cbc":
            b.set_cipher(cipher)
        return b.build()


# ======================================================================
#  ECDSA — P-256, P-384, P-521, secp256k1
# ======================================================================


    def __eq__(self, other):
        return isinstance(other, Ed25519Keys) and self.pub == other.pub

    def __hash__(self):
        return hash(self.pub)
EC_CURVES = {
    OID_PRIME256V1: {
        "name": "P-256",
        "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        "Gx": 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        "Gy": 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        "size": 32,
    },
    OID_SECP384R1: {
        "name": "P-384",
        "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        "a": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        "b": 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        "Gx": 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        "Gy": 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        "n": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        "size": 48,
    },
    OID_SECP521R1: {
        "name": "P-521",
        "p": (1 << 521) - 1,
        "a": ((1 << 521) - 1) - 3,
        "b": 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        "Gx": 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        "Gy": 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        "n": 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
        "size": 66,
    },
    OID_SECP256K1: {
        "name": "secp256k1",
        "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        "a": 0,
        "b": 7,
        "Gx": 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        "Gy": 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
        "n": 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
        "size": 32,
    },
}


def _ec_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _ec_mul(k, P, a, p):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, a, p)
        P = _ec_add(P, P, a, p)
        k >>= 1
    return R


def _ec_encode_point(P, size):
    if P is None:
        return b"\x00"
    x, y = P
    return b"\x04" + x.to_bytes(size, "big") + y.to_bytes(size, "big")


def _ec_decode_point(data, curve):
    size = curve["size"]
    if not data:
        return None
    tag = data[0]
    if tag == 0x04:                        # uncompressed
        if len(data) != 1 + 2 * size:
            return None
        x = int.from_bytes(data[1:1 + size], "big")
        y = int.from_bytes(data[1 + size:], "big")
    elif tag in (0x02, 0x03):              # compressed
        if len(data) != 1 + size:
            return None
        x = int.from_bytes(data[1:], "big")
        p = curve["p"]; a = curve["a"]; b = curve["b"]
        y2 = (pow(x, 3, p) + a * x + b) % p
        y = pow(y2, (p + 1) // 4, p) if p % 4 == 3 else None
        if y is None:
            return None
        if (y * y - y2) % p != 0:
            return None
        if (y & 1) != (tag & 1):
            y = p - y
    else:
        return None
    return (x, y)


def _encode_ecdsa_sig(r, s):
    return der_seq(der_int(r), der_int(s))


def _parse_ecdsa_sig(data):
    node, _ = ASN1.parse(data)
    if node.tag != TAG_SEQUENCE or len(node.children) != 2:
        raise X509ParseError("bad ECDSA-Sig-Value")
    return node.children[0].as_uint(), node.children[1].as_uint()


# ---- RFC 6979: deterministic k for ECDSA ----

def _bits2int(b, qlen):
    v = int.from_bytes(b, "big")
    blen = len(b) * 8
    if blen > qlen:
        v >>= (blen - qlen)
    return v


def _int2octets(v, rolen):
    return v.to_bytes(rolen, "big")


def _bits2octets(b, q, qlen, rolen):
    z1 = _bits2int(b, qlen)
    z2 = z1 % q
    return _int2octets(z2, rolen)


def _rfc6979_generate_k(x, h1, q, hash_name):
    """RFC 6979 §3.2 — HMAC-DRBG k."""
    hlen = hashlib.new(hash_name).digest_size
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8
    V = b"\x01" * hlen
    K = b"\x00" * hlen
    x_oct = _int2octets(x, rolen)
    h1_oct = _bits2octets(h1, q, qlen, rolen)

    K = hmac.new(K, V + b"\x00" + x_oct + h1_oct, hash_name).digest()
    V = hmac.new(K, V, hash_name).digest()
    K = hmac.new(K, V + b"\x01" + x_oct + h1_oct, hash_name).digest()
    V = hmac.new(K, V, hash_name).digest()

    while True:
        T = b""
        while len(T) < rolen:
            V = hmac.new(K, V, hash_name).digest()
            T += V
        k = _bits2int(T, qlen)
        if 1 <= k < q:
            return k
        K = hmac.new(K, V + b"\x00", hash_name).digest()
        V = hmac.new(K, V, hash_name).digest()


class ECDSAKeys:
    """ECDSA (P-256/P-384/P-521/secp256k1)."""

    __slots__ = ("curve_oid", "curve", "d", "point")

    def __init__(self, curve_oid, d=None, point=None):
        curve = EC_CURVES.get(curve_oid)
        if curve is None:
            raise X509Error(f"unsupported curve: {curve_oid}")
        self.curve_oid = curve_oid
        self.curve = curve
        if d is not None:
            n = curve["n"]
            if not (1 <= d < n):
                raise X509Error("private scalar out of range")
            self.d = d
            self.point = _ec_mul(d, (curve["Gx"], curve["Gy"]),
                                 curve["a"], curve["p"])
            if self.point is None:
                raise X509Error("bad private scalar")
        elif point is not None:
            self.d = None
            self.point = point
        else:
            raise ValueError("need d or point")

    @property
    def is_private(self): return self.d is not None
    @property
    def size_bits(self):  return self.curve["size"] * 8
    @property
    def weak(self):       return False
    @property
    def pub(self):
        return _ec_encode_point(self.point, self.curve["size"])

    def __repr__(self):
        kind = "private" if self.is_private else "public"
        return f"<ECDSAKeys {kind} {self.curve['name']}>"

    @classmethod
    def generate(cls, curve="P-256"):
        if curve not in ("P-256", "P-384", "P-521", "secp256k1"):
            raise ValueError(f"unknown curve: {curve}")
        oid = {
            "P-256": OID_PRIME256V1,
            "P-384": OID_SECP384R1,
            "P-521": OID_SECP521R1,
            "secp256k1": OID_SECP256K1,
        }[curve]
        c = EC_CURVES[oid]
        d = secrets.randbelow(c["n"] - 1) + 1
        return cls(oid, d=d)

    # ---- SPKI / PKCS#8 ----

    def to_public_der(self):
        alg = der_seq(encode_oid(OID_EC_PUBLIC_KEY), encode_oid(self.curve_oid))
        return der_seq(alg, der_bitstring(self.pub))

    def to_private_der(self):
        if not self.is_private:
            raise X509Error("private key required")
        d_bytes = self.d.to_bytes(self.curve["size"], "big")
        inner = der_seq(
            der_int(1),
            der_octet(d_bytes),
            _der_tlv(0xA1, der_bitstring(self.pub)),
        )
        alg = der_seq(encode_oid(OID_EC_PUBLIC_KEY), encode_oid(self.curve_oid))
        return der_seq(der_int(0), alg, der_octet(inner))

    @classmethod
    def from_public_der(cls, der):
        if len(der) == 1 + 2 * 48 or len(der) == 1 + 2 * 32 or len(der) == 1 + 2 * 66:
            for oid, c in EC_CURVES.items():
                if len(der) == 1 + 2 * c["size"]:
                    return cls(oid, point=_ec_decode_point(der, c))
            raise X509Error("EC point: unknown curve size")
        node, _ = ASN1.parse(der)
        if (node.tag == TAG_SEQUENCE and len(node.children) == 2
                and node.children[0].tag == TAG_SEQUENCE):
            params = node.children[0].children[1]
            curve_oid = params.as_oid()
            bits = node.children[1].value
            if not bits or bits[0] != 0:
                raise X509ParseError("EC SPKI: bad BIT STRING")
            c = EC_CURVES.get(curve_oid)
            if c is None:
                raise X509Error(f"unsupported EC curve: {curve_oid}")
            pt = _ec_decode_point(bits[1:], c)
            if pt is None:
                raise X509ParseError("bad EC point")
            return cls(curve_oid, point=pt)
        raise X509ParseError("not an EC public key")

    @classmethod
    def from_private_der(cls, der):
        node, _ = ASN1.parse(der)
        if (node.tag == TAG_SEQUENCE and len(node.children) == 3
                and node.children[0].tag == TAG_INTEGER
                and node.children[1].tag == TAG_SEQUENCE):
            alg = node.children[1]
            curve_oid = alg.children[1].as_oid()
            inner, _ = ASN1.parse(node.children[2].value)
            if inner.tag != TAG_SEQUENCE or len(inner.children) < 2:
                raise X509ParseError("bad ECPrivateKey inner")
            d_bytes = inner.children[1].value
            d = int.from_bytes(d_bytes, "big")
            return cls(curve_oid, d=d)
        raise X509ParseError("not an EC PKCS#8 private key")

    @classmethod
    def from_pem(cls, data, private=False, password=None):
        if isinstance(data, str): data = data.encode("ascii")
        want = {"PRIVATE KEY"} if private else {"PUBLIC KEY"}
        for label, der in pem_decode(data):
            if "ENCRYPTED PRIVATE KEY" in label:
                if password is None:
                    raise X509Error("PEM зашифрован, нужен password")
                der = _pkcs8_decrypt(der, password)
                return cls.from_private_der(der)
            if label in want:
                return cls.from_private_der(der) if private else cls.from_public_der(der)
        raise X509Error(f"no {'private' if private else 'public'} EC key in PEM")

    def to_public_pem(self):  return pem_encode("PUBLIC KEY", self.to_public_der())

    def to_private_pem(self, password=None, *, iterations=100000,
                       cipher="aes-256-cbc"):
        if password is None:
            return pem_encode("PRIVATE KEY", self.to_private_der())
        enc = _pkcs8_encrypt(self.to_private_der(), password,
                             iterations=iterations, cipher=cipher)
        return pem_encode("ENCRYPTED PRIVATE KEY", enc)

    # ---- sign / verify ----

    def _hash_to_int(self, data, hash_name):
        h = hashlib.new(hash_name, data).digest()
        z = int.from_bytes(h, "big")
        n_bits = self.curve["n"].bit_length()
        if z.bit_length() > n_bits:
            z >>= (z.bit_length() - n_bits)
        return z

    def sign(self, data, hash_name="sha256", deterministic=True):
        """Подписать. По умолчанию RFC 6979 (детерминированный k)."""
        if not self.is_private:
            raise X509Error("private key required")
        if hash_name not in ("sha256", "sha384", "sha512"):
            raise ValueError(f"unsupported hash for ECDSA: {hash_name}")
        curve = self.curve
        n = curve["n"]
        G = (curve["Gx"], curve["Gy"])
        a, p = curve["a"], curve["p"]
        h1 = hashlib.new(hash_name, data).digest()
        z = self._hash_to_int(data, hash_name)

        if deterministic:
            k = _rfc6979_generate_k(self.d, h1, n, hash_name)
            R = _ec_mul(k, G, a, p)
            if R is None:
                raise X509Error("RFC 6979: point at infinity")
            r = R[0] % n
            if r == 0:
                raise X509Error("RFC 6979: r == 0")
            s = (pow(k, -1, n) * (z + r * self.d)) % n
            if s == 0:
                raise X509Error("RFC 6979: s == 0")
            return _encode_ecdsa_sig(r, s)

        while True:
            k = secrets.randbelow(n - 1) + 1
            R = _ec_mul(k, G, a, p)
            if R is None:
                continue
            r = R[0] % n
            if r == 0:
                continue
            s = (pow(k, -1, n) * (z + r * self.d)) % n
            if s == 0:
                continue
            return _encode_ecdsa_sig(r, s)

    def verify(self, data, signature, hash_name="sha256"):
        if hash_name not in ("sha256", "sha384", "sha512"):
            return False
        try:
            r, s = _parse_ecdsa_sig(signature)
        except Exception:
            return False
        curve = self.curve
        n = curve["n"]
        if not (1 <= r < n and 1 <= s < n):
            return False
        z = self._hash_to_int(data, hash_name)
        w = pow(s, -1, n)
        u1 = (z * w) % n
        u2 = (r * w) % n
        G = (curve["Gx"], curve["Gy"])
        a, p = curve["a"], curve["p"]
        P = _ec_add(_ec_mul(u1, G, a, p),
                    _ec_mul(u2, self.point, a, p), a, p)
        if P is None:
            return False
        return P[0] % n == r

    def sign_pss(self, *a, **k):
        raise X509Error("ECDSA does not support PSS")

    def wipe(self):
        self.d = None


    def to_pkcs12(self, cert, chain=None, password="", name=None,
                  iterations=2048, cipher="aes-256-cbc"):
        """Упаковать этот ключ + сертификат (+цепочку) в PKCS#12.

        Возвращает PKCS12. Для сохранения:
            key.to_pkcs12(cert, chain=[ca]).save("client.p12")
        """
        b = PKCS12Builder()
        b.set_key(self)
        b.set_cert(cert)
        if chain:
            b.add_chain(*chain)
        b.set_password(password)
        if name:
            b.set_name(name)
        b.set_iterations(iterations)
        if cipher != "aes-256-cbc":
            b.set_cipher(cipher)
        return b.build()


# ======================================================================
#  SPKI
# ======================================================================


    def __eq__(self, other):
        return (isinstance(other, ECDSAKeys)
                and self.curve_oid == other.curve_oid
                and self.point == other.point)

    def __hash__(self):
        return hash((self.curve_oid, self.point))
def _parse_spki(node):
    alg = AlgorithmIdentifier(node.children[0])
    bits_node = node.children[1]
    if bits_node.tag != TAG_BIT_STRING or not bits_node.value:
        raise X509ParseError("subjectPublicKey must be BIT STRING")
    if bits_node.value[0] != 0:
        raise X509ParseError("SPKI BIT STRING must have zero unused bits")
    key_data = bits_node.value[1:]
    if alg.oid == OID_RSA_ENCRYPTION:
        return RSAKeys.from_public_der(key_data), alg.oid, node.raw
    if alg.oid == OID_ED25519:
        return Ed25519Keys(pub=key_data), alg.oid, node.raw
    if alg.oid == OID_EC_PUBLIC_KEY:
        if alg.params is None:
            raise X509ParseError("EC SPKI: missing curve params")
        curve_oid = alg.params.as_oid()
        c = EC_CURVES.get(curve_oid)
        if c is None:
            raise X509Error(f"unsupported EC curve: {curve_oid}")
        pt = _ec_decode_point(key_data, c)
        if pt is None:
            raise X509ParseError("bad EC point in SPKI")
        return ECDSAKeys(curve_oid, point=pt), alg.oid, node.raw
    return ("raw", alg.oid, key_data), alg.oid, node.raw


# ======================================================================
#  Extensions
# ======================================================================

KU_BITS = {
    "digitalSignature": 0, "nonRepudiation": 1, "keyEncipherment": 2,
    "dataEncipherment": 3, "keyAgreement": 4, "keyCertSign": 5,
    "cRLSign": 6, "encipherOnly": 7, "decipherOnly": 8,
}


def _parse_time(node):
    try:
        s = node.value.decode("ascii")
        if node.tag == TAG_UTC_TIME:
            yy = int(s[0:2]); year = 2000 + yy if yy < 50 else 1900 + yy; p = 2
        elif node.tag == TAG_GENERALIZED_TIME:
            year = int(s[0:4]); p = 4
        else:
            raise X509ParseError(f"not a time tag: 0x{node.tag:02x}")
        month  = int(s[p:p+2]); p += 2
        day    = int(s[p:p+2]); p += 2
        hour   = int(s[p:p+2]); p += 2
        minute = int(s[p:p+2]); p += 2
        second = 0
        if p + 2 <= len(s) and s[p:p+2].isdigit():
            second = int(s[p:p+2]); p += 2
        tz = datetime.timedelta(0)
        rest = s[p:]
        if rest and rest[0] in "+-":
            sign = 1 if rest[0] == "+" else -1
            hh, mm = int(rest[1:3]), int(rest[3:5])
            tz = sign * datetime.timedelta(hours=hh, minutes=mm)
        return datetime.datetime(year, month, day, hour, minute, second,
                                 tzinfo=datetime.timezone(tz))
    except (ValueError, TypeError, UnicodeDecodeError, IndexError) as e:
        raise X509ParseError(f"invalid time value: {e}") from None
def _enc_time(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt = dt.astimezone(datetime.timezone.utc)
    if 1950 <= dt.year <= 2049:
        return _der_tlv(TAG_UTC_TIME, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return _der_tlv(TAG_GENERALIZED_TIME, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


class Validity:
    __slots__ = ("not_before", "not_after")

    @_safe_parse
    def __init__(self, node):
        self.not_before = _parse_time(node.children[0])
        self.not_after = _parse_time(node.children[1])

    def __repr__(self):
        return f"<Validity {self.not_before.isoformat()} .. {self.not_after.isoformat()}>"


class Extension:
    __slots__ = ("oid", "critical", "value")

    @_safe_parse
    def __init__(self, node):
        ch = node.children
        self.oid = ch[0].as_oid()
        if len(ch) == 3:
            self.critical = ch[1].as_bool(); self.value = ch[2].value
        elif len(ch) == 2:
            self.critical = False; self.value = ch[1].value
        else:
            raise X509ParseError("bad Extension structure")

    def __repr__(self):
        return f"<Extension {self.oid}{' critical' if self.critical else ''}>"


def _parse_san(data):
    node, _ = ASN1.parse(data)
    if node.tag != TAG_SEQUENCE:
        return []
    out = []
    for gn in node.children:
        t = gn.tag
        if t == 0x82:
            out.append(("dNSName", gn.value.decode("ascii", "replace")))
        elif t == 0x81:
            out.append(("rfc822Name", gn.value.decode("ascii", "replace")))
        elif t == 0x86:
            out.append(("URI", gn.value.decode("ascii", "replace")))
        elif t == 0x87:
            if len(gn.value) == 4:
                out.append(("iPAddress", socket.inet_ntop(socket.AF_INET, gn.value)))
            elif len(gn.value) == 16:
                out.append(("iPAddress", socket.inet_ntop(socket.AF_INET6, gn.value)))
            else:
                out.append(("iPAddress", gn.value.hex()))
        elif t == 0xA4:
            out.append(("directoryName", str(Name(gn.children[0]))))
        else:
            out.append((f"tag0x{t:02x}", gn.value.hex()))
    return out


def _parse_basic_constraints(data):
    node, _ = ASN1.parse(data)
    if node.tag != TAG_SEQUENCE:
        return False, None
    is_ca, path_len, i = False, None, 0
    if i < len(node.children) and node.children[i].tag == TAG_BOOLEAN:
        is_ca = node.children[i].as_bool(); i += 1
    if i < len(node.children) and node.children[i].tag == TAG_INTEGER:
        path_len = node.children[i].as_int()
        if path_len < 0:
            raise X509ParseError("negative path_len")
    return is_ca, path_len


def _parse_key_usage(data):
    node, _ = ASN1.parse(data)
    if node.tag != TAG_BIT_STRING or not node.value:
        return set()
    bits = node.value[1:]
    out = set()
    for name, bit in KU_BITS.items():
        byte_idx, bit_idx = bit // 8, 7 - (bit % 8)
        if byte_idx < len(bits) and (bits[byte_idx] >> bit_idx) & 1:
            out.add(name)
    return out


def _enc_basic_constraints(is_ca, path_len=None):
    parts = []
    if is_ca:
        parts.append(der_bool(True))
    if path_len is not None:
        if path_len < 0:
            raise ValueError("negative path_len")
        parts.append(der_int(path_len))
    return der_seq(*parts)


def _enc_key_usage(names):
    names = list(names)
    if not names:
        raise ValueError("empty KeyUsage")
    for n in names:
        if n not in KU_BITS:
            raise ValueError(f"unknown KeyUsage bit: {n}")
    max_bit = max(KU_BITS[n] for n in names)
    nbytes = max_bit // 8 + 1
    buf = bytearray(nbytes)
    for n in names:
        b = KU_BITS[n]
        buf[b // 8] |= 1 << (7 - (b % 8))
    unused = nbytes * 8 - (max_bit + 1)
    return _der_tlv(TAG_BIT_STRING, bytes([unused]) + bytes(buf))


def _enc_extension(oid, critical, value_der):
    parts = [encode_oid(oid)]
    if critical:
        parts.append(der_bool(True))
    parts.append(der_octet(value_der))
    return der_seq(*parts)


def san_extension(*, dns_names=None, emails=None, ips=None, uris=None):
    parts = []
    for name in (dns_names or []):
        parts.append(_der_tlv(0x82, name.encode("ascii")))
    for e in (emails or []):
        parts.append(_der_tlv(0x81, e.encode("ascii")))
    for ip in (ips or []):
        try:
            packed = socket.inet_pton(socket.AF_INET, ip)
        except OSError:
            packed = socket.inet_pton(socket.AF_INET6, ip)
        parts.append(_der_tlv(0x87, packed))
    for u in (uris or []):
        parts.append(_der_tlv(0x86, u.encode("ascii")))
    if not parts:
        raise ValueError("SAN extension needs at least one name")
    return _enc_extension(OID_SAN, False, der_seq(*parts))


# ---- SAN: отдельные типы GeneralName ----

_SAN_TAG_EMAIL = 0x81   # [1] rfc822Name
_SAN_TAG_DNS   = 0x82   # [2] dNSName
_SAN_TAG_URI   = 0x86   # [6] URI
_SAN_TAG_IP    = 0x87   # [7] iPAddress
_SAN_TAG_DN    = 0xA4   # [4] directoryName (constructed)


def _san_entry_dns(name):
    return (_SAN_TAG_DNS, name.encode("ascii"))


def _san_entry_email(email):
    return (_SAN_TAG_EMAIL, email.encode("ascii"))


def _san_entry_uri(uri):
    return (_SAN_TAG_URI, uri.encode("ascii"))


def _san_entry_ip(ip):
    if isinstance(ip, (bytes, bytearray)):
        if len(ip) not in (4, 16):
            raise ValueError(f"IP bytes must be 4 or 16, got {len(ip)}")
        return (_SAN_TAG_IP, bytes(ip))
    try:
        packed = socket.inet_pton(socket.AF_INET, ip)
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, ip)
    return (_SAN_TAG_IP, packed)


def _san_entry_dn(name_der):
    return (_SAN_TAG_DN, bytes(name_der))


# ---- Информативные ошибки ----

def _fail(what, how=None):
    msg = what
    if how:
        msg += f"\n  Как исправить: {how}"
    raise X509Error(msg)


def _spki_pub_matches(spki_der, key):
    try:
        node, _ = ASN1.parse(spki_der)
        pub, _, _ = _parse_spki(node)
    except Exception:
        return True
    return _public_keys_equal(pub, key)


def _is_ca_cert(cert):
    bc = cert.ext_get(OID_BASIC_CONSTR)
    if bc is None:
        return False
    try:
        is_ca, _ = _parse_basic_constraints(bc.value)
        return is_ca
    except Exception:
        return False


# ---- SKI / AKI (RFC 5280 §4.2.1.2 / §4.2.1.1) ----

def _compute_ski(spki_der):
    """SKI = SHA-1 от BIT STRING subjectPublicKey (без тега, длины и unused-bits)."""
    if not spki_der:
        return None
    try:
        node, _ = ASN1.parse(spki_der)
        bits_node = node.children[1]
        if bits_node.tag != TAG_BIT_STRING or not bits_node.value:
            return None
        return hashlib.sha1(bits_node.value[1:]).digest()
    except Exception:
        return None


def _extract_ski(cert):
    """SubjectKeyIdentifier bytes(20) или None."""
    ext = cert.ext_get(OID_SUBJ_KEY_ID)
    if ext is None:
        return None
    try:
        node, _ = ASN1.parse(ext.value)
        if node.tag == TAG_OCTET_STRING:
            return node.value
    except Exception:
        pass
    return None


def _extract_aki(cert):
    """AuthorityKeyIdentifier keyIdentifier bytes или None."""
    ext = cert.ext_get(OID_AUTH_KEY_ID)
    if ext is None:
        return None
    try:
        node, _ = ASN1.parse(ext.value)
        if node.tag != TAG_SEQUENCE:
            return None
        for child in node.children:
            if child.tag == 0x80:   # [0] KeyIdentifier implicit OCTET STRING
                return child.value
    except Exception:
        pass
    return None


# ---- Extended Key Usage ----

def _enc_eku(names):
    """Собрать Extension ExtendedKeyUsage из имён или OID'ов."""
    if not names:
        raise ValueError("EKU needs at least one purpose")
    oids = []
    for n in names:
        if n in EKU_OIDS:
            oids.append(EKU_OIDS[n])
        elif "." in str(n) and all(p.isdigit() for p in str(n).split(".")):
            oids.append(str(n))
        else:
            _fail(
                f"EKU: неизвестное назначение {n!r}.",
                "используй одно из: " + ", ".join(sorted(EKU_OIDS))
            )
    body = der_seq(*[encode_oid(o) for o in oids])
    return _enc_extension(OID_EXT_KEY_USAGE, False, body)


def _parse_eku(data):
    """Распарсить extnValue ExtendedKeyUsage → set имён или OID-строк."""
    node, _ = ASN1.parse(data)
    if node.tag != TAG_SEQUENCE:
        return set()
    out = set()
    for child in node.children:
        oid = child.as_oid()
        out.add(EKU_OIDS_REV.get(oid, oid))
    return out


# ---- Name Constraints (RFC 5280 §4.2.1.10) ----

def _enc_ip_subnet(cidr):
    """'10.0.0.0/8' → 8 байт (IPv4) или 32 (IPv6): base || mask."""
    import ipaddress as _ip
    try:
        net = _ip.ip_network(cidr, strict=False)
    except (ValueError, TypeError) as e:
        _fail(f"Name Constraints: неверный IP/CIDR {cidr!r}: {e}",
              "пример: '10.0.0.0/8' или '2001:db8::/32'")
    return net.network_address.packed + net.netmask.packed


def _parse_ip_subnet(data):
    """base||mask (8 или 32 байт) → CIDR-строка.
    Явно разбираем base/mask, не полагаясь на семантику IPv4Network((int,int))."""
    import ipaddress as _ip
    if len(data) == 8:
        base_int = int.from_bytes(data[:4], "big")
        mask_int = int.from_bytes(data[4:], "big")
        # Проверим, что маска непрерывная (1...10...0)
        # prefix = число единичных бит слева
        prefix = 0
        for i in range(31, -1, -1):
            if mask_int & (1 << i):
                prefix += 1
            else:
                break
        expected_mask = (((1 << prefix) - 1) << (32 - prefix)) & 0xFFFFFFFF
        if mask_int != expected_mask:
            raise X509ParseError(f"non-contiguous IPv4 netmask: 0x{mask_int:08x}")
        return f"{_ip.IPv4Address(base_int)}/{prefix}"
    if len(data) == 32:
        base_int = int.from_bytes(data[:16], "big")
        mask_int = int.from_bytes(data[16:], "big")
        prefix = 0
        for i in range(127, -1, -1):
            if mask_int & (1 << i):
                prefix += 1
            else:
                break
        expected_mask = (((1 << prefix) - 1) << (128 - prefix)) & ((1 << 128) - 1)
        if mask_int != expected_mask:
            raise X509ParseError(f"non-contiguous IPv6 netmask")
        return f"{_ip.IPv6Address(base_int)}/{prefix}"
    raise X509ParseError(f"bad IP subnet length: {len(data)}")


def _enc_general_subtree(kind, value):
    """Один GeneralSubtree."""
    if kind == "dns":
        return der_seq(_der_tlv(0x82, value.encode("ascii")))
    if kind == "email":
        return der_seq(_der_tlv(0x81, value.encode("ascii")))
    if kind == "uri":
        return der_seq(_der_tlv(0x86, value.encode("ascii")))
    if kind == "ip":
        return der_seq(_der_tlv(0x87, _enc_ip_subnet(value)))
    raise ValueError(f"unknown NC kind: {kind}")


def _enc_name_constraints(permitted, excluded):
    """NameConstraints extension (critical)."""
    parts = []
    if permitted:
        subs = []
        for kind, values in permitted.items():
            for v in values:
                subs.append(_enc_general_subtree(kind, v))
        parts.append(_der_tlv(0xA0, der_seq(*subs)))
    if excluded:
        subs = []
        for kind, values in excluded.items():
            for v in values:
                subs.append(_enc_general_subtree(kind, v))
        parts.append(_der_tlv(0xA1, der_seq(*subs)))
    return _enc_extension(OID_NAME_CONSTR, True, der_seq(*parts))


def _parse_general_subtrees(node):
    """SEQUENCE OF GeneralSubtree → {kind: [values]}."""
    out = {}
    if node.tag != TAG_SEQUENCE:
        return out
    for st in node.children:
        if not st.children:
            continue
        base = st.children[0]
        t = base.tag
        try:
            if t == 0x82:
                val = base.value.decode("ascii", "replace")
                out.setdefault("dns", []).append(val)
            elif t == 0x81:
                val = base.value.decode("ascii", "replace")
                out.setdefault("email", []).append(val)
            elif t == 0x86:
                val = base.value.decode("ascii", "replace")
                out.setdefault("uri", []).append(val)
            elif t == 0x87:
                val = _parse_ip_subnet(base.value)
                out.setdefault("ip", []).append(val)
        except Exception:
            # Ключ не создаём, если значение не распарсилось
            continue
    return out


def _parse_name_constraints(data):
    """extnValue → {'permitted': {...}, 'excluded': {...}}."""
    node, _ = ASN1.parse(data)
    result = {"permitted": {}, "excluded": {}}
    if node.tag != TAG_SEQUENCE:
        return result
    for child in node.children:
        if child.tag == 0xA0 and child.children:
            result["permitted"] = _parse_general_subtrees(child.children[0])
        elif child.tag == 0xA1 and child.children:
            result["excluded"] = _parse_general_subtrees(child.children[0])
    return result


def _dns_in_subtree(name, base):
    name = name.lower().rstrip(".")
    base = base.lower().rstrip(".")
    if base.startswith("."):
        return name.endswith(base) and name != base[1:]
    return name == base or name.endswith("." + base)


def _email_in_subtree(email, base):
    base = base.lower()
    email = email.lower()
    if "@" in base:
        return email == base
    domain = email.rsplit("@", 1)[1] if "@" in email else email
    return _dns_in_subtree(domain, base)


def _uri_in_subtree(uri, base):
    from urllib.parse import urlparse
    try:
        host = urlparse(uri).hostname or ""
    except Exception:
        return False
    if not host:
        return False
    return _dns_in_subtree(host, base)


def _ip_in_subnet(ip_str, cidr):
    import ipaddress as _ip
    try:
        addr = _ip.ip_address(ip_str)
        net = _ip.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False
    if addr.version != net.version:
        return False
    return addr in net


def _name_matches_constraint(kind, name, base):
    try:
        if kind == "dns":   return _dns_in_subtree(name, base)
        if kind == "email": return _email_in_subtree(name, base)
        if kind == "uri":   return _uri_in_subtree(name, base)
        if kind == "ip":    return _ip_in_subnet(name, base)
    except Exception:
        return False
    return False


# ---- NC intersection (RFC 5280 §4.2.1.10) ----

def _dns_base_contains(outer, inner):
    """True если DNS-поддерево inner внутри outer.

    outer=".example.com", inner=".sub.example.com" → True
    outer=".example.com", inner="example.com"      → False
    outer="example.com",  inner="sub.example.com"  → True
    outer=".example.com", inner=".example.com"     → True
    """
    o_strip = outer.lstrip(".").lower()
    i_strip = inner.lstrip(".").lower()
    if o_strip == i_strip:
        # outer с ведущей точкой не содержит bare domain
        if outer.startswith(".") and not inner.startswith("."):
            return False
        return True
    return i_strip.endswith("." + o_strip)


def _ip_base_contains(outer, inner):
    """True если IP-подсеть inner внутри outer."""
    import ipaddress as _ip
    try:
        o = _ip.ip_network(outer, strict=False)
        i = _ip.ip_network(inner, strict=False)
    except (ValueError, TypeError):
        return False
    if o.version != i.version:
        return False
    try:
        return i.subnet_of(o)
    except AttributeError:
        return i.network_address in o and i.netmask == i.netmask and \
               (int(i.network_address) & int(o.netmask)) == int(o.network_address)


def _nc_base_contains(kind, outer, inner):
    """Универсально: поддерево inner внутри outer для указанного типа."""
    if kind == "dns" or kind == "email" or kind == "uri":
        return _dns_base_contains(outer, inner)
    if kind == "ip":
        return _ip_base_contains(outer, inner)
    return False


def _nc_sub_constraint_of(child_nc, parent_nc):
    """True если child_nc ⊆ parent_nc (child строже или равен).

    Проверяет:
      * permitted child ⊆ permitted parent (для каждого типа)
      * permitted child не пересекается с excluded parent

    Возвращает (ok, reason).
    """
    child_perm = (child_nc or {}).get("permitted", {})
    parent_perm = (parent_nc or {}).get("permitted", {})
    parent_excl = (parent_nc or {}).get("excluded", {})

    # 1. permitted child внутри permitted parent
    for kind, child_bases in child_perm.items():
        parent_bases = parent_perm.get(kind, [])
        if not parent_bases:
            continue    # parent не ограничивает этот тип
        for cb in child_bases:
            if not any(_nc_base_contains(kind, pb, cb) for pb in parent_bases):
                return False, (f"child permitted {kind}={cb!r} "
                               f"not within parent {parent_bases}")

    # 2. permitted child не пересекает excluded parent
    for kind, parent_bases in parent_excl.items():
        child_bases = child_perm.get(kind, [])
        for pb in parent_bases:
            for cb in child_bases:
                if _nc_base_contains(kind, pb, cb):
                    return False, (f"child permitted {kind}={cb!r} "
                                   f"overlaps parent excluded {pb!r}")

    return True, None


def _check_name_constraints(names, nc):
    """names = [(kind, value)]; nc = parsed dict. Returns (ok, reason|None)."""
    permitted = nc.get("permitted", {})
    excluded = nc.get("excluded", {})
    for kind, value in names:
        for base in excluded.get(kind, []):
            if _name_matches_constraint(kind, value, base):
                return False, f"{kind} '{value}' matches excluded '{base}'"
        bases = permitted.get(kind)
        if bases:
            if not any(_name_matches_constraint(kind, value, b) for b in bases):
                return False, f"{kind} '{value}' not within permitted {bases}"
    return True, None


def _collect_names_from_san(san_list, subject_name):
    """[(kind,value)] из cert.san + CN."""
    out = []
    mapping = {"dNSName": "dns", "iPAddress": "ip",
               "rfc822Name": "email", "URI": "uri"}
    for kind, val in san_list:
        if kind in mapping:
            out.append((mapping[kind], val))
    if subject_name is not None:
        cn = subject_name.get("CN")
        # CN проверяем как dNSName только если он похож на DNS-имя
        # (иначе CA с CN="Test CA" не пройдёт NC, хотя RFC этого не требует)
        if cn and "." in cn:
            out.append(("dns", cn))
    return out


def _collect_names_from_builder(builder):
    """Собирает имена из Builder (san_entries + extensions с OID_SAN + CN)."""
    import ipaddress as _ip
    san_list = []
    for tag, val in (builder._san_entries or []):
        if tag == 0x82:
            san_list.append(("dNSName", val.decode("ascii", "replace")))
        elif tag == 0x81:
            san_list.append(("rfc822Name", val.decode("ascii", "replace")))
        elif tag == 0x86:
            san_list.append(("URI", val.decode("ascii", "replace")))
        elif tag == 0x87:
            if len(val) == 4:
                san_list.append(("iPAddress", str(_ip.IPv4Address(val))))
            elif len(val) == 16:
                san_list.append(("iPAddress", str(_ip.IPv6Address(val))))
    for ext in builder._extensions:
        if _ext_oid(ext) == OID_SAN:
            try:
                node, _ = ASN1.parse(ext)
                val_octet = node.children[-1].value
                san_list.extend(_parse_san(val_octet))
            except Exception:
                pass
    return _collect_names_from_san(san_list, builder._subject)


# ---- AIA (Authority Information Access, RFC 5280 §4.2.2.1) ----

def _enc_aia(ocsp=None, ca_issuers=None):
    """AIA extension DER (MUST be non-critical).

    Принимает готовые списки URL или строку (одна URL).
    """
    if isinstance(ocsp, str):
        ocsp = [ocsp]
    if isinstance(ca_issuers, str):
        ca_issuers = [ca_issuers]
    entries = []
    for url in (ocsp or []):
        entries.append(der_seq(
            encode_oid(OID_OCSP),
            _der_tlv(0x86, url.encode("ascii")),
        ))
    for url in (ca_issuers or []):
        entries.append(der_seq(
            encode_oid(OID_AD_CA_ISSUERS),
            _der_tlv(0x86, url.encode("ascii")),
        ))
    if not entries:
        raise ValueError("AIA needs at least one URL")
    return _enc_extension(OID_AIA, False, der_seq(*entries))


def _parse_aia(data):
    """extnValue → {'ocsp': [...], 'ca_issuers': [...]}."""
    node, _ = ASN1.parse(data)
    out = {"ocsp": [], "ca_issuers": []}
    if node.tag != TAG_SEQUENCE:
        return out
    for ad in node.children:
        if len(ad.children) < 2:
            continue
        method = ad.children[0].as_oid()
        loc = ad.children[1]
        if loc.tag == 0x86:                  # uniformResourceIdentifier
            url = loc.value.decode("ascii", "replace")
        elif loc.tag == 0x82:                # dNSName
            url = "dns:" + loc.value.decode("ascii", "replace")
        else:
            continue
        if method == OID_OCSP:
            out["ocsp"].append(url)
        elif method == OID_AD_CA_ISSUERS:
            out["ca_issuers"].append(url)
    return out


def _parse_key_id(v, context):
    """Принимает bytes/hex-строку, возвращает bytes."""
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
    elif isinstance(v, str):
        try:
            b = bytes.fromhex(v.replace(":", "").replace(" ", "").replace("-", ""))
        except ValueError:
            _fail(f"{context}: hex-строка не парсится: {v!r}")
    else:
        _fail(f"{context}: нужен bytes или hex-строка, получен {type(v).__name__}")
    if not b:
        _fail(f"{context}: пустой key id")
    return b


def _enc_ski_ext(key_id):
    """Extension SubjectKeyIdentifier: OCTET STRING внутри extnValue."""
    return _enc_extension(OID_SUBJ_KEY_ID, False, der_octet(key_id))


def _enc_aki_ext(key_id):
    """Extension AuthorityKeyIdentifier: SEQUENCE { [0] KeyIdentifier }."""
    return _enc_extension(
        OID_AUTH_KEY_ID, False,
        der_seq(_der_tlv(0x80, key_id)),
    )


def _aki_ski_match(cert, issuer):
    """True если cert.aki == issuer.ski, либо у кого-то нет значения."""
    aki = _extract_aki(cert)
    ski = _extract_ski(issuer)
    if aki is None or ski is None:
        return True
    return aki == ski


def _build_san_extension(entries):
    """Собрать одно SAN-расширение из списка (tag, value)."""
    if not entries:
        raise ValueError("SAN needs at least one entry")
    parts = []
    for tag, value in entries:
        if tag == _SAN_TAG_DN:
            parts.append(_der_tlv(tag | 0x20, value))
        else:
            parts.append(_der_tlv(tag, value))
    return _enc_extension(OID_SAN, False, der_seq(*parts))


# ======================================================================
#  Cert
# ======================================================================

class Cert:
    @_safe_parse
    def __init__(self, data):
        if isinstance(data, str):
            data = data.encode("ascii")
        if b"-----BEGIN" in data:
            for label, der in pem_decode(data):
                if "CERTIFICATE" in label and "REQUEST" not in label:
                    data = der; break
            else:
                raise X509ParseError("no CERTIFICATE block in PEM input")

        self.der = bytes(data)
        root, _ = ASN1.parse(self.der)
        if root.tag != TAG_SEQUENCE or len(root.children) != 3:
            raise X509ParseError("not an X.509 Certificate")
        tbs, sig_alg, sig_val = root.children
        if sig_val.tag != TAG_BIT_STRING or not sig_val.value:
            raise X509ParseError("signatureValue must be non-empty BIT STRING")
        if sig_val.value[0] != 0:
            raise X509ParseError("signature BIT STRING must have zero unused bits")

        self.tbs_der = tbs.raw
        self.signature = sig_val.value[1:]
        self.signature_algorithm = AlgorithmIdentifier(sig_alg)
        self._parse_tbs(tbs)

        hash_name = SIG_ALG_RSA_HASH.get(self.signature_algorithm.oid)
        self.weak_hash = hash_name in WEAK_HASHES
        self.has_unknown_critical = any(
            e.critical and e.oid not in KNOWN_EXTENSION_OIDS
            for e in self.extensions
        )

    def _parse_tbs(self, tbs):
        ch = list(tbs.children)
        i = 0
        version = 1
        if ch[0].tag == 0xA0:
            version = ch[0].children[0].as_int() + 1
            i = 1
        self.version = version
        serial = ch[i].as_uint(); i += 1
        if serial == 0:
            raise X509ParseError("serial number must be positive")
        self.serial = serial
        self.tbs_signature_algorithm = AlgorithmIdentifier(ch[i]); i += 1
        self.issuer = Name(ch[i]); i += 1
        self.validity = Validity(ch[i]); i += 1
        self.subject = Name(ch[i]); i += 1
        self.public_key, self.key_algorithm_oid, self.spki_der = _parse_spki(ch[i]); i += 1
        self.extensions = []
        while i < len(ch):
            c = ch[i]
            if c.tag == 0xA3:
                for ext in c.children[0].children:
                    self.extensions.append(Extension(ext))
            i += 1

    @property
    def not_before(self): return self.validity.not_before
    @property
    def not_after(self):  return self.validity.not_after
    @property
    def signature_algorithm_name(self): return self.signature_algorithm.name

    @property
    def san(self):
        ext = self.ext_get(OID_SAN)
        return _parse_san(ext.value) if ext else []





    @property
    def dns_names(self):
        """Список dNSName из SAN."""
        return [v for kind, v in self.san if kind == "dNSName"]

    @property
    def ip_addresses(self):
        """Список iPAddress из SAN (уже как строки)."""
        return [v for kind, v in self.san if kind == "iPAddress"]

    @property
    def emails(self):
        """Список rfc822Name из SAN."""
        return [v for kind, v in self.san if kind == "rfc822Name"]

    @property
    def uris(self):
        """Список URI из SAN."""
        return [v for kind, v in self.san if kind == "URI"]

    @property
    def crl_distribution_points(self):
        """Список URL из CRL Distribution Points."""
        ext = self.ext_get(OID_CRL_DP)
        if ext is None:
            return []
        try:
            node, _ = ASN1.parse(ext.value)
            out = []
            for dp in node.children:
                for sub in dp.children:
                    if sub.tag == 0xA0:
                        for name in sub.children:
                            if name.tag == 0xA0:
                                for uri in name.children:
                                    if uri.tag == 0x86:
                                        out.append(uri.value.decode("ascii", "replace"))
            return out
        except Exception:
            return []
    @property
    def aki(self):
        """AuthorityKeyIdentifier keyIdentifier (bytes) или None."""
        return _extract_aki(self)

    @property
    def eku(self):
        """Extended Key Usage (set имён или OID-строк). Пустой set, если нет."""
        ext = self.ext_get(OID_EXT_KEY_USAGE)
        if ext is None:
            return set()
        try:
            return _parse_eku(ext.value)
        except Exception:
            return set()

    def has_eku(self, purpose):
        """Есть ли назначение (по имени или OID) в EKU.
        Пустой EKU означает «любое назначение» (RFC 5280).
        """
        e = self.eku
        if not e:
            return True
        if purpose in EKU_OIDS:
            return purpose in e or "anyExtendedKeyUsage" in e
        return purpose in e or "anyExtendedKeyUsage" in e

    @property
    def name_constraints(self):
        """Разобранные Name Constraints (dict) или None, если нет."""
        ext = self.ext_get(OID_NAME_CONSTR)
        if ext is None:
            return None
        try:
            return _parse_name_constraints(ext.value)
        except Exception:
            return None

    def name_matches(self, other):
        """Каноничное сравнение subject'а этого сертификата с другим.

        Принимает Cert (сравнит subject'ы), Name или строку.

        Пример:
            leaf.name_matches(ca)              # leaf.subject ~= ca.subject
            leaf.name_matches(ca.issuer)       # ~
            leaf.subject_matches_issuer(ca)    # алиас
        """
        if isinstance(other, Cert):
            other_name = other.subject
        elif isinstance(other, Name):
            other_name = other
        else:
            raise TypeError(
                f"name_matches: ожидался Cert или Name, получен {type(other).__name__}"
            )
        return names_equal(self.subject, other_name)

    def subject_matches_issuer(self, issuer_cert):
        """Канонично: этот сертификат имеет issuer, эквивалентный
        subject'у issuer_cert.

        Не то же самое, что verify_signature — там проверяется подпись.
        Здесь — что имя issuer'а семантически совпадает с именем CA.
        """
        if isinstance(issuer_cert, Cert):
            other = issuer_cert.subject
        elif isinstance(issuer_cert, Name):
            other = issuer_cert
        else:
            raise TypeError("subject_matches_issuer: ожидался Cert или Name")
        return names_equal(self.issuer, other)

    @property
    def aia(self):
        """AIA (dict {'ocsp': [...], 'ca_issuers': [...]}) или None."""
        ext = self.ext_get(OID_AIA)
        if ext is None:
            return None
        try:
            return _parse_aia(ext.value)
        except Exception:
            return None

    @property
    def aia_ocsp(self):
        """Список URL OCSP-responder'ов (пустой, если нет AIA)."""
        a = self.aia
        return a["ocsp"] if a else []

    @property
    def aia_issuers(self):
        """Список URL для скачивания issuer-сертификата."""
        a = self.aia
        return a["ca_issuers"] if a else []

    def ext_get(self, oid):
        for e in self.extensions:
            if e.oid == oid:
                return e
        return None

    def is_valid_at(self, when=None):
        when = when or datetime.datetime.now(datetime.timezone.utc)
        return self.not_before <= when <= self.not_after

    def verify_signature(self, issuer):
        key = issuer.public_key if isinstance(issuer, Cert) else issuer
        return _verify_signed_data(
            self.tbs_der, self.signature, self.signature_algorithm, key)

    def is_self_signed(self):
        if self.subject.raw != self.issuer.raw:
            return False
        try:
            return self.verify_signature(self.public_key)
        except Exception:
            return False

    def to_der(self): return self.der
    def to_pem(self): return pem_encode("CERTIFICATE", self.der)

    def __repr__(self):
        return f"<Cert subject={self.subject!r} serial=0x{self.serial:x}>"

    def __str__(self):
        lines = [
            f"Certificate v{self.version}",
            f"  Serial:   0x{self.serial:x}",
            f"  Subject:  {self.subject}",
            f"  Issuer:   {self.issuer}",
            f"  Validity: {self.not_before.isoformat()} .. {self.not_after.isoformat()}",
            f"  Sig alg:  {self.signature_algorithm_name}"
            + (" [WEAK]" if self.weak_hash else ""),
        ]
        key = self.public_key
        if isinstance(key, RSAKeys):
            lines.append(f"  Pubkey:   RSA {key.size_bits} bit (e={key.e})"
                         + (" [WEAK]" if key.weak else ""))
        elif isinstance(key, Ed25519Keys):
            lines.append(f"  Pubkey:   Ed25519")
        else:
            lines.append(f"  Pubkey:   {self.key_algorithm_oid}")
        if self.extensions:
            lines.append(f"  Extensions: {len(self.extensions)}")
            for e in self.extensions:
                crit = " [critical]" if e.critical else ""
                known = "" if e.oid in KNOWN_EXTENSION_OIDS else " [UNKNOWN]"
                lines.append(f"    - {e.oid}{crit}{known}")
        san = self.san
        if san:
            lines.append("  SAN:")
            for kind, val in san:
                lines.append(f"    - {kind}: {val}")
        return "\n".join(lines)


# ======================================================================
#  Сборка cert DER (используется и в CACert, и в Builder)
# ======================================================================

# ======================================================================
#  Диспетчер крипто-операций (RSA / Ed25519 / ECDSA)
#  Единое место для sig_alg / sign / verify / сравнения публичных ключей.
# ======================================================================


    def __eq__(self, other):
        return isinstance(other, Cert) and self.der == other.der

    def __hash__(self):
        return hash(self.der)


    @classmethod
    def from_url(cls, url, port=None, timeout=5, verify=False):
        """Загрузить сертификат с HTTPS-сервера.

        url — "https://example.com" или просто "example.com"
        verify=False (default) — принять любой сертификат (для инспекции)
        verify=True — упасть, если сертификат невалиден

        Возвращает Cert.
        """
        import ssl as _ssl
        from urllib.parse import urlparse

        if "://" in url:
            parsed = urlparse(url)
            host = parsed.hostname
            if port is None:
                port = parsed.port or 443
        else:
            host = url
            if port is None:
                port = 443
        if not host:
            raise X509Error(f"Cert.from_url: cannot parse host from {url!r}")

        if verify:
            ctx = _ssl.create_default_context()
        else:
            ctx = _ssl._create_unverified_context()

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)

        return cls(der)

    def info(self):
        """Текстовое представление в стиле `openssl x509 -text`."""
        def _fmt_time(dt):
            return dt.strftime("%b %d %H:%M:%S %Y GMT")

        lines = []
        lines.append("Certificate:")
        lines.append("    Data:")
        lines.append(f"        Version: {self.version} (0x{self.version - 1:x})")
        lines.append(f"        Serial Number: {self.serial} (0x{self.serial:x})")
        lines.append(f"        Signature Algorithm: {self.signature_algorithm_name}")
        lines.append(f"        Issuer: {self.issuer}")
        lines.append( "        Validity")
        lines.append(f"            Not Before: {_fmt_time(self.not_before)}")
        lines.append(f"            Not After : {_fmt_time(self.not_after)}")
        lines.append(f"        Subject: {self.subject}")

        key = self.public_key
        lines.append("        Subject Public Key Info:")
        if isinstance(key, RSAKeys):
            lines.append("            Public Key Algorithm: rsaEncryption")
            lines.append(f"                Public-Key: ({key.size_bits} bit)")
            h = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big").hex()
            lines.append("                Modulus:")
            for i in range(0, len(h), 64):
                lines.append(f"                    {h[i:i+64]}")
            lines.append(f"                Exponent: {key.e} (0x{key.e:x})")
        elif isinstance(key, Ed25519Keys):
            lines.append("            Public Key Algorithm: ED25519")
            lines.append("                ED25519 Public-Key:")
            h = key.pub.hex()
            for i in range(0, len(h), 64):
                lines.append(f"                    {h[i:i+64]}")
        elif isinstance(key, ECDSAKeys):
            lines.append("            Public Key Algorithm: id-ecPublicKey")
            lines.append(f"                ASN1 OID: {key.curve_oid}")
            size = key.curve["size"]
            x, y = key.point
            xh = x.to_bytes(size, "big").hex()
            yh = y.to_bytes(size, "big").hex()
            lines.append("                pub:")
            for i in range(0, len(xh), 64):
                lines.append(f"                    {xh[i:i+64]}")
            for i in range(0, len(yh), 64):
                lines.append(f"                    {yh[i:i+64]}")
        else:
            lines.append(f"            Public Key Algorithm: {self.key_algorithm_oid}")

        if self.extensions:
            lines.append("        X509v3 extensions:")
            for ext in self.extensions:
                name = EXT_NAMES.get(ext.oid, ext.oid)
                crit = " critical" if ext.critical else ""
                lines.append(f"            {name}:{crit}")
                v = ext.value
                if v:
                    hexed = v.hex()
                    if len(hexed) > 64:
                        lines.append(f"                {hexed[:64]}...")
                    else:
                        lines.append(f"                {hexed}")

        lines.append(f"    Signature Algorithm: {self.signature_algorithm_name}")
        sig_hex = self.signature.hex()
        for i in range(0, len(sig_hex), 64):
            lines.append(f"        {sig_hex[i:i+64]}")

        return "\n".join(lines)


def _sign_and_build_alg(key, data, hash_name="sha256", sig_scheme="pkcs1v15"):
    """Подписать `data` и вернуть (AlgorithmIdentifier DER, signature bytes)."""
    if not isinstance(key, (RSAKeys, Ed25519Keys, ECDSAKeys)):
        _fail(f"unsupported signing key: {type(key).__name__}",
              "используй RSAKeys / Ed25519Keys / ECDSAKeys")
    if not key.is_private:
        _fail("signing key must be private", "нужен приватный ключ")

    if isinstance(key, Ed25519Keys):
        sig_alg = der_seq(encode_oid(OID_ED25519))
    elif isinstance(key, ECDSAKeys):
        sig_oid = _ECDSA_HASH_TO_SIG_OID.get(hash_name)
        if sig_oid is None:
            _fail(f"ECDSA не поддерживает hash {hash_name!r}",
                  "используй sha256 / sha384 / sha512")
        sig_alg = der_seq(encode_oid(sig_oid))
    else:
        if sig_scheme == "pss":
            sig_alg = _build_pss_alg_id(hash_name)
        elif sig_scheme == "pkcs1v15":
            sig_alg = der_seq(encode_oid(_RSA_HASH_TO_SIG_OID[hash_name]),
                              der_null())
        else:
            _fail(f"unknown sig_scheme: {sig_scheme!r}",
                  "используй 'pkcs1v15' или 'pss'")

    if isinstance(key, Ed25519Keys):
        sig = key.sign(data)
    elif isinstance(key, ECDSAKeys):
        sig = key.sign(data, hash_name)
    else:
        if sig_scheme == "pss":
            sig = key.sign_pss(data, hash_name)
        else:
            sig = key.sign_pkcs1v15(data, hash_name)

    return sig_alg, sig


def _verify_signed_data(data, sig, sig_alg, key):
    """Единая проверка подписи по AlgorithmIdentifier + публичному ключу."""
    if sig_alg is None:
        return False
    oid = sig_alg.oid

    if oid == OID_ED25519:
        if not isinstance(key, Ed25519Keys): return False
        return key.verify(data, sig)

    if oid in ECDSA_SIG_OID_TO_HASH:
        if not isinstance(key, ECDSAKeys): return False
        return key.verify(data, sig, ECDSA_SIG_OID_TO_HASH[oid])

    if oid == OID_RSA_PSS:
        if not isinstance(key, RSAKeys): return False
        try:
            hash_name, salt_len = _parse_pss_params(sig_alg.params)
        except Exception:
            return False
        return key.verify_pss(data, sig, hash_name, salt_len)

    hash_name = SIG_ALG_RSA_HASH.get(oid)
    if hash_name is None or not isinstance(key, RSAKeys):
        return False
    return key.verify_pkcs1v15(data, sig, hash_name)


def _public_keys_equal(a, b):
    if isinstance(a, RSAKeys) and isinstance(b, RSAKeys):
        return a.n == b.n and a.e == b.e
    if isinstance(a, Ed25519Keys) and isinstance(b, Ed25519Keys):
        return a.pub == b.pub
    if isinstance(a, ECDSAKeys) and isinstance(b, ECDSAKeys):
        return a.curve_oid == b.curve_oid and a.point == b.point
    return False


def _build_cert_der(*, serial, hash_name, issuer_der, subject_der,
                    not_before, not_after, spki_der, extensions,
                    signing_key, sig_scheme="pkcs1v15"):
    if serial <= 0:
        raise ValueError("serial must be positive")

    # sig_alg не зависит от tbs — вычисляем заранее через диспетчер.
    # Передаём пустую data: диспетчер использует её только для подписи,
    # а нам здесь нужен только AlgorithmIdentifier. Подпишем tbs ниже.
    sig_alg, _ = _sign_and_build_alg(signing_key, b"", hash_name, sig_scheme)

    version  = _der_tlv(0xA0, der_int(2))
    validity = der_seq(_enc_time(not_before), _enc_time(not_after))
    parts = [version, der_int(serial), sig_alg, issuer_der,
             validity, subject_der, spki_der]
    if extensions:
        parts.append(_der_tlv(0xA3, der_seq(*extensions)))
    tbs = der_seq(*parts)

    _, sig = _sign_and_build_alg(signing_key, tbs, hash_name, sig_scheme)
    return der_seq(tbs, sig_alg, der_bitstring(sig))


# ======================================================================
#  CACert
# ======================================================================

class CACert(Cert):
    _signing_key = None

    @_safe_parse
    def __init__(self, data):
        super().__init__(data)
        bc_ext = self.ext_get(OID_BASIC_CONSTR)
        if bc_ext is None:
            raise X509ParseError("не CA: нет BasicConstraints")
        self.is_ca, self.path_len = _parse_basic_constraints(bc_ext.value)
        if not self.is_ca:
            raise X509ParseError("не CA: BasicConstraints CA=FALSE")
        ku_ext = self.ext_get(OID_KEY_USAGE)
        self.key_usage = _parse_key_usage(ku_ext.value) if ku_ext else set()
        if self.key_usage and "keyCertSign" not in self.key_usage:
            raise X509ParseError("CA без keyCertSign в KeyUsage")
        self._revoked = []   # список (serial, when, reason_code)

    @classmethod
    def create_self_signed(cls, subject, keys, *, days=3650, hash_name="sha256",
                           path_len=None, serial=None, extra_extensions=None):
        return (CertificateBuilder(is_ca=True)
                .add_subject(subject)
                .add_public_key(keys)
                .add_serial(serial) if serial else None or True and None or
                CertificateBuilder(is_ca=True))

    # ^ этот метод оставлен для совместимости, используйте Builder.

    @classmethod
    def from_cert(cls, cert, signing_key=None):
        ca = cls(cert.der)
        if signing_key is not None:
            if not signing_key.is_private:
                raise X509Error("нужен приватный ключ")
            if not ca._keys_match(signing_key):
                raise X509Error("приватный ключ не соответствует сертификату")
            ca._signing_key = signing_key
        return ca

    @classmethod
    def from_pem(cls, data, private_key_pem=None):
        certs = load_pem_certs(data)
        if not certs:
            raise X509ParseError("нет CERTIFICATE в PEM")
        key = None
        if private_key_pem is not None:
            for kcls in (Ed25519Keys, RSAKeys, ECDSAKeys):
                try:
                    key = kcls.from_pem(private_key_pem, private=True); break
                except Exception:
                    continue
            if key is None:
                raise X509Error("не удалось загрузить приватный ключ CA")
        return cls.from_cert(certs[0], signing_key=key)

    def _keys_match(self, signing_key):
        return _public_keys_equal(signing_key, self.public_key)

    def issue_csr(self, csr, **kwargs):
        if self._signing_key is None:
            raise X509Error("CACert без приватного ключа")
        return self.issue_with_key(csr, self._signing_key, **kwargs)

    def issue_with_key(self, csr, signing_key, *, days=365, hash_name="sha256",
                       serial=None, is_ca=False, path_len=None,
                       copy_csr_extensions=True, extra_extensions=None):
        if not signing_key.is_private:
            raise X509Error("нужен приватный ключ")
        if not self._keys_match(signing_key):
            raise X509Error("приватный ключ не соответствует CA")
        if is_ca and path_len is not None and path_len < 0:
            raise ValueError("path_len must be >= 0")

        b = CertificateBuilder(is_ca=is_ca)
        b.add_subject(csr.subject)
        b.add_issuer(self)    # передаём Cert, а не Name — нужно для AKI и NC
        b.add_public_key(csr.spki_der)
        b.add_serial(serial) if serial else b.add_serial_random()
        b.add_validity(days=days)
        if copy_csr_extensions:
            for ext in csr.extensions:
                if ext.oid in (OID_BASIC_CONSTR, OID_KEY_USAGE):
                    continue
                b.add_extension(ext.oid, ext.critical, ext.value)
        if extra_extensions:
            for e in extra_extensions:
                b._extensions.append(e)
        return b.sign(signing_key, hash_name=hash_name)

    def revoke(self, cert_or_serial, *, reason=None, when=None):
        """Добавить серийный номер в список отзыва этого CA.
        reason — имя из CRL_REASONS или int (0..10, кроме 7)."""
        if isinstance(cert_or_serial, Cert):
            serial = cert_or_serial.serial
        else:
            serial = int(cert_or_serial)
        when = when or datetime.datetime.now(datetime.timezone.utc)
        code = None
        if reason is not None:
            if isinstance(reason, int):
                code = reason
            elif reason in CRL_REASONS:
                code = CRL_REASONS[reason]
            else:
                _fail(f"CACert.revoke: неизвестная причина {reason!r}.",
                      "используй: " + ", ".join(CRL_REASONS))
        self._revoked.append((serial, when, code))
        return self

    def to_crl(self, days=7, hash_name=None):
        """Выпустить CRL с текущим списком отзыва. Нужен приватный ключ."""
        if self._signing_key is None:
            _fail("CACert.to_crl: нет приватного ключа.",
                  "используй CACert.from_pem(..., private_key_pem=...) "
                  "или CACert.from_cert(cert, signing_key)")
        b = CRLBuilder()
        b.set_issuer(self)
        b.set_validity(days=days)
        if hash_name:
            b.set_hash(hash_name)
        for serial, when, code in self._revoked:
            b.add_revoked(serial, when=when, reason=code)
        return b.sign(self._signing_key)

    def respond_ocsp(self, cert_or_serial_or_request, *,
                     status="good", reason=None, days=7,
                     nonce=None, hash_name=None):
        """Выпустить подписанный OCSPResponse для сертификата/серийника/запроса.

        Если первый аргумент — OCSPRequest, nonce из него автоматически
        переносится в ответ.
        """
        if self._signing_key is None:
            _fail("CACert.respond_ocsp: нет приватного ключа",
                  "CACert.from_pem(..., private_key_pem=...) или from_cert(..., signing_key=...)")

        # Извлекаем цель и nonce
        target = cert_or_serial_or_request
        if isinstance(target, OCSPRequest):
            if nonce is None:
                nonce = target.nonce
            cid = target.cert_id
            target = cid[3] if cid else None
            if target is None:
                _fail("OCSPRequest пустой")

        b = OCSPResponseBuilder()
        b.set_responder(self)
        b.set_validity(days=days)
        if nonce is not None:
            b.set_nonce(nonce)
        if hash_name:
            b.set_hash(hash_name)
        # дефолтный хэш подписанта — свой
        if isinstance(self._signing_key, RSAKeys):
            b.set_sig_scheme("pkcs1v15")
        b.add_status(target, status=status, reason=reason)
        return b.sign(self._signing_key)

    def verify_ocsp_response(self, response, request=None):
        """Проверить подпись и свежесть ответа. Если дан request — сверить nonce."""
        if not isinstance(response, OCSPResponse):
            _fail("verify_ocsp_response: нужен OCSPResponse")
        if not response.is_successful:
            return False
        if not response.verify_signature(self):
            return False
        if not response.is_fresh():
            return False
        if request is not None:
            rn = request.nonce
            if rn is not None and response.nonce != rn:
                return False
        return True

    def verify_cert(self, cert, when=None, allow_weak_hash=False, allow_weak_key=False,
                    crl=None, ocsp_response=None):
        when = when or datetime.datetime.now(datetime.timezone.utc)
        if not self.is_valid_at(when) or not cert.is_valid_at(when):
            return False
        if not allow_weak_hash and (self.weak_hash or cert.weak_hash):
            return False
        if not allow_weak_key:
            if isinstance(cert.public_key, RSAKeys) and cert.public_key.weak:
                return False
            if isinstance(self.public_key, RSAKeys) and self.public_key.weak:
                return False
        if self.has_unknown_critical or cert.has_unknown_critical:
            return False
        if crl is not None:
            if not crl.verify_signature(self):
                return False
            if not crl.is_valid_at(when):
                return False
            if crl.is_revoked(cert):
                return False
        if ocsp_response is not None:
            if not self.verify_ocsp_response(ocsp_response):
                return False
            if ocsp_response.get_status(cert) != "good":
                return False
        if not _aki_ski_match(cert, self):
            return False
        nc = self.name_constraints
        if nc is not None:
            names = _collect_names_from_san(cert.san, cert.subject)
            ok, _ = _check_name_constraints(names, nc)
            if not ok:
                return False
        if not cert.verify_signature(self):
            return False
        bc = cert.ext_get(OID_BASIC_CONSTR)
        is_sub_ca = bool(bc and _parse_basic_constraints(bc.value)[0])
        if is_sub_ca and self.path_len == 0:
            return False
        return True

    def verify_chain(self, chain, when=None, allow_weak_hash=False, allow_weak_key=False,
                     crl=None):
        when = when or datetime.datetime.now(datetime.timezone.utc)
        if not chain:
            return False
        if not self.is_valid_at(when) or self.has_unknown_critical:
            return False
        if crl is not None:
            if not crl.verify_signature(self):
                return False
            if not crl.is_valid_at(when):
                return False
        for c in chain:
            if not c.is_valid_at(when): return False
            if c.has_unknown_critical:  return False
            if not allow_weak_hash and c.weak_hash: return False
            if (not allow_weak_key and isinstance(c.public_key, RSAKeys)
                    and c.public_key.weak):
                return False
            if crl is not None and crl.is_revoked(c):
                return False
        for c in chain[1:]:
            bc = c.ext_get(OID_BASIC_CONSTR)
            if not (bc and _parse_basic_constraints(bc.value)[0]):
                return False

        # Name Constraints: root сверху вниз, каждый CA проверяет всё, что ниже
        all_certs = [self] + list(reversed(chain))
        for i, ca in enumerate(all_certs):
            nc = ca.name_constraints
            if nc is None:
                continue
            for below in all_certs[i + 1:]:
                names = _collect_names_from_san(below.san, below.subject)
                ok, _ = _check_name_constraints(names, nc)
                if not ok:
                    return False

        # NC intersection: sub-CA не может разрешить больше, чем родитель
        for i in range(len(all_certs)):
            child_nc = all_certs[i].name_constraints
            if child_nc is None:
                continue
            for j in range(i):
                parent_nc = all_certs[j].name_constraints
                if parent_nc is None:
                    continue
                ok, _reason = _nc_sub_constraint_of(child_nc, parent_nc)
                if not ok:
                    return False
        for i in range(len(chain) - 1):
            if not _aki_ski_match(chain[i], chain[i + 1]):
                return False
            if not chain[i].verify_signature(chain[i + 1]):
                return False
        if not _aki_ski_match(chain[-1], self):
            return False
        if not chain[-1].verify_signature(self):
            return False
        if self.path_len is not None and (len(chain) - 1) > self.path_len:
            return False
        return True

    def __str__(self):
        extra = f"\n  CA:       path_len={self.path_len}\n  KeyUsage: {sorted(self.key_usage)}"
        if self.ski is not None:
            extra += f"\n  SKI:      {self.ski.hex()}"
        if self.aki is not None:
            extra += f"\n  AKI:      {self.aki.hex()}"
        nc = self.name_constraints
        if nc is not None:
            if nc.get("permitted"):
                extra += f"\n  NC permit:{nc['permitted']}"
            if nc.get("excluded"):
                extra += f"\n  NC excl:  {nc['excluded']}"
        return super().__str__() + extra

    def __repr__(self):
        return f"<CACert subject={self.subject!r} path_len={self.path_len}>"


# ======================================================================
#  CSR
# ======================================================================

class CSR:
    @_safe_parse
    def __init__(self, data):
        if isinstance(data, str): data = data.encode("ascii")
        if b"-----BEGIN" in data:
            for label, der in pem_decode(data):
                if "CERTIFICATE REQUEST" in label:
                    data = der; break
            else:
                raise X509ParseError("no CERTIFICATE REQUEST block in PEM")

        self.der = bytes(data)
        root, _ = ASN1.parse(self.der)
        if root.tag != TAG_SEQUENCE or len(root.children) != 3:
            raise X509ParseError("not a CertificationRequest")
        cri, sig_alg, sig_val = root.children
        if sig_val.tag != TAG_BIT_STRING or not sig_val.value:
            raise X509ParseError("signature must be non-empty BIT STRING")
        if sig_val.value[0] != 0:
            raise X509ParseError("signature BIT STRING unused bits must be 0")

        self.cri_der = cri.raw
        self.signature = sig_val.value[1:]
        self.signature_algorithm = AlgorithmIdentifier(sig_alg)

        ch = cri.children
        self.version = ch[0].as_int()
        if self.version != 0:
            raise X509ParseError("unsupported CSR version")
        self.subject = Name(ch[1])
        self.public_key, self.key_algorithm_oid, self.spki_der = _parse_spki(ch[2])

        self.extensions = []
        if len(ch) > 3 and ch[3].tag == 0xA0:
            for attr in ch[3].children:
                if attr.children[0].as_oid() == OID_EXT_REQUEST:
                    values = attr.children[1]
                    ext_seq = values.children[0]
                    for ext in ext_seq.children:
                        self.extensions.append(Extension(ext))

    @classmethod
    def create(cls, subject, keys, *, hash_name="sha256", extensions=None):
        b = CSRBuilder()
        b.add_subject(subject)
        b.add_public_key(keys)
        if extensions:
            b._extensions.extend(extensions)
        return b.sign(keys, hash_name=hash_name)

    @property
    def signature_algorithm_name(self): return self.signature_algorithm.name

    @property
    def san(self):
        for e in self.extensions:
            if e.oid == OID_SAN:
                return _parse_san(e.value)
        return []








    @property
    def dns_names(self):
        """Список dNSName из SAN в CSR."""
        return [v for kind, v in self.san if kind == "dNSName"]

    @property
    def ip_addresses(self):
        """Список iPAddress из SAN в CSR."""
        return [v for kind, v in self.san if kind == "iPAddress"]

    @property
    def emails(self):
        """Список rfc822Name из SAN в CSR."""
        return [v for kind, v in self.san if kind == "rfc822Name"]

    @property
    def uris(self):
        """Список URI из SAN в CSR."""
        return [v for kind, v in self.san if kind == "URI"]
    @property
    def eku(self):
        """Extended Key Usage из CSR (set имён или OID). Пусто, если нет."""
        for e in self.extensions:
            if e.oid == OID_EXT_KEY_USAGE:
                try:
                    return _parse_eku(e.value)
                except Exception:
                    return set()
        return set()

    def has_eku(self, purpose):
        """Есть ли назначение. Пустой EKU = любое (RFC 5280)."""
        e = self.eku
        if not e:
            return True
        return purpose in e or "anyExtendedKeyUsage" in e

    def ext_get(self, oid):
        for e in self.extensions:
            if e.oid == oid:
                return e
        return None

    def verify_signature(self):
        return _verify_signed_data(
            self.cri_der, self.signature, self.signature_algorithm,
            self.public_key)

    def to_pem(self): return pem_encode("CERTIFICATE REQUEST", self.der)

    def __repr__(self):
        return f"<CSR subject={self.subject!r}>"

    def __str__(self):
        lines = [
            "CertificationRequest",
            f"  Version: {self.version}",
            f"  Subject: {self.subject}",
            f"  Sig alg: {self.signature_algorithm_name}",
        ]
        key = self.public_key
        if isinstance(key, RSAKeys):
            lines.append(f"  Pubkey:  RSA {key.size_bits} bit (e={key.e})")
        elif isinstance(key, Ed25519Keys):
            lines.append(f"  Pubkey:  Ed25519")
        else:
            lines.append(f"  Pubkey:  {self.key_algorithm_oid}")
        san = self.san
        if san:
            lines.append("  SAN:")
            for kind, val in san:
                lines.append(f"    - {kind}: {val}")
        return "\n".join(lines)


# ======================================================================
#  PEM
# ======================================================================


    def __eq__(self, other):
        return isinstance(other, CSR) and self.der == other.der

    def __hash__(self):
        return hash(self.der)
_PEM_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+?)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----",
    re.DOTALL,
)


def pem_decode(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    if len(data) > _MAX_PEM_SIZE:
        raise X509ParseError(
            f"PEM input too large: {len(data)} bytes "
            f"(limit {_MAX_PEM_SIZE})"
        )
    if isinstance(data, str): data = data.encode("ascii")
    out = []
    for m in _PEM_RE.finditer(data):
        label = m.group(1).decode("ascii")
        body = re.sub(rb"\s+", b"", m.group(2))
        try:
            out.append((label, base64.b64decode(body, validate=True)))
        except Exception as e:
            raise X509ParseError(f"bad base64 in PEM block {label}: {e}")
    return out


def pem_encode(label, der, width=64):
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i+width] for i in range(0, len(b64), width)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def load_pem_certs(data):
    return [Cert(der) for label, der in pem_decode(data)
            if "CERTIFICATE" in label and "REQUEST" not in label]


def load_pem_csrs(data):
    return [CSR(der) for label, der in pem_decode(data)
            if "CERTIFICATE REQUEST" in label]


# ======================================================================
#  CertBundle
# ======================================================================

class CertBundle:
    def __init__(self, certs):
        self.certs = list(certs)

    @classmethod
    def from_pem(cls, data):  return cls(load_pem_certs(data))
    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            return cls.from_pem(f.read())

    def to_pem(self): return "".join(c.to_pem() for c in self.certs)
    def save(self, path):
        path = os.path.expanduser(path)
        with open(path, "w") as f: f.write(self.to_pem())
        return os.path.abspath(path)

    def __len__(self):        return len(self.certs)
    def __iter__(self):       return iter(self.certs)
    def __getitem__(self, i): return self.certs[i]
    def __repr__(self):       return f"<CertBundle {len(self.certs)} certs>"


    def to_pkcs12(self, key, password="", name=None, iterations=2048,
                  cipher="aes-256-cbc"):
        """Собрать PKCS#12 из цепочки: certs[0] — leaf, остальные — chain.

        key — приватный ключ leaf'а.
        """
        if not self.certs:
            raise X509Error("CertBundle.to_pkcs12: empty bundle")
        leaf = self.certs[0]
        chain = self.certs[1:]
        b = PKCS12Builder()
        b.set_key(key)
        b.set_cert(leaf)
        if chain:
            b.add_chain(*chain)
        b.set_password(password)
        if name:
            b.set_name(name)
        b.set_iterations(iterations)
        if cipher != "aes-256-cbc":
            b.set_cipher(cipher)
        return b.build()


# ======================================================================
#  CRLBuilder — выпуск CRL
# ======================================================================


    def __eq__(self, other):
        return (isinstance(other, CertBundle)
                and [c.der for c in self.certs] == [c.der for c in other.certs])

    def __hash__(self):
        return hash(tuple(c.der for c in self.certs))
class CRLBuilder:
    """
    Сборка X.509 CRL (v2) цепочкой вызовов.

    Пример:
        crl = (CRLBuilder()
            .set_issuer(ca)
            .set_validity(days=7)
            .add_revoked(cert_serial, reason="keyCompromise")
            .sign(ca_key))

        crl.to_pem()
        crl.is_revoked(12345)   # True
    """

    def __init__(self):
        self._issuer = None          # Name
        self._issuer_cert = None     # Cert (для предупреждений/проверок)
        self._this_update = None
        self._next_update = None
        self._days = 7
        self._entries = []           # (serial, when, reason_code|None)
        self._crl_number = None
        self._hash_name = "sha256"
        self._sig_scheme = "pkcs1v15"

    def set_issuer(self, ca_or_name):
        """Cert/CA или Name/dict."""
        if isinstance(ca_or_name, Cert):
            self._issuer = ca_or_name.subject
            self._issuer_cert = ca_or_name
        elif isinstance(ca_or_name, Name):
            self._issuer = ca_or_name
        elif isinstance(ca_or_name, dict):
            self._issuer = Name.from_dict(ca_or_name)
        else:
            _fail(f"CRLBuilder.set_issuer: тип {type(ca_or_name).__name__}.",
                  "передай Cert, Name или dict")
        return self

    def set_validity(self, days=7):
        if days <= 0:
            raise ValueError("days must be positive")
        self._days = days
        return self

    def set_this_update(self, dt):
        self._this_update = dt
        return self

    def set_next_update(self, dt):
        self._next_update = dt
        return self

    def set_crl_number(self, n):
        self._crl_number = int(n)
        return self

    def set_sig_scheme(self, scheme):
        """'pkcs1v15' (default) или 'pss' (RSASSA-PSS)."""
        if scheme not in ("pkcs1v15", "pss"):
            _fail(f"CRLBuilder.set_sig_scheme: неизвестная схема {scheme!r}",
                  "используй 'pkcs1v15' или 'pss'")
        self._sig_scheme = scheme
        return self

    def use_pss(self):
        """Алиас для .set_sig_scheme('pss')."""
        return self.set_sig_scheme("pss")

    def set_hash(self, hash_name):
        if hash_name not in _RSA_HASH_TO_SIG_OID:
            raise ValueError(f"unsupported hash: {hash_name}")
        self._hash_name = hash_name
        return self

    def add_revoked(self, serial_or_cert, *, when=None, reason=None):
        """serial — int или Cert. reason — имя из CRL_REASONS или int."""
        if isinstance(serial_or_cert, Cert):
            serial = serial_or_cert.serial
        else:
            serial = int(serial_or_cert)
        if serial <= 0:
            raise ValueError("serial must be positive")
        when = when or datetime.datetime.now(datetime.timezone.utc)
        code = None
        if reason is not None:
            if isinstance(reason, int):
                code = reason
            elif reason in CRL_REASONS:
                code = CRL_REASONS[reason]
            else:
                _fail(f"CRLBuilder.add_revoked: неизвестная причина {reason!r}.",
                      "используй одну из: " + ", ".join(CRL_REASONS))
        self._entries.append((serial, when, code))
        return self

    def sign(self, signing_key):
        if self._issuer is None:
            _fail("CRLBuilder.sign: issuer не задан.", ".set_issuer(ca)")
        if not signing_key.is_private:
            _fail("CRLBuilder.sign: нужен приватный ключ.",
                  "используй приватный ключ CA")

        now = datetime.datetime.now(datetime.timezone.utc)
        this_update = self._this_update or now
        next_update = self._next_update or (this_update + datetime.timedelta(days=self._days))

        sig_alg, _ = _sign_and_build_alg(
            signing_key, b"", self._hash_name, self._sig_scheme)

        parts = [
            der_int(1),                    # version v2 (INTEGER 1)
            sig_alg,
            self._issuer.raw,
            _enc_time(this_update),
            _enc_time(next_update),
        ]

        if self._entries:
            entry_parts = []
            for serial, when, code in self._entries:
                e = [der_int(serial), _enc_time(when)]
                if code is not None:
                    reason_ext = _enc_crl_reason(code)
                    e.append(der_seq(reason_ext))   # crlEntryExtensions
                entry_parts.append(der_seq(*e))
            parts.append(der_seq(*entry_parts))

        # crlExtensions [0] EXPLICIT
        exts = []
        if self._crl_number is not None:
            exts.append(_enc_extension(OID_CRL_NUMBER, False,
                                       der_int(self._crl_number)))
        if exts:
            parts.append(_der_tlv(0xA0, der_seq(*exts)))

        tbs = der_seq(*parts)

        _, sig = _sign_and_build_alg(
            signing_key, tbs, self._hash_name, self._sig_scheme)

        return CRL(der_seq(tbs, sig_alg, der_bitstring(sig)))


# ======================================================================
#  CRL — парсинг и проверка
# ======================================================================

class CRL:
    """X.509 Certificate Revocation List (v1/v2)."""

    @_safe_parse
    def __init__(self, data):
        if isinstance(data, str):
            data = data.encode("ascii")
        if b"-----BEGIN" in data:
            for label, der in pem_decode(data):
                if "CRL" in label.upper():
                    data = der
                    break
            else:
                raise X509ParseError("no X509 CRL block in PEM")

        self.der = bytes(data)
        root, _ = ASN1.parse(self.der)
        if root.tag != TAG_SEQUENCE or len(root.children) != 3:
            raise X509ParseError("not a CertificateList")
        tbs, sig_alg, sig_val = root.children
        if sig_val.tag != TAG_BIT_STRING or not sig_val.value:
            raise X509ParseError("signatureValue must be non-empty BIT STRING")
        if sig_val.value[0] != 0:
            raise X509ParseError("signature BIT STRING unused bits must be 0")

        self.tbs_der = tbs.raw
        self.signature = sig_val.value[1:]
        self.signature_algorithm = AlgorithmIdentifier(sig_alg)
        self._parse_tbs(tbs)

    def _parse_tbs(self, tbs):
        ch = list(tbs.children)
        i = 0
        version = 1
        if ch[0].tag == TAG_INTEGER:
            v = ch[0].as_int()
            if v != 1:
                raise X509ParseError(f"unsupported CRL version {v}")
            version = 2
            i = 1
        self.version = version
        self.tbs_signature_algorithm = AlgorithmIdentifier(ch[i]); i += 1
        self.issuer = Name(ch[i]); i += 1
        self.this_update = _parse_time(ch[i]); i += 1
        self.next_update = None
        if i < len(ch) and ch[i].tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
            self.next_update = _parse_time(ch[i]); i += 1

        self.revoked = []       # list of (serial, when, reason_code|None)
        if i < len(ch) and ch[i].tag == TAG_SEQUENCE:
            for entry in ch[i].children:
                serial = entry.children[0].as_uint()
                date = _parse_time(entry.children[1])
                reason = None
                if len(entry.children) > 2:
                    for ext in entry.children[2].children:
                        if ext.children[0].as_oid() == OID_CRL_REASON:
                            try:
                                reason = _parse_crl_reason(ext)
                            except Exception:
                                reason = None
                self.revoked.append((serial, date, reason))
            i += 1

        self.extensions = []
        if i < len(ch) and ch[i].tag == 0xA0:
            for ext in ch[i].children[0].children:
                self.extensions.append(Extension(ext))
            i += 1

        self._by_serial = {r[0]: (r[1], r[2]) for r in self.revoked}

    # ---- API ----
    def is_revoked(self, cert_or_serial):
        if isinstance(cert_or_serial, Cert):
            serial = cert_or_serial.serial
        else:
            serial = int(cert_or_serial)
        return serial in self._by_serial

    def revoke_reason(self, cert_or_serial):
        if isinstance(cert_or_serial, Cert):
            serial = cert_or_serial.serial
        else:
            serial = int(cert_or_serial)
        info = self._by_serial.get(serial)
        if info is None:
            return None
        code = info[1]
        if code is None:
            return None
        return CRL_REASONS_REV.get(code, f"unknown({code})")

    def is_valid_at(self, when=None):
        when = when or datetime.datetime.now(datetime.timezone.utc)
        if self.next_update is not None and when > self.next_update:
            return False
        return when >= self.this_update

    def verify_signature(self, issuer):
        key = issuer.public_key if isinstance(issuer, Cert) else issuer
        return _verify_signed_data(
            self.tbs_der, self.signature, self.signature_algorithm, key)

    def to_pem(self):
        return pem_encode("X509 CRL", self.der)

    def __repr__(self):
        return f"<CRL issuer={self.issuer!r} revoked={len(self.revoked)}>"

    def __str__(self):
        lines = [
            f"X.509 CRL v{self.version}",
            f"  Issuer:      {self.issuer}",
            f"  This update: {self.this_update.isoformat()}",
            f"  Next update: {self.next_update.isoformat() if self.next_update else '—'}",
            f"  Sig alg:     {self.signature_algorithm.name}",
            f"  Revoked:     {len(self.revoked)}",
        ]
        for serial, when, code in self.revoked[:20]:
            reason = CRL_REASONS_REV.get(code, "—") if code is not None else "—"
            lines.append(f"    - 0x{serial:x}  {when.date()}  {reason}")
        if len(self.revoked) > 20:
            lines.append(f"    ... ещё {len(self.revoked)-20}")
        return "\n".join(lines)



    def __eq__(self, other):
        return isinstance(other, CRL) and self.der == other.der

    def __hash__(self):
        return hash(self.der)
def load_pem_crls(data):
    out = []
    for label, der in pem_decode(data):
        if "CRL" in label.upper():
            out.append(CRL(der))
    return out


# ======================================================================
#  OCSP (RFC 6960)
# ======================================================================

OCSP_STATUS_NAMES = {
    0: "successful",
    1: "malformedRequest",
    2: "internalError",
    3: "tryLater",
    5: "sigRequired",
    6: "unauthorized",
}
OCSP_STATUS_CODES = {v: k for k, v in OCSP_STATUS_NAMES.items()}


def _enc_gentime(dt):
    """Всегда GeneralizedTime (для OCSP)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt = dt.astimezone(datetime.timezone.utc)
    return _der_tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _compute_key_hash(spki_der, hash_name="sha1"):
    """Хэш от BIT STRING subjectPublicKey (без тега, длины, unused-bits)."""
    node, _ = ASN1.parse(spki_der)
    bits = node.children[1]
    return hashlib.new(hash_name, bits.value[1:]).digest()


def _enc_cert_id(issuer, serial, hash_name="sha256"):
    """CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serial }"""
    hash_oid = _HASH_OIDS.get(hash_name)
    if hash_oid is None:
        _fail(f"OCSP: неподдерживаемый хэш {hash_name!r}",
              "используй " + ", ".join(_HASH_OIDS))
    hash_alg = der_seq(encode_oid(hash_oid), der_null())
    name_hash = hashlib.new(hash_name, issuer.subject.raw).digest()
    key_hash = _compute_key_hash(issuer.spki_der, hash_name)
    return der_seq(
        hash_alg,
        der_octet(name_hash),
        der_octet(key_hash),
        der_int(serial),
    )


def _parse_cert_id(node):
    """CertID node → (hash_name, name_hash, key_hash, serial)."""
    if len(node.children) != 4:
        raise X509ParseError("CertID: ожидалось 4 поля")
    h_oid = node.children[0].children[0].as_oid()
    hash_name = _HASH_OIDS_REV.get(h_oid, h_oid)
    name_hash = node.children[1].value
    key_hash = node.children[2].value
    serial = node.children[3].as_uint()
    return hash_name, name_hash, key_hash, serial


def _parse_extensions_sequence(node):
    """node = SEQUENCE OF Extension. → dict {oid: (critical, value_bytes)}"""
    out = {}
    if node.tag != TAG_SEQUENCE:
        return out
    for ext in node.children:
        if len(ext.children) == 3:
            oid = ext.children[0].as_oid()
            crit = ext.children[1].as_bool()
            val = ext.children[2].value
            out[oid] = (crit, val)
        elif len(ext.children) == 2:
            oid = ext.children[0].as_oid()
            val = ext.children[1].value
            out[oid] = (False, val)
    return out


class OCSPRequest:
    """OCSPRequest (RFC 6960 §4.1)."""

    @_safe_parse
    def __init__(self, data):
        if isinstance(data, str):
            data = data.encode("ascii")
        if b"-----BEGIN" in data:
            for label, der in pem_decode(data):
                if "OCSP REQUEST" in label.upper():
                    data = der; break
            else:
                raise X509ParseError("no OCSP REQUEST in PEM")

        self.der = bytes(data)
        root, _ = ASN1.parse(self.der)
        if root.tag != TAG_SEQUENCE or len(root.children) < 1:
            raise X509ParseError("not an OCSPRequest")
        tbs = root.children[0]
        # tbs.version [0] OPTIONAL, tbs.requestorName [1] OPTIONAL
        i = 0
        if i < len(tbs.children) and tbs.children[i].tag == 0xA0:
            i += 1
        if i < len(tbs.children) and tbs.children[i].tag == 0xA1:
            i += 1
        if i >= len(tbs.children) or tbs.children[i].tag != TAG_SEQUENCE:
            raise X509ParseError("OCSPRequest: нет requestList")
        req_list = tbs.children[i]; i += 1

        self.requests = []
        for req in req_list.children:
            cert_id = req.children[0]
            self.requests.append(_parse_cert_id(cert_id))

        self.extensions = {}
        if i < len(tbs.children) and tbs.children[i].tag == 0xA2:
            inner = tbs.children[i].children[0]
            self.extensions = _parse_extensions_sequence(inner)

    @property
    def cert_id(self):
        return self.requests[0] if self.requests else None

    @property
    def serial(self):
        cid = self.cert_id
        return cid[3] if cid else None

    @property
    def nonce(self):
        info = self.extensions.get(OID_OCSP_NONCE)
        if info is None:
            return None
        try:
            node, _ = ASN1.parse(info[1])
            if node.tag == TAG_OCTET_STRING:
                return node.value
        except Exception:
            pass
        return None

    @classmethod
    def create(cls, issuer, cert_or_serial=None, *,
               cert=None, serial=None,
               hash_name="sha256", nonce=None, add_nonce=True):
        """Собрать OCSPRequest.

        issuer        — CA-сертификат (Cert/CACert)
        cert_or_serial — Cert или int serial (позиционно)
        cert          — Cert (именованный, альтернатива)
        serial        — int serial (именованный, альтернатива)
        nonce         — bytes (None → случайные 16; b'' → без nonce)
        """
        target = cert_or_serial
        if target is None:
            target = cert if cert is not None else serial
        if target is None:
            _fail(
                "OCSPRequest.create: не указан сертификат или серийник",
                "OCSPRequest.create(issuer=ca, cert=leaf) "
                "или OCSPRequest.create(ca, leaf) "
                "или OCSPRequest.create(ca, serial=12345)",
            )
        if isinstance(target, Cert):
            serial = target.serial
        else:
            serial = int(target)

        cert_id = _enc_cert_id(issuer, serial, hash_name)
        request = der_seq(cert_id)
        req_list = der_seq(request)
        parts = [req_list]

        if add_nonce and nonce != b"":
            if nonce is None:
                nonce = secrets.token_bytes(16)
            ext = _enc_extension(OID_OCSP_NONCE, False, der_octet(nonce))
            parts.append(_der_tlv(0xA2, der_seq(ext)))

        tbs = der_seq(*parts)
        return cls(der_seq(tbs))

    def to_der(self): return self.der
    def to_pem(self): return pem_encode("OCSP REQUEST", self.der)

    def __repr__(self):
        cid = self.cert_id
        return f"<OCSPRequest serial=0x{cid[3]:x}>" if cid else "<OCSPRequest>"


class OCSPResponse:
    """OCSPResponse (RFC 6960 §4.2)."""

    @_safe_parse
    def __init__(self, data):
        if isinstance(data, str):
            data = data.encode("ascii")
        if b"-----BEGIN" in data:
            for label, der in pem_decode(data):
                if "OCSP RESPONSE" in label.upper():
                    data = der; break
            else:
                raise X509ParseError("no OCSP RESPONSE in PEM")

        self.der = bytes(data)
        root, _ = ASN1.parse(self.der)
        if root.tag != TAG_SEQUENCE or len(root.children) < 1:
            raise X509ParseError("not an OCSPResponse")

        status_node = root.children[0]
        if status_node.tag != 0x0A:
            raise X509ParseError("OCSPResponse: responseStatus must be ENUMERATED")
        self.status_code = status_node.as_int()
        self.status = OCSP_STATUS_NAMES.get(self.status_code, f"unknown({self.status_code})")

        self.response_type = None
        self.response_der = None
        self.tbs_der = None
        self.signature = None
        self.signature_algorithm = None
        self.certs = []
        self.responder_id = None
        self.produced_at = None
        self.responses = []          # list of dict
        self.response_extensions = {}

        if len(root.children) >= 2 and root.children[1].tag == 0xA0:
            inner = root.children[1].children[0]   # ResponseBytes SEQUENCE
            if inner.tag == TAG_SEQUENCE and len(inner.children) >= 2:
                self.response_type = inner.children[0].as_oid()
                response_octet = inner.children[1].value
                self.response_der = response_octet
                if self.response_type == OID_OCSP_BASIC:
                    self._parse_basic(response_octet)

    def _parse_basic(self, data):
        root, _ = ASN1.parse(data)
        if root.tag != TAG_SEQUENCE or len(root.children) < 3:
            raise X509ParseError("not a BasicOCSPResponse")
        tbs, sig_alg, sig_val = root.children[0], root.children[1], root.children[2]
        self.tbs_der = tbs.raw
        self.signature_algorithm = AlgorithmIdentifier(sig_alg)
        if sig_val.tag != TAG_BIT_STRING or not sig_val.value:
            raise X509ParseError("BasicOCSPResponse: signature must be BIT STRING")
        self.signature = sig_val.value[1:]

        # certs [0] EXPLICIT OPTIONAL
        if len(root.children) > 3 and root.children[3].tag == 0xA0:
            for cert_node in root.children[3].children[0].children:
                try:
                    self.certs.append(Cert(cert_node.raw))
                except Exception:
                    pass

        # tbs: version [0] OPTIONAL, responderID, producedAt, responses, exts [1] OPTIONAL
        ch = list(tbs.children)
        i = 0
        if ch[i].tag == 0xA0:      # version
            i += 1
        self.responder_id = self._parse_responder_id(ch[i]); i += 1
        self.produced_at = _parse_time(ch[i]); i += 1
        responses_seq = ch[i]; i += 1
        for sr in responses_seq.children:
            self.responses.append(self._parse_single_response(sr))
        if i < len(ch) and ch[i].tag == 0xA1:
            inner = ch[i].children[0]
            self.response_extensions = _parse_extensions_sequence(inner)

    @staticmethod
    def _parse_responder_id(node):
        if node.tag == 0xA1:      # byName [1] EXPLICIT Name
            name_node = node.children[0]
            return ("byName", str(Name(name_node)))
        if node.tag == 0xA2:      # byKey [2] EXPLICIT KeyHash
            key_node = node.children[0]
            return ("byKey", key_node.value.hex())
        return (None, None)

    @staticmethod
    def _parse_cert_status(node):
        if node.tag == 0x80:      # good [0] IMPLICIT NULL
            return ("good", None)
        if node.tag == 0xA1:      # revoked [1] IMPLICIT RevokedInfo
            children = node.children
            when = _parse_time(children[0])
            reason_code = None
            if len(children) > 1 and children[1].tag == 0xA0:
                reason_code = children[1].children[0].as_int()
            return ("revoked", (when, reason_code))
        if node.tag == 0x82:      # unknown [2] IMPLICIT NULL
            return ("unknown", None)
        return (None, None)

    @classmethod
    def _parse_single_response(cls, node):
        cert_id_node = node.children[0]
        hash_name, name_hash, key_hash, serial = _parse_cert_id(cert_id_node)
        status_node = node.children[1]
        status, extra = cls._parse_cert_status(status_node)
        this_update = _parse_time(node.children[2])
        next_update = None
        exts = {}
        i = 3
        if i < len(node.children) and node.children[i].tag == 0xA0:
            next_update = _parse_time(node.children[i].children[0]); i += 1
        if i < len(node.children) and node.children[i].tag == 0xA1:
            exts = _parse_extensions_sequence(node.children[i].children[0])
        return {
            "hash_name": hash_name,
            "serial": serial,
            "status": status,
            "revoked_at": extra[0] if status == "revoked" else None,
            "reason_code": extra[1] if status == "revoked" else None,
            "this_update": this_update,
            "next_update": next_update,
            "extensions": exts,
        }

    # ---- свойства ----
    @property
    def is_successful(self):
        return self.status_code == 0

    @property
    def nonce(self):
        info = self.response_extensions.get(OID_OCSP_NONCE)
        if info is None:
            return None
        try:
            node, _ = ASN1.parse(info[1])
            if node.tag == TAG_OCTET_STRING:
                return node.value
        except Exception:
            pass
        return None

    def get_status(self, cert_or_serial):
        """'good' | 'revoked' | 'unknown' | None."""
        serial = cert_or_serial.serial if isinstance(cert_or_serial, Cert) else int(cert_or_serial)
        for r in self.responses:
            if r["serial"] == serial:
                return r["status"]
        return None

    def get_revoke_info(self, cert_or_serial):
        """(revoked_at, reason_name|None) или None."""
        serial = cert_or_serial.serial if isinstance(cert_or_serial, Cert) else int(cert_or_serial)
        for r in self.responses:
            if r["serial"] == serial and r["status"] == "revoked":
                code = r["reason_code"]
                reason = CRL_REASONS_REV.get(code) if code is not None else None
                return (r["revoked_at"], reason)
        return None

    def verify_signature(self, issuer):
        """issuer — Cert/CACert/ключ. Для signed responses."""
        if self.response_type != OID_OCSP_BASIC:
            return False
        if self.tbs_der is None or self.signature is None:
            return False
        key = issuer.public_key if isinstance(issuer, Cert) else issuer
        oid = self.signature_algorithm.oid
        if oid == OID_ED25519:
            if not isinstance(key, Ed25519Keys): return False
            return key.verify(self.tbs_der, self.signature)
        if oid == OID_RSA_PSS:
            if not isinstance(key, RSAKeys): return False
            hash_name, salt_len = _parse_pss_params(self.signature_algorithm.params)
            return key.verify_pss(self.tbs_der, self.signature, hash_name, salt_len)
        if oid in ECDSA_SIG_OID_TO_HASH:
            if not isinstance(key, ECDSAKeys): return False
            hash_name = ECDSA_SIG_OID_TO_HASH[oid]
            return key.verify(self.tbs_der, self.signature, hash_name)
        hash_name = SIG_ALG_RSA_HASH.get(oid)
        if hash_name is None or not isinstance(key, RSAKeys):
            return False
        return key.verify_pkcs1v15(self.tbs_der, self.signature, hash_name)

    def is_fresh(self, when=None, skew=300):
        """Все thisUpdate не старше skew секунд (по умолчанию 5 мин запаса)."""
        when = when or datetime.datetime.now(datetime.timezone.utc)
        for r in self.responses:
            tu = r["this_update"]
            nu = r["next_update"]
            if nu is not None and when > nu:
                return False
            if tu is not None and when < tu - datetime.timedelta(seconds=skew):
                return False
        return True

    def to_der(self): return self.der
    def to_pem(self): return pem_encode("OCSP RESPONSE", self.der)

    def __repr__(self):
        return f"<OCSPResponse status={self.status} responses={len(self.responses)}>"

    def __str__(self):
        lines = [
            f"OCSP Response",
            f"  Status:      {self.status}",
        ]
        if self.responder_id:
            lines.append(f"  Responder:   {self.responder_id[0]}={self.responder_id[1]}")
        if self.produced_at:
            lines.append(f"  Produced at: {self.produced_at.isoformat()}")
        for r in self.responses:
            lines.append(f"  ---")
            lines.append(f"    Serial:   0x{r['serial']:x}")
            lines.append(f"    Status:   {r['status']}")
            if r["status"] == "revoked":
                lines.append(f"    Revoked:  {r['revoked_at'].isoformat()}")
                if r["reason_code"] is not None:
                    lines.append(f"    Reason:   "
                                 f"{CRL_REASONS_REV.get(r['reason_code'], r['reason_code'])}")
            lines.append(f"    This:     {r['this_update'].isoformat()}")
            if r["next_update"]:
                lines.append(f"    Next:     {r['next_update'].isoformat()}")
        return "\n".join(lines)


class OCSPResponseBuilder:
    """Сборка подписанного OCSPResponse."""

    def __init__(self):
        self._responder = None
        self._produced_at = None
        self._next_update = None
        self._days = 7
        self._hash_name = "sha256"
        self._sig_scheme = "pkcs1v15"
        self._statuses = []         # list of dict
        self._nonce = None
        self._include_certs = True

    def set_responder(self, cert):
        """Cert/CACert, от чьего имени отвечаем."""
        if not isinstance(cert, Cert):
            _fail("set_responder: нужен Cert/CACert",
                  ".set_responder(ca)")
        self._responder = cert
        return self

    def set_validity(self, days=7):
        if days <= 0:
            raise ValueError("days must be positive")
        self._days = days
        return self

    def set_produced_at(self, dt):
        self._produced_at = dt
        return self

    def set_next_update(self, dt):
        self._next_update = dt
        return self

    def set_nonce(self, nonce):
        self._nonce = bytes(nonce) if nonce else None
        return self

    def set_hash(self, hash_name):
        if hash_name not in _HASH_OIDS:
            raise ValueError(f"unsupported hash: {hash_name}")
        self._hash_name = hash_name
        return self

    def set_sig_scheme(self, scheme):
        if scheme not in ("pkcs1v15", "pss"):
            raise ValueError("scheme must be pkcs1v15 or pss")
        self._sig_scheme = scheme
        return self

    use_pss = lambda self: self.set_sig_scheme("pss")

    def include_certs(self, yes=True):
        self._include_certs = bool(yes)
        return self

    def add_status(self, cert_or_serial, status="good", *,
                   reason=None, when=None):
        """status: 'good' | 'revoked' | 'unknown'."""
        if isinstance(cert_or_serial, Cert):
            serial = cert_or_serial.serial
        else:
            serial = int(cert_or_serial)
        if serial <= 0:
            raise ValueError("serial must be positive")
        if status not in ("good", "revoked", "unknown"):
            _fail(f"add_status: неизвестный статус {status!r}",
                  "good / revoked / unknown")
        code = None
        if reason is not None:
            if isinstance(reason, int):
                code = reason
            elif reason in CRL_REASONS:
                code = CRL_REASONS[reason]
            else:
                _fail(f"add_status: неизвестная причина {reason!r}",
                      "используй: " + ", ".join(CRL_REASONS))
        when = when or datetime.datetime.now(datetime.timezone.utc)
        self._statuses.append({
            "serial": serial, "status": status,
            "reason_code": code, "when": when,
        })
        return self

    def sign(self, signing_key):
        if self._responder is None:
            _fail("OCSPResponseBuilder: responder не задан",
                  ".set_responder(ca)")
        if not self._statuses:
            _fail("OCSPResponseBuilder: нет ни одного статуса",
                  ".add_status(cert, status='good')")
        if not signing_key.is_private:
            _fail("OCSPResponseBuilder: нужен приватный ключ",
                  "используй приватный ключ CA")

        now = datetime.datetime.now(datetime.timezone.utc)
        produced = self._produced_at or now
        next_upd = self._next_update or (produced + datetime.timedelta(days=self._days))

        # ---- responses SEQUENCE OF SingleResponse ----
        sr_list = []
        for st in self._statuses:
            cert_id = _enc_cert_id(self._responder, st["serial"], self._hash_name)
            # CertStatus
            if st["status"] == "good":
                status_der = b"\x80\x00"
            elif st["status"] == "unknown":
                status_der = b"\x82\x00"
            else:  # revoked
                rev = _enc_gentime(st["when"])
                if st["reason_code"] is not None:
                    rev += _der_tlv(0xA0, _der_tlv(0x0A, bytes([st["reason_code"]])))
                status_der = _der_tlv(0xA1, rev)
            sr_parts = [cert_id, status_der, _enc_gentime(st["this_update"] if "this_update" in st else now)]
            sr_parts.append(_der_tlv(0xA0, _enc_gentime(next_upd)))
            sr_list.append(der_seq(*sr_parts))
        responses_seq = der_seq(*sr_list)

        # ---- ResponderID: byName (проще) ----
        # [1] EXPLICIT Name — оборачиваем raw Name
        responder_id = _der_tlv(0xA1, self._responder.subject.raw)

        # ---- TBS ResponseData ----
        tbs_parts = [
            responder_id,
            _enc_gentime(produced),
            responses_seq,
        ]
        if self._nonce is not None:
            nonce_ext = _enc_extension(OID_OCSP_NONCE, False, der_octet(self._nonce))
            tbs_parts.append(_der_tlv(0xA1, der_seq(nonce_ext)))
        tbs = der_seq(*tbs_parts)

        # ---- signature ----
        sig_alg, sig = _sign_and_build_alg(
            signing_key, tbs, self._hash_name, self._sig_scheme)

        basic_parts = [tbs, sig_alg, der_bitstring(sig)]
        if self._include_certs:
            basic_parts.append(_der_tlv(0xA0, der_seq(self._responder.der)))
        basic = der_seq(*basic_parts)

        # ---- ResponseBytes ----
        rb = der_seq(encode_oid(OID_OCSP_BASIC), der_octet(basic))
        outer = der_seq(_der_tlv(0x0A, b"\x00"), _der_tlv(0xA0, rb))
        return OCSPResponse(outer)


def _ocsp_error(status_name, message=""):
    """Простой OCSPResponse с ошибкой (без подписи)."""
    code = OCSP_STATUS_CODES.get(status_name, 2)
    return OCSPResponse(der_seq(_der_tlv(0x0A, bytes([code]))))


# ======================================================================
#  PKCS#12 (RFC 7292) — export / import / verify
# ======================================================================

OID_PKCS7_DATA         = "1.2.840.113549.1.7.1"
OID_PKCS7_ENCRYPTED    = "1.2.840.113549.1.7.6"
OID_PKCS12_KEY_BAG     = "1.2.840.113549.1.12.10.1.1"
OID_PKCS12_SHROUDED    = "1.2.840.113549.1.12.10.1.2"
OID_PKCS12_CERT_BAG    = "1.2.840.113549.1.12.10.1.3"
OID_PKCS12_SAFE_BAG    = "1.2.840.113549.1.12.10.1.6"
OID_X509_CERTIFICATE   = "1.2.840.113549.1.9.22.1"
OID_FRIENDLY_NAME      = "1.2.840.113549.1.9.20"
OID_LOCAL_KEY_ID       = "1.2.840.113549.1.9.21"
OID_HMAC_SHA1          = "1.2.840.113549.2.7"


def _pkcs12_pbkdf(password, salt, iterations, keylen,
                  purpose=1, hash_name="sha1"):
    """PKCS#12 KDF (RFC 7292 Appendix B).

    purpose: 1 — key material, 2 — IV, 3 — MAC key.
    НЕ обычный PBKDF2 — у них разный алгоритм! Здесь ID в начале пароля,
    и обновление I через +B+1, а не через XOR.
    """
    u = hashlib.new(hash_name).digest_size
    v = 64
    if isinstance(password, str):
        password_b = password.encode("utf-16-be") + b"\x00\x00"
    else:
        password_b = bytes(password)
    D = bytes([purpose]) * v

    # Slen = v * ceil(saltlen / v); S = salt, повторённый до Slen байт.
    # ВАЖНО: (salt * n_rep)[:Slen] с n_rep = ceil(Slen / len(salt)),
    # а не ceil(len(salt) / v) — иначе S будет короче v-блока.
    if salt:
        Slen = v * ((len(salt) + v - 1) // v)
        n_rep = (Slen + len(salt) - 1) // len(salt)
        S = (salt * n_rep)[:Slen]
    else:
        S = b""

    if password_b:
        Plen = v * ((len(password_b) + v - 1) // v)
        n_rep = (Plen + len(password_b) - 1) // len(password_b)
        P = (password_b * n_rep)[:Plen]
    else:
        P = b""

    I = S + P
    c = (keylen + u - 1) // u
    out = b""
    for _ in range(c):
        A = hashlib.new(hash_name, D + I).digest()
        for _ in range(iterations - 1):
            A = hashlib.new(hash_name, A).digest()
        out += A
        # I_j = (I_j + B + 1) mod 2^v
        B = (A * ((v + len(A) - 1) // len(A)))[:v]
        b_int = int.from_bytes(B, "big")
        new_I = bytearray()
        for j in range(0, len(I), v):
            blk = int.from_bytes(I[j:j+v], "big")
            new_blk = (blk + b_int + 1) & ((1 << (v * 8)) - 1)
            new_I.extend(new_blk.to_bytes(v, "big"))
        I = bytes(new_I)
    return out[:keylen]


def _pkcs12_mac(password, authSafe_der, salt, iterations,
                hash_name="sha256"):
    """MAC = HMAC-hash(K[0:hashlen], authSafe_der), K = PBKDF(purpose=3).

    SHA-1 по умолчанию не используется — OpenSSL 3.x его не принимает
    для MAC (legacy provider disabled).
    """
    dlen = hashlib.new(hash_name).digest_size
    K = _pkcs12_pbkdf(password, salt, iterations, dlen,
                      purpose=3, hash_name=hash_name)
    return hmac.new(K, authSafe_der, hash_name).digest()


def _enc_cert_bag(cert_der, friendly_name=None, key_id=None):
    """CertBag + bagAttributes."""
    # CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
    cert_bag = der_seq(
        encode_oid(OID_X509_CERTIFICATE),
        _der_tlv(0xA0, der_octet(cert_der)),
    )

    attrs = []
    if friendly_name:
        attrs.append(der_seq(
            encode_oid(OID_FRIENDLY_NAME),
            der_set(_der_tlv(0x0C, friendly_name.encode("utf-8"))),
        ))
    if key_id:
        attrs.append(der_seq(
            encode_oid(OID_LOCAL_KEY_ID),
            der_set(der_octet(key_id)),
        ))

    parts = [
        encode_oid(OID_PKCS12_CERT_BAG),
        _der_tlv(0xA0, cert_bag),
    ]
    if attrs:
        parts.append(der_set(*attrs))

    return der_seq(*parts)


def _enc_shrouded_key_bag(encrypted_pkcs8_der, friendly_name=None, key_id=None):
    """SafeBag с pkcs8ShroudedKeyBag."""
    attrs = []
    if friendly_name:
        attrs.append(der_seq(
            encode_oid(OID_FRIENDLY_NAME),
            der_set(_der_tlv(0x0C, friendly_name.encode("utf-8"))),
        ))
    if key_id:
        attrs.append(der_seq(
            encode_oid(OID_LOCAL_KEY_ID),
            der_set(der_octet(key_id)),
        ))

    parts = [
        encode_oid(OID_PKCS12_SHROUDED),
        _der_tlv(0xA0, encrypted_pkcs8_der),
    ]
    if attrs:
        parts.append(der_set(*attrs))

    return der_seq(*parts)


def _pkcs12_wrap_data(content_der):
    """ContentInfo { pkcs7-data, [0] EXPLICIT OCTET STRING(content_der) }."""
    return der_seq(
        encode_oid(OID_PKCS7_DATA),
        _der_tlv(0xA0, der_octet(content_der)),
    )


def _pkcs12_wrap_encrypted(pbes2_encrypted_der):
    """ContentInfo { pkcs7-encryptedData, [0] EXPLICIT EncryptedData }.

    pbes2_encrypted_der — EncryptedData DER.
    """
    return der_seq(
        encode_oid(OID_PKCS7_ENCRYPTED),
        _der_tlv(0xA0, pbes2_encrypted_der),
    )


def _pkcs12_encrypted_data(pbes2_alg_der, ciphertext):
    """EncryptedData { version=0, EncryptedContentInfo { pkcs7-data, alg, [0] IMPLICIT } }."""
    eci = der_seq(
        encode_oid(OID_PKCS7_DATA),
        pbes2_alg_der,
        _der_tlv(0x80, ciphertext),   # [0] IMPLICIT OCTET STRING
    )
    return der_seq(der_int(0), eci)


class PKCS12:
    """
    PKCS#12 (RFC 7292) контейнер: приватный ключ + сертификат + цепочка.

    Совместим с OpenSSL: файлы читаются `openssl pkcs12 -in ... -info`,
    наоборот — тоже.

    Использование:
        # Экспорт
        pk = PKCS12.build(key, cert, chain=[inter], password="hunter2",
                          name="client")
        pk.save("client.p12")

        # Импорт
        pk = PKCS12.from_file("client.p12", password="hunter2")
        print(pk.key, pk.cert, pk.chain)
        assert pk.verify_mac("hunter2")
    """

    @_safe_parse
    def __init__(self, key, cert, chain=None, password="",
                 name=None, iterations=2048, mac_iterations=2048):
        if not isinstance(cert, Cert):
            raise TypeError("PKCS12: cert must be a Cert/CACert")
        if not key.is_private:
            raise X509Error("PKCS12: нужен приватный ключ")
        self.key = key
        self.cert = cert
        self.chain = list(chain or [])
        self.password = password
        self.name = name or (cert.subject.get("CN") or "certificate")
        self.iterations = iterations
        self.mac_iterations = mac_iterations
        self._mac_salt = None
        self._mac_verified = None
        self._last_auth_safe_der = None
        self._last_mac_salt = None
        self._last_mac_iter = None
        self._last_mac_hash = None
        self._last_mac_value = None

    # ---- export ----

    def to_der(self):
        # 1. localKeyId — общий 20-байтовый идентификатор key↔cert
        key_id = secrets.token_bytes(20)

        # 2. Приватный ключ → PKCS#8 → шифруем (EncryptedPrivateKeyInfo)
        pkcs8_inner = self._key_to_pkcs8_der()
        shrouded_der = _pkcs8_encrypt(
            pkcs8_inner, self.password, iterations=self.iterations,
            cipher="aes-256-cbc",
        )

        # 3. SafeBag #1: pkcs8ShroudedKeyBag (EncryptedPrivateKeyInfo)
        key_bag = _enc_shrouded_key_bag(shrouded_der,
                                        friendly_name=self.name,
                                        key_id=key_id)
        key_safe_contents = der_seq(key_bag)

        # 4. SafeBag #2: certBags (leaf + chain)
        cert_bags = [_enc_cert_bag(self.cert.der,
                                    friendly_name=self.name,
                                    key_id=key_id)]
        for c in self.chain:
            cert_bags.append(_enc_cert_bag(c.der,
                                           friendly_name=self.name))
        cert_safe_contents = der_seq(*cert_bags)

        # 5. authSafe: SEQUENCE OF ContentInfo(pkcs7-data, ...)
        auth_safe = der_seq(
            _pkcs12_wrap_data(key_safe_contents),
            _pkcs12_wrap_data(cert_safe_contents),
        )

        # 6. ContentInfo для PFX
        pfx_content_info = der_seq(
            encode_oid(OID_PKCS7_DATA),
            _der_tlv(0xA0, der_octet(auth_safe)),
        )

        # 7. MAC (HMAC-SHA1 через PKCS#12 KDF purpose=3)
        mac_salt = secrets.token_bytes(16)
        mac_hash = "sha256"
        mac = _pkcs12_mac(self.password, auth_safe, mac_salt,
                          self.mac_iterations, hash_name=mac_hash)
        # Запомним для последующего verify_mac() на этом же объекте
        self._last_auth_safe_der = auth_safe
        self._last_mac_salt = mac_salt
        self._last_mac_iter = self.mac_iterations
        self._last_mac_hash = mac_hash
        self._last_mac_value = mac
        # В MacData.digestAlgorithm — plain digest OID, НЕ HMAC-wrapper.
        # wrapper (id-hmacWithSHA256) → EVP_get_digestbynid вернёт NULL,
        # OpenSSL падает с "unknown digest algorithm".
        digest_info = der_seq(
            der_seq(encode_oid(_HASH_OIDS[mac_hash]), der_null()),
            der_octet(mac),
        )
        mac_data = der_seq(digest_info, der_octet(mac_salt),
                           der_int(self.mac_iterations))

        # 8. PFX ::= SEQUENCE { version=3, authSafe, macData }
        return der_seq(der_int(3), pfx_content_info, mac_data)

    def _key_to_pkcs8_der(self):
        """Обернуть to_private_der() ключа в PKCS#8, если надо."""
        raw = self.key.to_private_der()
        if isinstance(self.key, RSAKeys):
            alg = der_seq(encode_oid(OID_RSA_ENCRYPTION), der_null())
            return der_seq(der_int(0), alg, der_octet(raw))
        # Ed25519 и ECDSA уже возвращают PKCS#8
        return raw

    def save(self, path):
        path = os.path.expanduser(path)
        with open(path, "wb") as f:
            f.write(self.to_der())
        return os.path.abspath(path)

    @classmethod
    def build(cls, key, cert, chain=None, password="",
              name=None, iterations=2048):
        return cls(key, cert, chain=chain, password=password, name=name,
                   iterations=iterations)

    # ---- import ----

    @classmethod
    def load(cls, data, password=""):
        if isinstance(data, str):
            data = data.encode("ascii")
        if b"-----BEGIN" in data:
            # PEM-обёртка для PKCS#12 встречается, но редко — раскодируем
            blocks = pem_decode(data)
            if not blocks:
                raise X509ParseError("no PEM blocks in PKCS12")
            data = blocks[0][1]

        root, _ = ASN1.parse(data)
        if root.tag != TAG_SEQUENCE or len(root.children) < 2:
            raise X509ParseError("not a PFX structure")

        version = root.children[0].as_int()
        if version != 3:
            raise X509ParseError(f"unsupported PKCS12 version: {version}")

        auth_safe_ci = root.children[1]
        mac_data = root.children[2] if len(root.children) > 2 else None

        # authSafe
        if auth_safe_ci.children[0].as_oid() != OID_PKCS7_DATA:
            raise X509ParseError("PFX: authSafe must be pkcs7-data")
        auth_safe_octet = auth_safe_ci.children[1].children[0].value
        auth_safe_der = auth_safe_octet

        # MAC
        mac_ok = None
        mac_salt = None
        mac_iter = None
        if mac_data is not None:
            digest_info = mac_data.children[0]
            # AlgorithmIdentifier → OID определяет, какой хеш
            mac_alg = AlgorithmIdentifier(digest_info.children[0])
            # Поддерживаем и plain digest OID (правильно по RFC 7292),
            # и HMAC-wrapper OID (встречается у некоторых генераторов)
            mac_hash_map = {
                # plain digest OIDs
                "1.3.14.3.2.26":        "sha1",
                "2.16.840.1.101.3.4.2.4": "sha224",
                "2.16.840.1.101.3.4.2.1": "sha256",
                "2.16.840.1.101.3.4.2.2": "sha384",
                "2.16.840.1.101.3.4.2.3": "sha512",
                # HMAC-wrapper OIDs (legacy, некоторые генераторы)
                "1.2.840.113549.2.7":   "sha1",
                "1.2.840.113549.2.8":   "sha224",
                "1.2.840.113549.2.9":   "sha256",
                "1.2.840.113549.2.10":  "sha384",
                "1.2.840.113549.2.11":  "sha512",
            }
            mac_hash = mac_hash_map.get(mac_alg.oid, "sha256")
            mac_expected = digest_info.children[1].value
            mac_salt = mac_data.children[1].value
            mac_iter = mac_data.children[2].as_int()
            mac_actual = _pkcs12_mac(password, auth_safe_der,
                                     mac_salt, mac_iter,
                                     hash_name=mac_hash)
            mac_ok = hmac.compare_digest(mac_expected, mac_actual)

        # AuthenticatedSafe = SEQUENCE OF ContentInfo
        auth_node, _ = ASN1.parse(auth_safe_der)

        key_obj = None
        cert_obj = None
        chain = []

        for ci in auth_node.children:
            if not ci.children:
                continue
            ci_type = ci.children[0].as_oid()
            if ci_type == OID_PKCS7_DATA:
                # [0] EXPLICIT OCTET STRING( SafeContents DER )
                safe_data = ci.children[1].children[0].value
                k, c, ch = cls._parse_safe_contents(safe_data, password)
                if k and key_obj is None: key_obj = k
                if c and cert_obj is None: cert_obj = c
                chain.extend(ch)
            elif ci_type == OID_PKCS7_ENCRYPTED:
                # EncryptedData { version, EncryptedContentInfo }
                enc_data = ci.children[1].children[0]
                eci = enc_data.children[1]
                alg = AlgorithmIdentifier(eci.children[1])
                ciphertext = eci.children[2].value
                plain = cls._decrypt_pbes2(alg, ciphertext, password)
                k, c, ch = cls._parse_safe_contents(plain, password)
                if k and key_obj is None: key_obj = k
                if c and cert_obj is None: cert_obj = c
                chain.extend(ch)

        if cert_obj is None:
            raise X509ParseError("PKCS12: no certificate found")
        if key_obj is None:
            raise X509ParseError("PKCS12: no private key found")

        obj = cls.__new__(cls)
        obj.key = key_obj
        obj.cert = cert_obj
        obj.chain = chain
        obj.password = password
        obj.name = cert_obj.subject.get("CN") or "certificate"
        obj.iterations = 0
        obj.mac_iterations = mac_iter or 0
        obj._mac_salt = mac_salt
        obj._mac_verified = mac_ok
        return obj

    @classmethod
    def from_file(cls, path, password=""):
        with open(os.path.expanduser(path), "rb") as f:
            return cls.load(f.read(), password=password)

    @staticmethod
    def _decrypt_pbes2(alg_id, ciphertext, password):
        """PBES2 (как у _pkcs8_decrypt, но вынесено отдельно)."""
        # alg_id.oid == OID_PBES2
        if alg_id.oid != OID_PBES2:
            raise X509Error(f"unsupported cipher OID: {alg_id.oid}")
        pbes2 = alg_id.params
        kdf_seq = pbes2.children[0]
        enc_scheme = pbes2.children[1]
        if kdf_seq.children[0].as_oid() != OID_PBKDF2:
            raise X509Error(f"unsupported KDF: {kdf_seq.children[0].as_oid()}")
        kdf_params = kdf_seq.children[1]
        salt = kdf_params.children[0].value
        iterations = kdf_params.children[1].as_int()
        keylen = 32
        i = 2
        if i < len(kdf_params.children) and kdf_params.children[i].tag == TAG_INTEGER:
            keylen = kdf_params.children[i].as_int()
            i += 1
        # PRF
        prf_oid = OID_HMAC_SHA256
        if i < len(kdf_params.children):
            prf_oid = kdf_params.children[i].children[0].as_oid()
        prf_map = {
            OID_HMAC_SHA256: "sha256",
            "1.2.840.113549.2.7": "sha1",
            "1.2.840.113549.2.8": "sha224",
            "1.2.840.113549.2.9": "sha256",
            "1.2.840.113549.2.10": "sha384",
            "1.2.840.113549.2.11": "sha512",
        }
        hash_name = prf_map.get(prf_oid, "sha256")

        if isinstance(password, str):
            password_b = password.encode("utf-8")
        else:
            password_b = password
        key = hashlib.pbkdf2_hmac(hash_name, password_b, salt, iterations, keylen)

        cipher_oid = enc_scheme.children[0].as_oid()
        params = enc_scheme.children[1]
        if cipher_oid == OID_AES_256_CBC:
            iv = params.value
            return _aes256_cbc_decrypt(key, iv, ciphertext)
        if cipher_oid == OID_AES_256_GCM:
            iv = params.children[0].value
            tag_len = 16
            if len(params.children) > 1:
                tag_len = params.children[1].as_int()
            ct, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
            return _aes256_gcm_decrypt(key, iv, ct, tag)
        raise X509Error(f"unsupported cipher: {cipher_oid}")

    @staticmethod
    def _parse_safe_contents(safe_contents_der, password):
        """SafeContents = SEQUENCE OF SafeBag. Возвращает (key, cert, chain)."""
        node, _ = ASN1.parse(safe_contents_der)
        if node.tag != TAG_SEQUENCE:
            raise X509ParseError("SafeContents: not SEQUENCE")

        key_obj = None
        cert_obj = None
        chain = []

        for bag in node.children:
            if not bag.children or len(bag.children) < 2:
                continue
            bag_id = bag.children[0].as_oid()

            # bag value = [0] EXPLICIT <bag>
            wrapper = bag.children[1]
            if not wrapper.children:
                continue
            bag_value = wrapper.children[0]

            if bag_id == OID_PKCS12_CERT_BAG:
                # CertBag { certId, certValue [0] EXPLICIT OCTET STRING(der) }
                if not bag_value.children or len(bag_value.children) < 2:
                    continue
                cert_id = bag_value.children[0].as_oid()
                if cert_id != OID_X509_CERTIFICATE:
                    continue
                try:
                    cert_der = bag_value.children[1].children[0].value
                except (IndexError, AttributeError):
                    continue
                c = Cert(cert_der)
                if cert_obj is None:
                    cert_obj = c
                else:
                    chain.append(c)

            elif bag_id == OID_PKCS12_SHROUDED:
                # bag_value — EncryptedPrivateKeyInfo (SEQUENCE { alg, octet })
                try:
                    plain = _pkcs8_decrypt(bag_value.raw, password)
                except Exception as e:
                    raise X509Error(f"PKCS12: cannot decrypt key bag: {e}")
                key_obj = PKCS12._key_from_pkcs8_der(plain)

            elif bag_id == OID_PKCS12_KEY_BAG:
                # открытый PrivateKeyInfo (без шифрования)
                key_obj = PKCS12._key_from_pkcs8_der(bag_value.raw)

        return key_obj, cert_obj, chain

    @staticmethod
    def _key_from_pkcs8_der(pkcs8_der):
        """Распознать тип ключа по PKCS#8 AlgorithmIdentifier."""
        node, _ = ASN1.parse(pkcs8_der)
        if node.tag != TAG_SEQUENCE or len(node.children) < 3:
            # может быть PKCS#1 RSAPrivateKey
            return RSAKeys.from_private_der(pkcs8_der)
        alg_oid = node.children[1].children[0].as_oid()
        if alg_oid == OID_RSA_ENCRYPTION:
            return RSAKeys.from_private_der(pkcs8_der)
        if alg_oid == OID_ED25519:
            return Ed25519Keys.from_private_der(pkcs8_der)
        if alg_oid == OID_EC_PUBLIC_KEY:
            return ECDSAKeys.from_private_der(pkcs8_der)
        raise X509Error(f"unsupported key algorithm in PKCS12: {alg_oid}")

    # ---- verify ----

    def verify_mac(self, password=None):
        """Проверить MAC.

        * После load() — возвращает кэшированный результат проверки.
        * После build() + to_der() — пересчитывает из сохранённых параметров.
        * Иначе — пересобирает to_der() и парсит заново (медленно, но работает).
        """
        if password is None:
            password = self.password

        # Случай A: уже проверяли при load()
        if self._mac_verified is not None and password == self.password:
            return self._mac_verified

        # Случай B: свежепостроенный объект — есть сохранённые параметры
        if self._last_auth_safe_der is not None:
            mac_actual = _pkcs12_mac(
                password, self._last_auth_safe_der,
                self._last_mac_salt, self._last_mac_iter,
                hash_name=self._last_mac_hash)
            return hmac.compare_digest(mac_actual, self._last_mac_value)

        # Случай C: вообще нет данных — пересобрать через to_der()
        der = self.to_der()
        reloaded = PKCS12.load(der, password=password)
        return reloaded.verify_mac(password)

    def verify_chain(self, trust_anchor=None, when=None):
        """Проверить цепочку: leaf + intermediates → trust_anchor.

        Если trust_anchor=None, в качестве anchor используется последний
        элемент self.chain. Он НЕ считается промежуточным — это и есть CA,
        который подписал предыдущий сертификат.
        """
        # Определяем anchor и промежуточные
        if trust_anchor is None:
            if not self.chain:
                return False
            anchor = self.chain[-1]
            mid = list(self.chain[:-1])
        else:
            anchor = trust_anchor
            mid = list(self.chain)
            # если последний совпадает с anchor — убираем дубликат
            if mid and mid[-1].der == anchor.der:
                mid = mid[:-1]

        try:
            ca_obj = CACert(anchor.der)
        except Exception:
            return False

        return ca_obj.verify_chain([self.cert] + mid, when=when)

    def __repr__(self):
        return (f"<PKCS12 key={type(self.key).__name__} "
                f"cert={self.cert.subject!r} chain={len(self.chain)}>")


class PKCS12Builder:
    """
    Fluent-обёртка над PKCS12.build().

    Пример:
        data = (PKCS12Builder()
            .set_key(leaf_key)
            .set_cert(leaf)
            .add_chain(ca_inter, ca_root)
            .set_password("hunter2")
            .set_name("alice")
            .build())

        data.save("alice.p12")
        # или одной строкой:
        PKCS12Builder().set_key(k).set_cert(c).set_password("pw").save("x.p12")
    """

    def __init__(self):
        self._key = None
        self._cert = None
        self._chain = []
        self._password = ""
        self._name = None
        self._iterations = 2048
        self._mac_iterations = 2048
        self._cipher = "aes-256-cbc"

    # ---- ключ и сертификат ----

    def set_key(self, key):
        """Приватный ключ (RSAKeys / Ed25519Keys / ECDSAKeys)."""
        self._key = key
        return self

    def set_cert(self, cert):
        """Листовой сертификат (Cert/CACert)."""
        self._cert = cert
        return self

    def add_chain(self, *certs):
        """Промежуточные сертификаты (в порядке от leaf к root)."""
        for c in certs:
            if isinstance(c, (Cert, CACert)):
                self._chain.append(c)
            elif isinstance(c, (list, tuple)):
                for x in c:
                    if not isinstance(x, (Cert, CACert)):
                        _fail(
                            f"PKCS12Builder.add_chain: не Cert — {type(x).__name__}",
                            "передавай Cert, CACert или список из них",
                        )
                    self._chain.append(x)
            else:
                _fail(
                    f"PKCS12Builder.add_chain: не Cert — {type(c).__name__}",
                    "передавай Cert, CACert или список из них",
                )
        return self

    # алиасы для симметрии с CertificateBuilder
    add_key = set_key
    add_cert = set_cert

    # ---- параметры контейнера ----

    def set_password(self, password):
        """Пароль для шифрования ключа и MAC. Пустая строка — не рекомендую."""
        self._password = password or ""
        return self

    def set_name(self, name):
        """friendlyName для UI (Windows/macOS показывают это в keychain)."""
        self._name = name
        return self

    def set_iterations(self, n):
        """PBKDF2 iterations для шифрования ключа (по умолчанию 2048)."""
        if n < 1:
            _fail("PKCS12Builder.set_iterations: n < 1",
                  "используй >= 2048 для production")
        self._iterations = int(n)
        return self

    def set_mac_iterations(self, n):
        """PKCS#12 KDF iterations для MAC (по умолчанию 2048)."""
        if n < 1:
            _fail("PKCS12Builder.set_mac_iterations: n < 1",
                  "используй >= 2048 для production")
        self._mac_iterations = int(n)
        return self

    def set_cipher(self, cipher):
        """'aes-256-cbc' (default, совместимо с OpenSSL) или 'aes-256-gcm'."""
        if cipher not in ("aes-256-cbc", "aes-256-gcm"):
            _fail(f"PKCS12Builder.set_cipher: неизвестный шифр {cipher!r}",
                  "используй 'aes-256-cbc' или 'aes-256-gcm'")
        self._cipher = cipher
        return self

    # ---- финал ----

    def build(self) -> "PKCS12":
        """Собрать PKCS12. Проверяет обязательные поля."""
        if self._key is None:
            _fail("PKCS12Builder.build: ключ не задан", ".set_key(key)")
        if self._cert is None:
            _fail("PKCS12Builder.build: сертификат не задан", ".set_cert(cert)")
        if not self._key.is_private:
            _fail("PKCS12Builder.build: нужен ПРИВАТНЫЙ ключ",
                  ".set_key(private_key), не публичный")
        # Сверяем, что ключ соответствует сертификату
        cert_pub = self._cert.public_key
        if not _public_keys_equal(self._key, cert_pub):
            _fail(
                "PKCS12Builder.build: приватный ключ не соответствует "
                "публичному ключу в сертификате",
                "проверь, что .set_key(k) и .set_cert(cert) — от одного ключа",
            )
        # Проверим, что chain согласован
        # (не обязательно, но полезно предупредить)
        obj = PKCS12.__new__(PKCS12)
        obj.key = self._key
        obj.cert = self._cert
        obj.chain = list(self._chain)
        obj.password = self._password
        obj.name = self._name or (self._cert.subject.get("CN") or "certificate")
        obj.iterations = self._iterations
        obj.mac_iterations = self._mac_iterations
        obj._mac_salt = None
        obj._mac_verified = None
        obj._last_auth_safe_der = None
        obj._last_mac_salt = None
        obj._last_mac_iter = None
        obj._last_mac_hash = None
        obj._last_mac_value = None
        return obj

    def to_der(self):
        return self.build().to_der()

    def save(self, path):
        """Собрать и сохранить в файл."""
        return self.build().save(path)


def load_pem_bundle(data): return CertBundle.from_pem(data)


def save_pem(path, *items):
    lines = []
    for it in items:
        if isinstance(it, CertBundle):
            lines.append(it.to_pem())
        elif isinstance(it, (Cert, CACert, CSR)):
            lines.append(it.to_pem())
        elif isinstance(it, (list, tuple)):
            for x in it:
                if not isinstance(x, (Cert, CACert, CSR)):
                    raise TypeError(f"save_pem: не тот тип {type(x)}")
                lines.append(x.to_pem())
        else:
            raise TypeError(f"save_pem: не тот тип {type(it)}")
    path = os.path.expanduser(path)
    with open(path, "w") as f: f.write("".join(lines))
    return os.path.abspath(path)


# ======================================================================
#  AES-256 (чистый Python) + CBC
#  Только для шифрования приватных ключей в PKCS#8.
# ======================================================================

_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

_AES_INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb"
    "7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e"
    "082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b692"
    "6c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506"
    "d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e673"
    "96ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1b"
    "fc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f"
    "60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961"
    "172b047eba77d626e169146355210c7d"
)

_AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p


_GF_MUL2  = bytes(_gf_mul(b, 2)  for b in range(256))
_GF_MUL3  = bytes(_gf_mul(b, 3)  for b in range(256))
_GF_MUL9  = bytes(_gf_mul(b, 9)  for b in range(256))
_GF_MUL11 = bytes(_gf_mul(b, 11) for b in range(256))
_GF_MUL13 = bytes(_gf_mul(b, 13) for b in range(256))
_GF_MUL14 = bytes(_gf_mul(b, 14) for b in range(256))


def _aes256_key_expand(key):
    """AES-256 key expansion. key=32 байта → 60 words."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    w = [list(key[4*i:4*i+4]) for i in range(8)]
    for i in range(8, 60):
        t = list(w[i-1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [_AES_SBOX[b] for b in t]
            t[0] ^= _AES_RCON[i // 8 - 1]
        elif i % 8 == 4:
            t = [_AES_SBOX[b] for b in t]
        w.append([w[i-8][j] ^ t[j] for j in range(4)])
    return w


def _aes_shift_rows(s):
    return [s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11]]


def _aes_inv_shift_rows(s):
    return [s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3]]


def _aes_mix_columns(s):
    out = list(s)
    for c in range(4):
        a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
        out[4*c]   = _GF_MUL2[a0] ^ _GF_MUL3[a1] ^ a2 ^ a3
        out[4*c+1] = a0 ^ _GF_MUL2[a1] ^ _GF_MUL3[a2] ^ a3
        out[4*c+2] = a0 ^ a1 ^ _GF_MUL2[a2] ^ _GF_MUL3[a3]
        out[4*c+3] = _GF_MUL3[a0] ^ a1 ^ a2 ^ _GF_MUL2[a3]
    return out


def _aes_inv_mix_columns(s):
    out = list(s)
    for c in range(4):
        a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
        out[4*c]   = _GF_MUL14[a0] ^ _GF_MUL11[a1] ^ _GF_MUL13[a2] ^ _GF_MUL9[a3]
        out[4*c+1] = _GF_MUL9[a0] ^ _GF_MUL14[a1] ^ _GF_MUL11[a2] ^ _GF_MUL13[a3]
        out[4*c+2] = _GF_MUL13[a0] ^ _GF_MUL9[a1] ^ _GF_MUL14[a2] ^ _GF_MUL11[a3]
        out[4*c+3] = _GF_MUL11[a0] ^ _GF_MUL13[a1] ^ _GF_MUL9[a2] ^ _GF_MUL14[a3]
    return out


def _aes_round_keys(w):
    rk = []
    for r in range(15):
        block = []
        for c in range(4):
            block.extend(w[4*r + c])
        rk.append(block)
    return rk


def _aes256_encrypt_block(block, w):
    state = list(block)
    rk = _aes_round_keys(w)
    for i in range(16):
        state[i] ^= rk[0][i]
    for r in range(1, 14):
        state = [_AES_SBOX[b] for b in state]
        state = _aes_shift_rows(state)
        state = _aes_mix_columns(state)
        for i in range(16):
            state[i] ^= rk[r][i]
    state = [_AES_SBOX[b] for b in state]
    state = _aes_shift_rows(state)
    for i in range(16):
        state[i] ^= rk[14][i]
    return bytes(state)


def _aes256_decrypt_block(block, w):
    state = list(block)
    rk = _aes_round_keys(w)
    for i in range(16):
        state[i] ^= rk[14][i]
    for r in range(13, 0, -1):
        state = _aes_inv_shift_rows(state)
        state = [_AES_INV_SBOX[b] for b in state]
        for i in range(16):
            state[i] ^= rk[r][i]
        state = _aes_inv_mix_columns(state)
    state = _aes_inv_shift_rows(state)
    state = [_AES_INV_SBOX[b] for b in state]
    for i in range(16):
        state[i] ^= rk[0][i]
    return bytes(state)


def _pkcs7_pad(data, block=16):
    n = block - len(data) % block
    return data + bytes([n]) * n


def _pkcs7_unpad(data, block=16):
    if len(data) == 0 or len(data) % block != 0:
        raise X509Error("bad padding: length not multiple of block")
    n = data[-1]
    if n < 1 or n > block:
        raise X509Error(f"bad padding length: {n}")
    if data[-n:] != bytes([n]) * n:
        raise X509Error("bad padding content")
    return data[:-n]


def _aes256_cbc_encrypt(key, iv, plaintext):
    w = _aes256_key_expand(key)
    pt = _pkcs7_pad(plaintext, 16)
    out = bytearray()
    prev = iv
    for i in range(0, len(pt), 16):
        blk = bytes(a ^ b for a, b in zip(pt[i:i+16], prev))
        ct = _aes256_encrypt_block(blk, w)
        out.extend(ct)
        prev = ct
    return bytes(out)


def _aes256_cbc_decrypt(key, iv, ciphertext):
    w = _aes256_key_expand(key)
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise X509Error("ciphertext length must be multiple of 16")
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        blk = ciphertext[i:i+16]
        pt = _aes256_decrypt_block(blk, w)
        out.extend(a ^ b for a, b in zip(pt, prev))
        prev = blk
    return _pkcs7_unpad(bytes(out), 16)


# ======================================================================
#  AES-256-GCM (NIST SP 800-38D, чистый Python)
# ======================================================================

_AES_GCM_R = 0xE1 << 120


def _gf128_mul(x, y):
    """Умножение в GF(2^128). x, y, результат — int."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= _AES_GCM_R
    return z


def _ghash(h, data):
    """GHASH_{H}(data) → 16 bytes. h — int, data — bytes (кратно 16)."""
    if len(data) % 16 != 0:
        raise ValueError("GHASH: data length must be multiple of 16")
    y = 0
    for i in range(0, len(data), 16):
        blk = int.from_bytes(data[i:i+16], "big")
        y = _gf128_mul(y ^ blk, h)
    return y.to_bytes(16, "big")


def _gcm_inc32(block):
    """Increment last 32 bits (big-endian)."""
    counter = int.from_bytes(block[12:], "big")
    counter = (counter + 1) & 0xFFFFFFFF
    return block[:12] + counter.to_bytes(4, "big")


def _gcm_ctr(key_w, iv, data):
    """GCTR: AES-CTR. Первый блок шифруется counter'ом J0+1 = IV||0x02."""
    out = bytearray()
    counter = iv + b"\x00\x00\x00\x01"   # J0
    for i in range(0, len(data), 16):
        counter = _gcm_inc32(counter)         # J0+1 для первого блока
        ks = _aes256_encrypt_block(counter, key_w)
        blk = data[i:i+16]
        out.extend(a ^ b for a, b in zip(blk, ks))
    return bytes(out)


def _gcm_ghash_data(h_int, aad, ct):
    """GHASH для AAD + CT с длинами."""
    def pad16(b):
        if len(b) % 16 == 0:
            return b
        return b + b"\x00" * (16 - len(b) % 16)
    block = pad16(aad) + pad16(ct)
    block += (len(aad) * 8).to_bytes(8, "big")
    block += (len(ct) * 8).to_bytes(8, "big")
    return _ghash(h_int, block)


def _aes256_gcm_encrypt(key, nonce, plaintext, aad=b""):
    """AES-256-GCM encrypt. nonce — 12 байт. → (ct, tag16)."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM: key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("AES-256-GCM: nonce must be 12 bytes")
    w = _aes256_key_expand(key)
    h = int.from_bytes(_aes256_encrypt_block(b"\x00" * 16, w), "big")
    ct = _gcm_ctr(w, nonce, plaintext)
    s = _gcm_ghash_data(h, aad, ct)
    # tag = AES_K(J0) XOR S
    j0 = nonce + b"\x00\x00\x00\x01"
    ek_j0 = _aes256_encrypt_block(j0, w)
    tag = bytes(a ^ b for a, b in zip(ek_j0, s))
    return ct, tag


def _aes256_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    """AES-256-GCM decrypt. Verify tag, иначе X509Error."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM: key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("AES-256-GCM: nonce must be 12 bytes")
    w = _aes256_key_expand(key)
    h = int.from_bytes(_aes256_encrypt_block(b"\x00" * 16, w), "big")
    s = _gcm_ghash_data(h, aad, ciphertext)
    j0 = nonce + b"\x00\x00\x00\x01"
    ek_j0 = _aes256_encrypt_block(j0, w)
    expected_tag = bytes(a ^ b for a, b in zip(ek_j0, s))
    if not hmac.compare_digest(expected_tag, tag):
        raise X509Error("AES-GCM: tag mismatch (неверный пароль или данные)")
    return _gcm_ctr(w, nonce, ciphertext)


# ======================================================================
#  PKCS#8 EncryptedPrivateKeyInfo (PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC/GCM)
# ======================================================================

OID_PBES2              = "1.2.840.113549.1.5.13"
OID_PBKDF2             = "1.2.840.113549.1.5.12"
OID_HMAC_SHA256        = "1.2.840.113549.2.9"
OID_AES_256_CBC        = "2.16.840.1.101.3.4.1.42"
OID_AES_256_GCM        = "2.16.840.1.101.3.4.1.46"


def _pbkdf2_sha256(password, salt, iterations, keylen):
    if isinstance(password, str):
        password = password.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, keylen)


def _pkcs8_encrypt(plain_der, password, *, iterations=100000, salt=None,
                   cipher="aes-256-cbc", nonce=None):
    """plain_der → EncryptedPrivateKeyInfo DER.

    cipher: "aes-256-cbc" | "aes-256-gcm"
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    if salt is None:
        salt = secrets.token_bytes(16)
    key = _pbkdf2_sha256(password, salt, iterations, 32)

    if cipher == "aes-256-cbc":
        iv = nonce or secrets.token_bytes(16)
        ciphertext = _aes256_cbc_encrypt(key, iv, plain_der)
        enc_scheme = der_seq(encode_oid(OID_AES_256_CBC), der_octet(iv))
    elif cipher == "aes-256-gcm":
        iv = nonce or secrets.token_bytes(12)
        if len(iv) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes")
        ct, tag = _aes256_gcm_encrypt(key, iv, plain_der)
        ciphertext = ct + tag   # в PBES2 GCM tag — часть encryptedData
        # RFC 5084: AlgorithmIdentifier.params для GCM = SEQUENCE { nonce, ICVlen }
        gcm_params = der_seq(der_octet(iv), der_int(16))
        enc_scheme = der_seq(encode_oid(OID_AES_256_GCM), gcm_params)
    else:
        raise ValueError(f"unsupported cipher: {cipher}")

    prf = der_seq(encode_oid(OID_HMAC_SHA256), der_null())
    kdf_params = der_seq(
        der_octet(salt),
        der_int(iterations),
        der_int(32),
        prf,
    )
    kdf = der_seq(encode_oid(OID_PBKDF2), kdf_params)
    pbes2_params = der_seq(kdf, enc_scheme)
    alg = der_seq(encode_oid(OID_PBES2), pbes2_params)
    return der_seq(alg, der_octet(ciphertext))


def _pkcs8_decrypt(encrypted_der, password):
    """EncryptedPrivateKeyInfo DER → plain_der."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    root, _ = ASN1.parse(encrypted_der)
    if root.tag != TAG_SEQUENCE or len(root.children) != 2:
        raise X509ParseError("not an EncryptedPrivateKeyInfo")
    alg_seq, enc_data = root.children
    if alg_seq.children[0].as_oid() != OID_PBES2:
        raise X509Error(f"unsupported KDF: {alg_seq.children[0].as_oid()}")

    pbes2 = alg_seq.children[1]
    kdf_seq, enc_scheme = pbes2.children[0], pbes2.children[1]

    if kdf_seq.children[0].as_oid() != OID_PBKDF2:
        raise X509Error(f"unsupported KDF alg: {kdf_seq.children[0].as_oid()}")

    kdf_params = kdf_seq.children[1]
    salt = kdf_params.children[0].value
    iterations = kdf_params.children[1].as_int()
    idx = 2
    keylen = 32
    if kdf_params.children[idx].tag == TAG_INTEGER:
        keylen = kdf_params.children[idx].as_int()
        idx += 1
    # PRF опционально
    if idx < len(kdf_params.children):
        prf = kdf_params.children[idx]
        prf_oid = prf.children[0].as_oid()
        if prf_oid != OID_HMAC_SHA256:
            raise X509Error(f"unsupported PRF: {prf_oid}")

    cipher_oid = enc_scheme.children[0].as_oid()
    ciphertext = enc_data.value

    key = _pbkdf2_sha256(password, salt, iterations, keylen)

    if cipher_oid == OID_AES_256_CBC:
        iv = enc_scheme.children[1].value
        return _aes256_cbc_decrypt(key, iv, ciphertext)

    if cipher_oid == OID_AES_256_GCM:
        # params: SEQUENCE { OCTET STRING nonce, INTEGER ICVlen } — RFC 5084
        params = enc_scheme.children[1]
        if params.tag != TAG_SEQUENCE or not params.children:
            raise X509Error("AES-GCM: params must be SEQUENCE")
        iv = params.children[0].value
        tag_len = 16
        if len(params.children) > 1 and params.children[1].tag == TAG_INTEGER:
            tag_len = params.children[1].as_int()
        if len(iv) != 12:
            raise X509Error(f"AES-GCM: IV must be 12 bytes, got {len(iv)}")
        if len(ciphertext) < tag_len:
            raise X509Error("AES-GCM: ciphertext too short (no tag)")
        ct, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
        return _aes256_gcm_decrypt(key, iv, ct, tag)

    raise X509Error(f"unsupported cipher: {cipher_oid}")


# ======================================================================
#  CRL helpers
# ======================================================================

def _enc_crl_reason(code):
    """CRL entry extension reasonCode: ENUMERATED."""
    if not (0 <= code <= 10) or code in (7,):
        raise ValueError(f"invalid CRL reason code: {code}")
    return _enc_extension(OID_CRL_REASON, False,
                          _der_tlv(0x0A, bytes([code])))


def _parse_crl_reason(ext_node):
    """Из Extension { OID=reason, extnValue=OCTET(ENUMERATED) } → int."""
    # ext_node.children = [OID, OCTET] или [OID, BOOL, OCTET]
    val_octet = ext_node.children[-1]
    inner, _ = ASN1.parse(val_octet.value)
    return inner.as_int()


# ======================================================================
#  Directory String канонизация (RFC 4518)
# ======================================================================

def _map_insignificant_space(s):
    """RFC 4518 §2.6.1: убрать leading/trailing, схлопнуть внутренние
    пробелы до одного.

    Пример: '  Org  Name  ' → 'Org Name'
    """
    return " ".join(s.split())


def _case_fold(s):
    """RFC 4518 §2.3: case folding.

    Агрессивнее .lower() — учитывает Unicode-специфику (Straße → strasse,
    İ → i̇). Для ASCII-имён полностью эквивалентно .lower().
    """
    return s.casefold()


def _normalize_nfkc(s):
    """RFC 4518 §2.2: Unicode NFKC.

    NFKC — compatibility decomposition + canonical composition.
    Примеры:
        'ﬁ' (ligature fi) → 'fi'
        '²' (superscript 2) → '2'
        'Ａ' (fullwidth A) → 'A'
    """
    try:
        return unicodedata.normalize("NFKC", s)
    except Exception:
        return s


def _canonicalize_attribute_value(s):
    """Применить шаги RFC 4518 к одной строке."""
    s = _normalize_nfkc(s)
    s = _map_insignificant_space(s)
    s = _case_fold(s)
    return s


def canonicalize_name(name):
    """Канонический вид Name для сравнения (RFC 4518 + RFC 5280 §7.1).

    Возвращает tuple of tuple of (oid, canonical_value):
      - RDNSequence сохраняет порядок (SEQUENCE OF — упорядочен)
      - Внутри RDN — сортируем (SET OF — неупорядочен)

    Пример:
        Name { CN=Example.COM, O=My  Org }
        → ( (('2.5.4.10', 'my org'),), (('2.5.4.3', 'example.com'),) )
    """
    result = []
    for rdn in name.rdns:
        rdn_canon = []
        for oid, value in rdn:
            rdn_canon.append((oid, _canonicalize_attribute_value(value)))
        rdn_canon.sort()
        result.append(tuple(rdn_canon))
    return tuple(result)


def names_equal(a, b):
    """Каноничное сравнение двух Name.

    Принимает Name или Cert (берётся .subject).

    Пример:
        names_equal(cert1.subject, cert2.subject)
        names_equal(cert1.subject, cert2.issuer)   # кросс
    """
    if isinstance(a, Cert):
        a = a.subject
    if isinstance(b, Cert):
        b = b.subject
    if not isinstance(a, Name) or not isinstance(b, Name):
        raise TypeError("names_equal: ожидался Name или Cert")
    return canonicalize_name(a) == canonicalize_name(b)


# ======================================================================
#  validate_hostname (RFC 6125)
# ======================================================================

def _dnsname_match(pattern, hostname):
    pattern  = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == hostname
    if pattern.count("*") != 1 or not pattern.startswith("*."):
        return False
    suffix = pattern[2:]
    if not suffix or "." not in hostname:
        return False
    head, rest = hostname.split(".", 1)
    return bool(head) and rest == suffix


def validate_hostname(cert, hostname):
    if not hostname or not isinstance(hostname, str):
        _fail("validate_hostname: hostname пустой или не строка.",
              "передай строку: validate_hostname(cert, 'example.com')")
    if not isinstance(cert, Cert):
        _fail(f"validate_hostname: первый аргумент — {type(cert).__name__}, не Cert.",
              "validate_hostname(cert, 'example.com')")
    import ipaddress as _ip
    try:
        _ip.ip_address(hostname); is_ip = True
    except ValueError:
        is_ip = False
    san = cert.san
    if san:
        if is_ip:
            return any(kind == "iPAddress" and val == hostname for kind, val in san)
        return any(kind == "dNSName" and _dnsname_match(val, hostname) for kind, val in san)
    if is_ip:
        return False
    cn = cert.subject.get("CN")
    return bool(cn) and _dnsname_match(cn, hostname)


# ======================================================================
#  verify_chain (top-level helper)
# ======================================================================

def verify_chain(chain, trust_anchor=None, when=None):
    if not chain:
        return False
    when = when or datetime.datetime.now(datetime.timezone.utc)
    for c in chain:
        if not c.is_valid_at(when):
            return False
    for i in range(len(chain) - 1):
        if not chain[i].verify_signature(chain[i + 1]):
            return False
    if trust_anchor is not None:
        if not trust_anchor.is_valid_at(when):
            return False
        last = chain[-1]
        if last.der == trust_anchor.der:
            return True
        if not last.verify_signature(trust_anchor):
            return False
    return True


# ======================================================================
#  CertificateBuilder — fluent-сборка сертификата
# ======================================================================

class CertificateBuilder:
    """
    Сборка X.509-сертификата цепочкой вызовов.

    Все поля опциональны. `sign()` соберёт TBS и подпишет.

    Пример — Root CA (self-signed):
        ca = (CertificateBuilder(is_ca=True)
            .add_subject({"C": "RU", "O": "Org", "CN": "My Root CA"})
            .add_public_key(ca_key)
            .add_serial_random()
            .add_validity(days=3650)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .self_signed()
            .sign(ca_key))

    Пример — Leaf от CA:
        leaf = (CertificateBuilder()
            .add_subject({"CN": "example.com"})
            .add_issuer(ca)                     # берёт subject из CA
            .add_public_key(leaf_key)
            .add_serial_random()
            .add_validity(days=365)
            .add_san(dns=["example.com"])
            .sign(ca_key))                       # ca_key — приватный ключ CA

    Пример — из CSR:
        leaf = (CertificateBuilder.from_csr(csr)
            .add_issuer(ca)
            .add_validity(days=365)
            .sign(ca_key))
    """

    def __init__(self, is_ca: bool = False):
        self._is_ca = bool(is_ca)
        self._path_len = None
        self._subject = None
        self._issuer = None
        self._issuer_obj = None
        self._self_signed = False
        self._public_key_der = None
        self._serial = None
        self._not_before = None
        self._not_after = None
        self._days = None
        self._days_from = "not_before"     # "now" | "not_before"
        self._key_usage = None             # None → авто
        self._extensions = []
        self._san_entries = []
        self._from_csr = None
        self._hash_name = "sha256"
        self._ski_manual = None            # bytes(20) или None
        self._aki_manual = None            # bytes или None
        self._sig_scheme = "pkcs1v15"       # или "pss"

    # ---------- subject / issuer ----------

    def add_subject(self, name):
        """Принимает dict, Name, Cert или CSR."""
        if isinstance(name, dict):
            if not name:
                _fail("add_subject: пустой dict. Нужно хотя бы CN.",
                      ".add_subject({'CN': 'example.com', 'O': 'Org', 'C': 'RU'})")
            self._subject = Name.from_dict(name)
        elif isinstance(name, Name):
            if not name.rdns:
                _fail("add_subject: пустое Name.")
            self._subject = name
        elif isinstance(name, (Cert, CSR)):
            self._subject = name.subject
        else:
            _fail(
                f"add_subject: неподдерживаемый тип {type(name).__name__}.",
                ".add_subject({'CN': 'example.com'}) — dict, Name, Cert или CSR"
            )
        return self

    def add_issuer(self, name):
        """Принимает dict, Name, Cert или CSR. Cert/CA — берётся .subject."""
        if isinstance(name, Name):
            self._issuer = name
            self._issuer_obj = None
        elif isinstance(name, dict):
            if not name:
                _fail("add_issuer: пустой dict.",
                      ".add_issuer(ca) — передай объект CA, а не пустой dict")
            self._issuer = Name.from_dict(name)
            self._issuer_obj = None
        elif isinstance(name, Cert):
            if not _is_ca_cert(name):
                _fail(
                    f"add_issuer: '{name.subject}' не является CA (нет BasicConstraints CA:TRUE).",
                    "issuer должен быть CA-сертификатом. Корневой CA можно создать через "
                    "CertificateBuilder(is_ca=True)"
                )
            self._issuer = name.subject
            self._issuer_obj = name
        elif isinstance(name, CSR):
            _fail(
                "add_issuer: CSR нельзя использовать как issuer.",
                "issuer — это всегда сертификат CA: .add_issuer(ca_cert)"
            )
        else:
            _fail(
                f"add_issuer: неподдерживаемый тип {type(name).__name__}.",
                ".add_issuer(ca) — Cert, Name или dict"
            )
        return self

    def self_signed(self):
        """Помечает сертификат как self-signed (issuer = subject)."""
        self._self_signed = True
        return self

    # ---------- публичный ключ ----------

    def add_public_key(self, key_or_der):
        """RSAKeys, Ed25519Keys, ECDSAKeys, их SPKI-DER, или CSR."""
        if isinstance(key_or_der, (RSAKeys, Ed25519Keys, ECDSAKeys)):
            _check_rsa_key(key_or_der, "CertificateBuilder.add_public_key")
            self._public_key_der = key_or_der.to_public_der()
        elif isinstance(key_or_der, CSR):
            self._public_key_der = key_or_der.spki_der
        elif isinstance(key_or_der, (bytes, bytearray)):
            self._public_key_der = bytes(key_or_der)
        else:
            raise TypeError(f"add_public_key: неподдерживаемый тип {type(key_or_der).__name__}")
        return self

    # ---------- serial ----------

    def add_serial(self, n):
        if n is None:
            return self
        if n <= 0:
            raise ValueError("serial must be positive")
        self._serial = n
        return self

    def add_serial_random(self, bits=63):
        self._serial = secrets.randbits(bits) | 1
        return self

    # ---------- срок действия ----------

    def add_not_before(self, dt):
        self._not_before = dt
        return self

    def add_not_after(self, dt):
        self._not_after = dt
        return self

    def add_validity(self, days=None, *, start=None, end=None, from_now=False):
        """
        add_validity(days=365)      → от not_before (или now) + 365 дней
        add_validity(start=..., end=...)  → явные границы
        """
        if start is not None: self._not_before = start
        if end is not None:   self._not_after = end
        if days is not None:
            if days <= 0:
                raise ValueError("days must be positive")
            self._days = days
            self._days_from = "now" if from_now else "not_before"
        return self

    # ---------- расширения ----------

    def add_basic_constraints(self, path_len=None, critical=True):
        """BasicConstraints. Для CA — ставит CA:TRUE, для листа — CA:FALSE.

        path_len применим только к CA. Если передать path_len у листа —
        запишем в _path_len для диагностики в sign() (плюс warning)."""
        if path_len is not None and not self._is_ca:
            _warn(
                f"add_basic_constraints: path_len={path_len} у листа игнорируется",
                "path_len применим только к CA. Для листа: .add_basic_constraints()",
            )
            self._path_len = path_len   # чтобы sign() тоже напомнил
        else:
            self._path_len = path_len
        self._extensions.append(_enc_extension(
            OID_BASIC_CONSTR, critical,
            _enc_basic_constraints(self._is_ca, path_len if self._is_ca else None),
        ))
        return self

    def add_key_usage(self, *names, critical=True):
        """
        KeyUsage. Пример: .add_key_usage("digitalSignature", "keyEncipherment")
        Полный список имён — см. KU_BITS.
        """
        if len(names) == 1 and isinstance(names[0], (list, tuple, set)):
            names = tuple(names[0])
        self._extensions.append(_enc_extension(
            OID_KEY_USAGE, critical, _enc_key_usage(list(names)),
        ))
        return self

    def _san_ensure(self):
        if self._san_entries is None:
            self._san_entries = []
        return self._san_entries

    def add_san(self, dns=None, ips=None, emails=None, uris=None, critical=False):
        """Универсальный: .add_san(dns=["a.com"], ips=["10.0.0.1"]).
        Накопительный — можно вызывать несколько раз."""
        entries = self._san_ensure()
        for name in (dns or []):   entries.append(_san_entry_dns(name))
        for ip in (ips or []):     entries.append(_san_entry_ip(ip))
        for e in (emails or []):   entries.append(_san_entry_email(e))
        for u in (uris or []):     entries.append(_san_entry_uri(u))
        return self

    def add_san_dns(self, *names):
        entries = self._san_ensure()
        for n in names:
            _check_san_value("dNSName", n, "add_san_dns")
            entries.append(_san_entry_dns(n))
        return self

    def add_san_ip(self, *ips):
        entries = self._san_ensure()
        for ip in ips:
            entries.append(_san_entry_ip(ip))
        return self

    def add_san_email(self, *emails):
        entries = self._san_ensure()
        for e in emails:
            _check_san_value("rfc822Name", e, "add_san_email")
            entries.append(_san_entry_email(e))
        return self

    def add_san_uri(self, *uris):
        entries = self._san_ensure()
        for u in uris:
            _check_san_value("URI", u, "add_san_uri")
            entries.append(_san_entry_uri(u))
        return self

    def add_san_directory_name(self, name):
        if isinstance(name, Name):
            nd = name
        elif isinstance(name, dict):
            nd = Name.from_dict(name)
        elif isinstance(name, (Cert, CSR)):
            nd = name.subject
        else:
            raise TypeError(f"add_san_directory_name: тип {type(name).__name__}")
        inner = nd.raw
        hdr = 2
        if inner[1] & 0x80:
            hdr = 2 + (inner[1] & 0x7F)
        entries = self._san_ensure()
        entries.append((_SAN_TAG_DN, inner[hdr:]))
        return self

    def clear_san(self):
        self._san_entries = []
        return self

    def add_extension(self, oid, critical, value_der):
        """
        Произвольное расширение.
        oid — строка вида "2.5.29.17"
        value_der — DER-значение (то, что пойдёт внутрь OCTET STRING).
        """
        self._extensions.append(_enc_extension(oid, critical, value_der))
        return self

    def add_raw_extension(self, ext_der):
        """Готовый Extension-DER (например, полученный из CSR)."""
        self._extensions.append(bytes(ext_der))
        return self

    def add_ski(self, key_id=None):
        """SubjectKeyIdentifier вручную. None → авто (SHA-1 от публичного ключа).

        Принимает bytes или hex-строку: .add_ski("ab:cd:ef:...")
        """
        if key_id is None:
            self._ski_manual = None      # авто
        else:
            self._ski_manual = _parse_key_id(key_id, "add_ski")
        return self

    def add_aki(self, key_id=None):
        """AuthorityKeyIdentifier вручную.
        None → авто из issuer'а (если он передан как Cert).
        """
        if key_id is None:
            self._aki_manual = None
        else:
            self._aki_manual = _parse_key_id(key_id, "add_aki")
        return self

    def add_extended_key_usage(self, *purposes, critical=False):
        """Extended Key Usage. Пример:
            .add_extended_key_usage("serverAuth", "clientAuth")
        """
        self._extensions.append(_enc_eku(purposes))
        if critical and not self._extensions[-1][1] == 0x01:
            # пересобираем с critical=True
            self._extensions[-1] = _enc_extension(
                OID_EXT_KEY_USAGE, True, der_seq(
                    *[encode_oid(EKU_OIDS.get(p, p)) for p in purposes]
                )
            )
        return self

    # короткий алиас
    add_eku = add_extended_key_usage

    def add_name_constraints(self, *,
                             permitted_dns=None, excluded_dns=None,
                             permitted_ip=None, excluded_ip=None,
                             permitted_email=None, excluded_email=None,
                             permitted_uri=None, excluded_uri=None):
        """Name Constraints (RFC 5280 §4.2.1.10), critical.

        Пример:
            .add_name_constraints(permitted_dns=[".example.com"],
                                  excluded_dns=[".bad.example.com"])

        permitted_* — можно выпускать только эти поддеревья.
        excluded_*  — эти поддеревья запрещены.
        """
        if not self._is_ca:
            _warn("add_name_constraints: NC в не-CA сертификате",
                  "Name Constraints имеют смысл только на CA. "
                  "Используй CertificateBuilder(is_ca=True)")
        permitted, excluded = {}, {}
        if permitted_dns:   permitted["dns"]   = list(permitted_dns)
        if permitted_ip:    permitted["ip"]    = list(permitted_ip)
        if permitted_email: permitted["email"] = list(permitted_email)
        if permitted_uri:   permitted["uri"]   = list(permitted_uri)
        if excluded_dns:    excluded["dns"]    = list(excluded_dns)
        if excluded_ip:     excluded["ip"]     = list(excluded_ip)
        if excluded_email:  excluded["email"]  = list(excluded_email)
        if excluded_uri:    excluded["uri"]    = list(excluded_uri)
        if not permitted and not excluded:
            _fail("add_name_constraints: нужно хотя бы одно ограничение",
                  ".add_name_constraints(permitted_dns=['.example.com'])")
        self._extensions.append(_enc_name_constraints(permitted, excluded))
        return self

    def add_aia(self, *, ocsp=None, ca_issuers=None):
        """Authority Information Access (RFC 5280 §4.2.2.1), non-critical.

        Пример:
            .add_aia(ocsp=["http://ocsp.example.com"],
                     ca_issuers=["http://ca.example.com/ca.pem"])
        """
        if not ocsp and not ca_issuers:
            _fail("add_aia: нужен хотя бы один URL",
                  ".add_aia(ocsp=['http://...'])")
        self._extensions.append(_enc_aia(ocsp=ocsp, ca_issuers=ca_issuers))
        return self

    def add_crl_distribution_point(self, *urls):
        """CRL Distribution Points (2.5.29.31) — URL, где искать CRL.
        Пример: .add_crl_distribution_point('http://ca.example.com/crl.pem')
        """
        if not urls:
            raise ValueError("нужен хотя бы один URL")
        dps = []
        for url in urls:
            dp = der_seq(
                _der_tlv(0xA0,                    # [0] distributionPoint
                    _der_tlv(0xA0,                # [0] fullName (implicit GeneralNames)
                        _der_tlv(0x86, url.encode("ascii"))  # [6] URI — прямой потомок
                    )
                )
            )
            dps.append(dp)
        self._extensions.append(
            _enc_extension(OID_CRL_DP, False, der_seq(*dps))
        )
        return self

    # ---------- CA / end-entity шорткаты ----------

    def set_ca(self, path_len=None):
        """Пометить как CA (эквивалентно is_ca=True + add_basic_constraints)."""
        self._is_ca = True
        self._path_len = path_len
        return self

    def set_end_entity(self):
        """Пометить как лист."""
        self._is_ca = False
        self._path_len = None
        return self

    # ---------- CSR ----------

    @classmethod
    def from_csr(cls, csr, is_ca=False, copy_extensions=True):
        """
        Из CSR. SAN переносится в накопитель — можно добавлять свои
        через add_san_dns / add_san_ip, всё соберётся в одно расширение.
        Остальные extensions копируются как есть, кроме BC/KU.
        """
        b = cls(is_ca=is_ca)
        b._subject = csr.subject
        b._public_key_der = csr.spki_der
        b._from_csr = csr
        if copy_extensions:
            for ext in csr.extensions:
                if ext.oid in (OID_BASIC_CONSTR, OID_KEY_USAGE):
                    continue
                if ext.oid == OID_SAN:
                    for kind, val in _parse_san(ext.value):
                        if kind == "dNSName":
                            b._san_entries.append(_san_entry_dns(val))
                        elif kind == "iPAddress":
                            b._san_entries.append(_san_entry_ip(val))
                        elif kind == "rfc822Name":
                            b._san_entries.append(_san_entry_email(val))
                        elif kind == "URI":
                            b._san_entries.append(_san_entry_uri(val))
                    continue
                b._extensions.append(
                    _enc_extension(ext.oid, ext.critical, ext.value)
                )
        return b

    # ---------- hash ----------

    def set_hash(self, hash_name):
        if hash_name not in _RSA_HASH_TO_SIG_OID:
            raise ValueError(f"unsupported hash: {hash_name}")
        self._hash_name = hash_name
        return self

    def set_sig_scheme(self, scheme):
        """'pkcs1v15' (default) или 'pss' (RSASSA-PSS, RFC 8017)."""
        if scheme not in ("pkcs1v15", "pss"):
            _fail(f"set_sig_scheme: неизвестная схема {scheme!r}.",
                  "используй 'pkcs1v15' или 'pss'")
        self._sig_scheme = scheme
        return self

    def use_pss(self):
        """Короткий алиас для .set_sig_scheme('pss')."""
        return self.set_sig_scheme("pss")

    # ---------- финал ----------

    def sign(self, signing_key, hash_name=None):
        """Собрать TBS, подписать. Возвращает Cert (или CACert при is_ca=True)."""
        if hash_name is not None:
            if hash_name not in _RSA_HASH_TO_SIG_OID and not isinstance(signing_key, Ed25519Keys):
                _fail(f"sign: неизвестный hash {hash_name!r}.",
                      "sha256 / sha384 / sha512. Для Ed25519 параметр игнорируется.")
            self._hash_name = hash_name

        if self._subject is None:
            _fail("sign: subject не задан.",
                  ".add_subject({'CN': 'example.com', 'O': 'Org'})")
        if self._public_key_der is None:
            _fail("sign: публичный ключ не задан.",
                  ".add_public_key(leaf_key) — RSAKeys, Ed25519Keys, SPKI-DER или CSR")
        if self._serial is None:
            _fail("sign: serial не задан.",
                  ".add_serial_random()  или  .add_serial(12345)")
        if self._self_signed and self._issuer is not None:
            _fail("sign: конфликт — вызваны и .self_signed(), и .add_issuer(...).",
                  "self_signed означает issuer = subject. Убери один из вызовов.")
        if not self._self_signed and self._issuer is None:
            _fail("sign: issuer не задан.",
                  ".add_issuer(ca)  для обычного сертификата,  "
                  "или .self_signed()  для корневого CA")
        if self._not_after is None and self._days is None:
            _fail("sign: срок действия не задан.",
                  ".add_validity(days=365)  или  .add_not_before(...) + .add_not_after(...)")

        if not isinstance(signing_key, (RSAKeys, Ed25519Keys, ECDSAKeys)):
            _fail(f"sign: неподдерживаемый тип ключа {type(signing_key).__name__}.",
                  "используй RSAKeys, Ed25519Keys или ECDSAKeys")
        if not signing_key.is_private:
            _fail("sign: передан ПУБЛИЧНЫЙ ключ. Подписывать можно только приватным.",
                  "используй приватный ключ (.to_private_pem() при загрузке)")

        if self._issuer_obj is not None:
            if not _public_keys_equal(signing_key, self._issuer_obj.public_key):
                _fail(
                    f"sign: подписывающий ключ НЕ совпадает с issuer "
                    f"'{self._issuer_obj.subject}'.\n"
                    "  Ты пытаешься подписать ключом SUBJECT'а, а не ISSUER'а — "
                    "сертификат не сойдётся.\n"
                    "  Правило: подпись делает issuer, а не тот, чей ключ "
                    "в сертификате.",
                    "передай приватный ключ issuer'а: .sign(root_key)",
                )

        if self._self_signed:
            issuer_name = self._subject
        else:
            issuer_name = self._issuer

        serial = self._serial
        if serial <= 0:
            _fail(f"sign: serial должен быть > 0, получено {serial}.",
                  ".add_serial_random() для автоматического выбора")

        now = datetime.datetime.now(datetime.timezone.utc)
        nb = self._not_before if self._not_before is not None else now
        if self._not_after is not None:
            na = self._not_after
        elif self._days is not None:
            base = now if self._days_from == "now" else nb
            na = base + datetime.timedelta(days=self._days)
        else:
            na = now + datetime.timedelta(days=365)

        if na <= nb:
            _fail(
                f"sign: not_after ({na.isoformat()}) <= not_before ({nb.isoformat()}).",
                "проверь порядок дат в .add_not_before / .add_not_after"
            )

        # ---- warnings (не-фатальные) ----
        _check_rsa_key(signing_key, "CertificateBuilder.sign")
        if not isinstance(signing_key, (Ed25519Keys,)):
            _check_hash(self._hash_name, "CertificateBuilder.sign")
        if isinstance(signing_key, ECDSAKeys) and \
                self._hash_name not in ("sha256", "sha384", "sha512"):
            _fail(f"sign: ECDSA не поддерживает hash {self._hash_name}",
                  "используй sha256 / sha384 / sha512")

        if not self._is_ca:
            if self._days is not None and self._days > 825:
                _warn(
                    f"CertificateBuilder.sign: leaf со сроком {self._days} дней",
                    "CA/Browser Forum ограничивает 825 днями для TLS-листов",
                )
            if self._path_len is not None:
                _warn(
                    "CertificateBuilder.sign: path_len задан у не-CA сертификата",
                    "path_len применим только к CA. Используй .set_ca(path_len=N)",
                )
            has_san = bool(self._san_entries) or any(
                _ext_oid(e) == OID_SAN for e in self._extensions
            )
            if not has_san:
                _warn(
                    "CertificateBuilder.sign: лист без SAN",
                    "браузеры игнорируют CN с 2017; добавь .add_san_dns(...)",
                )

        if self._san_entries:
            seen = set()
            for tag, val in self._san_entries:
                k = (tag, bytes(val))
                if k in seen:
                    _warn(
                        f"CertificateBuilder.sign: дубликат SAN {tag:#x}",
                        "проверь вызовы .add_san_*",
                    )
                seen.add(k)

        # SAN: собрать одно расширение из накопителя
        if self._san_entries:
            self._extensions.append(_build_san_extension(self._san_entries))

        # дополняем расширения BC / KU, если их ещё нет
        have_bc = any(_ext_oid(e) == OID_BASIC_CONSTR for e in self._extensions)
        have_ku = any(_ext_oid(e) == OID_KEY_USAGE for e in self._extensions)
        if not have_bc:
            self.add_basic_constraints(self._path_len)
        if not have_ku:
            if self._is_ca:
                self.add_key_usage("keyCertSign", "cRLSign")
            else:
                self.add_key_usage("digitalSignature", "keyEncipherment")

        # ---- SKI (SubjectKeyIdentifier) ----
        have_ski = any(_ext_oid(e) == OID_SUBJ_KEY_ID for e in self._extensions)
        if not have_ski:
            if self._ski_manual is not None:
                self._extensions.append(_enc_ski_ext(self._ski_manual))
            elif self._is_ca:
                # у CA SKI обязателен
                ski = _compute_ski(self._public_key_der)
                if ski is not None:
                    self._extensions.append(_enc_ski_ext(ski))

        # ---- AKI (AuthorityKeyIdentifier) ----
        have_aki = any(_ext_oid(e) == OID_AUTH_KEY_ID for e in self._extensions)
        if not have_aki and not self._self_signed:
            aki = self._aki_manual
            if aki is None and self._issuer_obj is not None:
                aki = _extract_ski(self._issuer_obj)
            if aki is not None:
                self._extensions.append(_enc_aki_ext(aki))

        # ---- Name Constraints enforcement ----
        if self._issuer_obj is not None:
            nc = getattr(self._issuer_obj, "name_constraints", None)
            if nc is not None:
                names = _collect_names_from_builder(self)
                ok, reason = _check_name_constraints(names, nc)
                if not ok:
                    _fail(
                        f"Name Constraints violation: {reason}",
                        f"CA '{self._issuer_obj.subject}' запрещает это имя. "
                        f"Разрешено: permitted={nc.get('permitted')}, "
                        f"запрещено: excluded={nc.get('excluded')}"
                    )

        der = _build_cert_der(
            serial=serial,
            hash_name=self._hash_name,
            issuer_der=issuer_name.raw,
            subject_der=self._subject.raw,
            not_before=nb, not_after=na,
            spki_der=self._public_key_der,
            extensions=self._extensions,
            signing_key=signing_key,
            sig_scheme=self._sig_scheme,
        )
        if self._is_ca:
            ca = CACert(der)
            ca._signing_key = signing_key
            return ca
        return Cert(der)


def _ext_oid(ext_der):
    try:
        node, _ = ASN1.parse(ext_der)
        return node.children[0].as_oid()
    except Exception:
        return ""


# Backwards-compatible alias
CertBuilder = CertificateBuilder


# ======================================================================
#  CSRBuilder
# ======================================================================

class CSRBuilder:
    """
    Сборка PKCS#10 CSR.

        csr = (CSRBuilder()
            .add_subject({"CN": "example.com"})
            .add_public_key(leaf_key)
            .add_san(dns=["example.com"])
            .sign(leaf_key))
    """

    def __init__(self):
        self._subject = None
        self._public_key_der = None
        self._extensions = []
        self._san_entries = []
        self._hash_name = "sha256"
        self._sig_scheme = "pkcs1v15"

    def add_subject(self, name):
        if isinstance(name, dict):
            if not name:
                _fail("CSRBuilder.add_subject: пустой dict.",
                      ".add_subject({'CN': 'example.com'})")
            self._subject = Name.from_dict(name)
        elif isinstance(name, Name):
            if not name.rdns:
                _fail("CSRBuilder.add_subject: пустое Name.")
            self._subject = name
        elif isinstance(name, (Cert, CSR)):
            self._subject = name.subject
        else:
            _fail(
                f"CSRBuilder.add_subject: неподдерживаемый тип {type(name).__name__}.",
                ".add_subject({'CN': 'example.com'})"
            )
        return self

    def add_public_key(self, key_or_der):
        if isinstance(key_or_der, (RSAKeys, Ed25519Keys, ECDSAKeys)):
            self._public_key_der = key_or_der.to_public_der()
        elif isinstance(key_or_der, (bytes, bytearray)):
            self._public_key_der = bytes(key_or_der)
        else:
            raise TypeError(f"add_public_key: неподдерживаемый тип {type(key_or_der).__name__}")
        return self

    def _san_ensure(self):
        if self._san_entries is None:
            self._san_entries = []
        return self._san_entries

    def add_san(self, dns=None, ips=None, emails=None, uris=None, critical=False):
        entries = self._san_ensure()
        for name in (dns or []):   entries.append(_san_entry_dns(name))
        for ip in (ips or []):     entries.append(_san_entry_ip(ip))
        for e in (emails or []):   entries.append(_san_entry_email(e))
        for u in (uris or []):     entries.append(_san_entry_uri(u))
        return self

    def add_san_dns(self, *names):
        entries = self._san_ensure()
        for n in names:
            _check_san_value("dNSName", n, "add_san_dns")
            entries.append(_san_entry_dns(n))
        return self

    def add_san_ip(self, *ips):
        entries = self._san_ensure()
        for ip in ips: entries.append(_san_entry_ip(ip))
        return self

    def add_san_email(self, *emails):
        entries = self._san_ensure()
        for e in emails:
            _check_san_value("rfc822Name", e, "add_san_email")
            entries.append(_san_entry_email(e))
        return self

    def add_san_uri(self, *uris):
        entries = self._san_ensure()
        for u in uris:
            _check_san_value("URI", u, "add_san_uri")
            entries.append(_san_entry_uri(u))
        return self

    def clear_san(self):
        self._san_entries = []
        return self

    def add_extension(self, oid, critical, value_der):
        self._extensions.append(_enc_extension(oid, critical, value_der))
        return self

    def add_extended_key_usage(self, *purposes, critical=False):
        """Extended Key Usage для CSR."""
        body = der_seq(*[encode_oid(EKU_OIDS.get(p, p)) for p in purposes])
        self._extensions.append(
            _enc_extension(OID_EXT_KEY_USAGE, critical, body)
        )
        return self

    add_eku = add_extended_key_usage

    def set_hash(self, hash_name):
        if hash_name not in _RSA_HASH_TO_SIG_OID:
            raise ValueError(f"unsupported hash: {hash_name}")
        self._hash_name = hash_name
        return self

    def set_sig_scheme(self, scheme):
        if scheme not in ("pkcs1v15", "pss"):
            _fail(f"CSRBuilder.set_sig_scheme: неизвестная схема {scheme!r}.",
                  "используй 'pkcs1v15' или 'pss'")
        self._sig_scheme = scheme
        return self

    use_pss = lambda self: self.set_sig_scheme("pss")

    def sign(self, signing_key, hash_name=None):
        if hash_name is not None:
            if isinstance(signing_key, ECDSAKeys):
                if hash_name not in ("sha256", "sha384", "sha512"):
                    _fail(f"CSRBuilder.sign: ECDSA не поддерживает {hash_name!r}.",
                          "sha256 / sha384 / sha512")
            elif not isinstance(signing_key, Ed25519Keys) and \
                    hash_name not in _RSA_HASH_TO_SIG_OID:
                _fail(f"CSRBuilder.sign: неизвестный hash {hash_name!r}.",
                      "sha256 / sha384 / sha512")
            self._hash_name = hash_name
        if self._subject is None:
            _fail("CSRBuilder.sign: subject не задан.",
                  ".add_subject({'CN': 'example.com'})")
        if self._public_key_der is None:
            _fail("CSRBuilder.sign: публичный ключ не задан.",
                  ".add_public_key(leaf_key)")
        if not isinstance(signing_key, (RSAKeys, Ed25519Keys, ECDSAKeys)):
            _fail(f"CSRBuilder.sign: тип ключа {type(signing_key).__name__}.",
                  "нужен RSAKeys, Ed25519Keys или ECDSAKeys")
        if not signing_key.is_private:
            _fail("CSRBuilder.sign: передан публичный ключ.",
                  "CSR подписывается ПРИВАТНЫМ ключом владельца")

        if not _spki_pub_matches(self._public_key_der, signing_key):
            _fail(
                "CSRBuilder.sign: подписывающий ключ НЕ совпадает с публичным ключом в CSR.\n"
                "  CSR подтверждает, что ты владеешь приватным ключом от этого публичного.\n"
                "  Если ключи разные — сервер отклонит запрос.",
                ".add_public_key(leaf_key).sign(leaf_key)"
            )

        # ---- warnings ----
        _check_rsa_key(signing_key, "CSRBuilder.sign")
        if not isinstance(signing_key, Ed25519Keys):
            _check_hash(self._hash_name, "CSRBuilder.sign")

        if self._san_entries:
            seen = set()
            for tag, val in self._san_entries:
                k = (tag, bytes(val))
                if k in seen:
                    _warn(
                        f"CSRBuilder.sign: дубликат SAN {tag:#x}",
                        "проверь вызовы .add_san_*",
                    )
                seen.add(k)

        if self._san_entries:
            self._extensions.append(_build_san_extension(self._san_entries))

        if self._extensions:
            attr = der_seq(
                encode_oid(OID_EXT_REQUEST),
                der_set(der_seq(*self._extensions)),
            )
            attributes = _der_tlv(0xA0, attr)
        else:
            attributes = _der_tlv(0xA0, b"")

        cri = der_seq(der_int(0), self._subject.raw,
                      self._public_key_der, attributes)

        sig_alg, sig = _sign_and_build_alg(
            signing_key, cri, self._hash_name, self._sig_scheme)
        return CSR(der_seq(cri, sig_alg, der_bitstring(sig)))


# ======================================================================
#  __all__
# ======================================================================

__all__ = [
    "RSAKeys", "Ed25519Keys", "ECDSAKeys",
    "EC_CURVES", "OID_EC_PUBLIC_KEY", "OID_PRIME256V1",
    "OID_SECP384R1", "OID_SECP521R1", "OID_SECP256K1",
    "Cert", "CACert", "CSR", "CertBundle",
    "CertificateBuilder", "CertBuilder", "CSRBuilder",
    "CRL", "CRLBuilder", "CRL_REASONS", "load_pem_crls",
    "EKU_OIDS", "OID_RSA_PSS", "OID_NAME_CONSTR",
    "OCSPRequest", "OCSPResponse", "OCSPResponseBuilder",
    "OCSP_STATUS_NAMES", "OCSP_STATUS_CODES",
    "OID_OCSP", "OID_OCSP_BASIC", "OID_OCSP_NONCE",
    "OID_AIA", "OID_AD_CA_ISSUERS",
    "PKCS12", "PKCS12Builder",
    "OID_PKCS7_DATA", "OID_PKCS7_ENCRYPTED",
    "OID_PKCS12_SHROUDED", "OID_PKCS12_CERT_BAG",
    "OID_X509_CERTIFICATE", "OID_FRIENDLY_NAME", "OID_LOCAL_KEY_ID",
    "OID_PBES2", "OID_PBKDF2", "OID_HMAC_SHA256",
    "OID_AES_256_CBC", "OID_AES_256_GCM",
    "_aes256_gcm_encrypt", "_aes256_gcm_decrypt",
    "san_extension", "validate_hostname",
    "canonicalize_name", "names_equal",
    "load_pem_certs", "load_pem_csrs", "load_pem_bundle", "save_pem",
    "pem_encode", "pem_decode", "verify_chain",
    "X509Error", "X509ParseError", "X509VerifyError", "X509Warning",
    "__version__",
]