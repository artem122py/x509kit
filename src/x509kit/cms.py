# -*- coding: utf-8 -*-
"""
x509kit.cms — CMS (RFC 5652) SignedData.

Полный цикл подписи и проверки CMS SignedData на чистом stdlib.

Поддерживает:
  * ContentInfo (SEQUENCE { contentType OID, content [0] EXPLICIT ANY })
  * SignedData (1.2.840.113549.1.7.2)
  * Attached и detached content
  * SignerIdentifier: IssuerAndSerialNumber и [0] SubjectKeyIdentifier
  * Signed attributes: contentType, messageDigest, signingTime
  * X.509-сертификаты в certificates [0]
  * CRL в crls [1]
  * DER и PEM
  * cms_sign() — подпись content ключами RSA / Ed25519 / ECDSA
  * CMSSignedData.verify() — проверка подписи, messageDigest,
    contentType и цепочки (опционально, через trust_anchor)

НЕ поддерживает:
  * EnvelopedData / DigestedData / EncryptedData / AuthenticatedData
  * CAdES-BES/LT/LTA, timestamping, внешние TSA
  * Множественные подписанты при signing (парсятся корректно)

Использование:

    from x509kit.cms import cms_sign, CMSSignedData

    # Attached (content внутри .p7s)
    sd = cms_sign(b"hello, cms!", key=signing_key, cert=signing_cert,
                   chain=[ca])
    sd.save("message.p7s")
    assert sd.verify(trust_anchor=ca)

    # Detached (content отдельно)
    sd = cms_sign(b"hello, cms!", key=signing_key, cert=signing_cert,
                   detached=True)
    sd.save("message.p7s.sig")
    sd2 = CMSSignedData.load("message.p7s.sig")
    assert sd2.verify(detached_data=b"hello, cms!", trust_anchor=ca)

    # Inspection
    print(sd2.content_type_name)     # 'signedData'
    print(sd2.detached)              # True
    for s in sd2.signers:
        print(s.digest_algorithm.name, s.signature_algorithm.name)
        print(s.signing_time)
        print(s.message_digest.hex())

Проверено с OpenSSL CLI: openssl cms -sign / -verify.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from .x509 import (
    ASN1, Name, AlgorithmIdentifier, Cert, CRL,
    Ed25519Keys, RSAKeys, ECDSAKeys,
    X509Error, X509ParseError,
    _safe_parse,
    _sign_and_build_alg, _verify_signed_data, _public_keys_equal,
    _HASH_OIDS,
    der_seq, der_int, der_octet, der_null, der_set, der_bitstring,
    _der_tlv,
    encode_oid,
    pem_decode, pem_encode,
    _parse_time, _enc_time,
    TAG_SEQUENCE, TAG_SET, TAG_OCTET_STRING, TAG_INTEGER,
    OID_PKCS7_DATA,
)


# ======================================================================
#  OID-константы
# ======================================================================

OID_PKCS7_DATA             = "1.2.840.113549.1.7.1"
OID_PKCS7_SIGNED           = "1.2.840.113549.1.7.2"
OID_PKCS7_ENVELOPED        = "1.2.840.113549.1.7.3"
OID_PKCS7_SIGNED_ENVELOPED = "1.2.840.113549.1.7.4"
OID_PKCS7_DIGESTED         = "1.2.840.113549.1.7.5"
OID_PKCS7_ENCRYPTED        = "1.2.840.113549.1.7.6"
OID_PKCS7_AUTH_ENVELOPED   = "1.2.840.113549.1.7.23"

OID_PKCS9_CONTENT_TYPE     = "1.2.840.113549.1.9.3"
OID_PKCS9_MESSAGE_DIGEST   = "1.2.840.113549.1.9.4"
OID_PKCS9_SIGNING_TIME     = "1.2.840.113549.1.9.5"
OID_PKCS9_SIGNING_CERT_V2  = "1.2.840.113549.1.9.16.2.47"

CONTENT_TYPE_NAMES = {
    OID_PKCS7_DATA:             "data",
    OID_PKCS7_SIGNED:           "signedData",
    OID_PKCS7_ENVELOPED:        "envelopedData",
    OID_PKCS7_SIGNED_ENVELOPED: "signedAndEnvelopedData",
    OID_PKCS7_DIGESTED:         "digestedData",
    OID_PKCS7_ENCRYPTED:        "encryptedData",
    OID_PKCS7_AUTH_ENVELOPED:   "authenticatedData",
}

SIGNED_ATTR_NAMES = {
    OID_PKCS9_CONTENT_TYPE:    "contentType",
    OID_PKCS9_MESSAGE_DIGEST:  "messageDigest",
    OID_PKCS9_SIGNING_TIME:    "signingTime",
    OID_PKCS9_SIGNING_CERT_V2: "signingCertificateV2",
}


# ======================================================================
#  CMSSignerInfo
# ======================================================================

class CMSSignerInfo:
    """SignerInfo (RFC 5652 §5.3).

    Разобранная структура:
        version             — 1 (IssuerAndSerialNumber) или 3 (SKI)
        sid_kind            — 'issuer_and_serial' | 'subject_key_id'
        issuer              — Name (для IssuerAndSerialNumber)
        serial              — int  (для IssuerAndSerialNumber)
        subject_key_id      — bytes (для SubjectKeyIdentifier)
        digest_algorithm    — AlgorithmIdentifier
        signature_algorithm — AlgorithmIdentifier
        signature           — bytes (BIT STRING contents без unused-bits)
        signed_attrs        — dict {oid: [raw DER value, ...]} или None
        unsigned_attrs      — dict или None
        signed_attrs_raw    — DER SET OF Attribute (готов для verify)
    """

    __slots__ = ("version", "sid_kind", "issuer", "serial",
                 "subject_key_id", "digest_algorithm",
                 "signed_attrs", "signature_algorithm",
                 "signature", "unsigned_attrs",
                 "signed_attrs_raw", "raw")

    @_safe_parse
    def __init__(self, node):
        ch = list(node.children)
        if len(ch) < 5:
            raise X509ParseError(f"SignerInfo has {len(ch)} fields, want >= 5")
        self.raw = node.raw
        self.version = ch[0].as_int()

        sid = ch[1]
        if sid.tag == TAG_SEQUENCE:
            if len(sid.children) < 2:
                raise X509ParseError("IssuerAndSerialNumber malformed")
            self.sid_kind = "issuer_and_serial"
            self.issuer = Name(sid.children[0])
            self.serial = sid.children[1].as_uint()
            self.subject_key_id = None
        elif sid.tag == 0x80:
            self.sid_kind = "subject_key_id"
            self.subject_key_id = sid.value
            self.issuer = None
            self.serial = None
        else:
            raise X509ParseError(
                f"unknown SignerIdentifier tag: 0x{sid.tag:02x}")

        self.digest_algorithm = AlgorithmIdentifier(ch[2])

        i = 3
        self.signed_attrs = None
        self.signed_attrs_raw = None
        if i < len(ch) and ch[i].tag == 0xA0:
            self.signed_attrs = self._parse_attrs(ch[i])
            # RFC 5652 §5.4: signedAttrs подписывается с тегом SET (0x31),
            # но в SignerInfo хранится с [0] IMPLICIT (0xA0).
            self.signed_attrs_raw = _der_tlv(TAG_SET, ch[i].value)
            i += 1

        if i + 1 >= len(ch):
            raise X509ParseError("SignerInfo: missing signatureAlgorithm/signature")
        self.signature_algorithm = AlgorithmIdentifier(ch[i]); i += 1
        sig_node = ch[i]
        # RFC 5652 §5.3: signature SignatureValue ::= OCTET STRING
        if sig_node.tag != TAG_OCTET_STRING:
            raise X509ParseError(
                f"SignerInfo.signature must be OCTET STRING, "
                f"got tag 0x{sig_node.tag:02x}"
            )
        self.signature = sig_node.value
        i += 1

        self.unsigned_attrs = None
        if i < len(ch) and ch[i].tag == 0xA1:
            self.unsigned_attrs = self._parse_attrs(ch[i])

    @staticmethod
    def _parse_attrs(node):
        out = {}
        for attr in node.children:
            if len(attr.children) < 2:
                continue
            oid = attr.children[0].as_oid()
            values_node = attr.children[1]
            if values_node.tag != TAG_SET:
                continue
            out[oid] = [v.raw for v in values_node.children]
        return out

    def get_attr_raw(self, oid):
        if self.signed_attrs is None:
            return None
        vals = self.signed_attrs.get(oid)
        return vals[0] if vals else None

    def get_attr_node(self, oid):
        raw = self.get_attr_raw(oid)
        if raw is None:
            return None
        node, _ = ASN1.parse(raw)
        return node

    @property
    def content_type_attr(self):
        """OID contentType из signed_attrs или None."""
        node = self.get_attr_node(OID_PKCS9_CONTENT_TYPE)
        return node.as_oid() if node is not None else None

    @property
    def message_digest(self):
        """bytes messageDigest из signed_attrs или None."""
        node = self.get_attr_node(OID_PKCS9_MESSAGE_DIGEST)
        return node.value if node is not None else None

    @property
    def signing_time(self):
        """datetime signingTime или None."""
        node = self.get_attr_node(OID_PKCS9_SIGNING_TIME)
        if node is None:
            return None
        try:
            return _parse_time(node)
        except Exception:
            return None

    def __repr__(self):
        if self.sid_kind == "issuer_and_serial":
            sid = f"issuer={self.issuer!r} serial=0x{self.serial:x}"
        else:
            sid = f"ski={self.subject_key_id.hex()[:16]}\u2026"
        return (f"<CMSSignerInfo v{self.version} {sid} "
                f"digest={self.digest_algorithm.name}>")

    def __str__(self):
        lines = [f"SignerInfo v{self.version}"]
        if self.sid_kind == "issuer_and_serial":
            lines.append(f"  Issuer: {self.issuer}")
            lines.append(f"  Serial: 0x{self.serial:x}")
        else:
            lines.append(f"  SubjectKeyIdentifier: {self.subject_key_id.hex()}")
        lines.append(f"  Digest:  {self.digest_algorithm.name}")
        lines.append(f"  Sig:     {self.signature_algorithm.name}")
        st = self.signing_time
        if st is not None:
            lines.append(f"  Time:    {st.isoformat()}")
        if self.signed_attrs:
            lines.append(f"  Attrs:   {len(self.signed_attrs)}")
            for oid in sorted(self.signed_attrs):
                name = SIGNED_ATTR_NAMES.get(oid, oid)
                lines.append(f"    - {name}")
        return "\n".join(lines)


# ======================================================================
#  CMSSignedData
# ======================================================================

class CMSSignedData:
    """CMS SignedData (RFC 5652 §5.1).

    Загрузка:
        sd = CMSSignedData.load(der_or_pem_or_path)

    Подпись:
        sd = cms_sign(content, key, cert, chain=[...])
        sd = CMSSignedData.sign(content, key, cert, chain=[...])  # алиас

    Проверка:
        sd.verify()                                 — только подпись+digest
        sd.verify(trust_anchor=ca)                  — плюс цепочка
        sd.verify(detached_data=b"...")             — для detached
    """

    __slots__ = ("version", "digest_algorithms", "content_type",
                 "content", "detached", "certificates", "crls",
                 "signers", "content_info_der")

    @_safe_parse
    def __init__(self, content_info_node):
        self.content_info_der = content_info_node.raw

        if content_info_node.tag != TAG_SEQUENCE:
            raise X509ParseError("ContentInfo must be SEQUENCE")
        if not content_info_node.children:
            raise X509ParseError("ContentInfo has no contentType")

        ct = content_info_node.children[0].as_oid()
        if ct != OID_PKCS7_SIGNED:
            raise X509ParseError(
                f"ContentInfo contentType is {ct}, "
                f"expected signedData ({OID_PKCS7_SIGNED})"
            )
        if len(content_info_node.children) < 2:
            raise X509ParseError("ContentInfo has no content")
        wrapper = content_info_node.children[1]
        if wrapper.tag != 0xA0 or not wrapper.children:
            raise X509ParseError("ContentInfo content [0] is not EXPLICIT")
        sd_node = wrapper.children[0]
        if sd_node.tag != TAG_SEQUENCE:
            raise X509ParseError("SignedData must be SEQUENCE")

        ch = list(sd_node.children)
        if len(ch) < 4:
            raise X509ParseError(f"SignedData has {len(ch)} fields, want >= 4")

        self.version = ch[0].as_int()

        if ch[1].tag != TAG_SET:
            raise X509ParseError("digestAlgorithms must be SET")
        self.digest_algorithms = [AlgorithmIdentifier(n) for n in ch[1].children]

        eci = ch[2]
        if eci.tag != TAG_SEQUENCE or not eci.children:
            raise X509ParseError("encapContentInfo malformed")
        self.content_type = eci.children[0].as_oid()
        self.content = None
        self.detached = True
        if len(eci.children) > 1 and eci.children[1].tag == 0xA0:
            inner = eci.children[1].children[0]
            if inner.tag == TAG_OCTET_STRING:
                self.content = inner.value
                self.detached = False

        self.certificates = []
        self.crls = []
        i = 3
        if i < len(ch) and ch[i].tag == 0xA0:
            for cert_node in ch[i].children:
                if cert_node.tag == TAG_SEQUENCE:
                    try:
                        self.certificates.append(Cert(cert_node.raw))
                    except X509Error:
                        pass
            i += 1

        if i < len(ch) and ch[i].tag == 0xA1:
            for crl_node in ch[i].children:
                if crl_node.tag == TAG_SEQUENCE:
                    try:
                        self.crls.append(CRL(crl_node.raw))
                    except X509Error:
                        pass
            i += 1

        if i >= len(ch) or ch[i].tag != TAG_SET:
            raise X509ParseError("signerInfos must be SET")
        self.signers = [CMSSignerInfo(n) for n in ch[i].children]
        i += 1

    # ---- загрузка ----

    @classmethod
    def load(cls, data):
        """Загрузить CMSSignedData из DER/PEM/пути."""
        import os as _os
        if isinstance(data, str):
            if "\n" not in data and _os.path.exists(data):
                with open(data, "rb") as f:
                    data = f.read()
            else:
                data = data.encode("ascii")
        if b"-----BEGIN" in data:
            blocks = pem_decode(data)
            if not blocks:
                raise X509ParseError("no PEM blocks in CMS input")
            for label, der in blocks:
                up = label.upper()
                if "CMS" in up or "PKCS7" in up or "PKCS #7" in up:
                    data = der
                    break
            else:
                data = blocks[0][1]

        root, _ = ASN1.parse(data)
        return cls(root)

    from_der = load
    from_pem = load

    @classmethod
    def sign(cls, content, key, cert, chain=None, **kwargs):
        """Алиас для cms_sign(). См. документацию cms_sign()."""
        return cms_sign(content, key, cert, chain=chain, **kwargs)

    # ---- round-trip ----

    def to_der(self):
        return self.content_info_der

    def to_pem(self, label="CMS"):
        return pem_encode(label, self.content_info_der)

    def save(self, path):
        import os as _os
        path = _os.path.expanduser(path)
        with open(path, "wb") as f:
            f.write(self.content_info_der)
        return _os.path.abspath(path)

    # ---- удобные свойства ----

    @property
    def content_type_name(self):
        return CONTENT_TYPE_NAMES.get(self.content_type, self.content_type)

    @property
    def signer_count(self):
        return len(self.signers)

    def get_cert_for_signer(self, signer):
        """Найти сертификат подписанта в self.certificates по SID."""
        for c in self.certificates:
            if signer.sid_kind == "issuer_and_serial":
                if c.serial == signer.serial and \
                        c.issuer.raw == signer.issuer.raw:
                    return c
            else:
                ski = c.ext_get("2.5.29.14")
                if ski is None:
                    continue
                try:
                    node, _ = ASN1.parse(ski.value)
                    if node.tag == TAG_OCTET_STRING and \
                            node.value == signer.subject_key_id:
                        return c
                except Exception:
                    continue
        return None

    # ---- verify ----

    def verify(self, *, trust_anchor=None, detached_data=None,
               allow_weak_hash=False):
        """Проверить CMS.

        Для каждого SignerInfo:
          1. Найти сертификат в self.certificates по SID.
          2. Если есть signed_attrs — проверить подпись над DER SET
             (RFC 5652 §5.4), затем сравнить messageDigest с хэшем content.
          3. Если signed_attrs нет — подпись над content напрямую.
          4. Если задан trust_anchor — проверить цепочку до него
             через сертификаты в контейнере.

        Возвращает True, если ВСЕ signers валидны. Не бросает исключений
        на «подпись не сходится» — возвращает False.
        """
        if not self.signers:
            return False

        if self.detached:
            if detached_data is None:
                return False
            content = detached_data
        else:
            content = self.content

        if content is None:
            return False

        for signer in self.signers:
            if not self._verify_one_signer(signer, content,
                                           trust_anchor, allow_weak_hash):
                return False
        return True

    def _verify_one_signer(self, signer, content, trust_anchor,
                            allow_weak_hash):
        cert = self.get_cert_for_signer(signer)
        if cert is None:
            return False
        if cert.weak_hash and not allow_weak_hash:
            return False

        if signer.signed_attrs_raw is not None:
            # подпись над DER SET (уже 0x31, см. CMSSignerInfo)
            if not _verify_signed_data(
                    signer.signed_attrs_raw, signer.signature,
                    signer.signature_algorithm, cert.public_key):
                return False

            md = signer.message_digest
            if md is None:
                return False
            digest_name = signer.digest_algorithm.digest_name
            if digest_name is None:
                return False
            computed = hashlib.new(digest_name, content).digest()
            if not hmac.compare_digest(md, computed):
                return False

            ct = signer.content_type_attr
            if ct is not None and ct != self.content_type:
                return False
        else:
            # нет signed_attrs — подпись над content напрямую
            if not _verify_signed_data(
                    content, signer.signature,
                    signer.signature_algorithm, cert.public_key):
                return False

        if trust_anchor is not None:
            if not self._check_cert_trust(cert, trust_anchor):
                return False
        return True

    def _check_cert_trust(self, leaf, trust_anchor):
        """Проверить, что leaf цепочкой сходится к trust_anchor
        через сертификаты в self.certificates."""
        if leaf.der == trust_anchor.der:
            return True
        if leaf.verify_signature(trust_anchor):
            return True

        visited = {leaf.der}
        current = leaf
        for _ in range(8):
            found = None
            for c in self.certificates:
                if c.der in visited:
                    continue
                if current.verify_signature(c):
                    found = c
                    break
            if found is None:
                return False
            if found.der == trust_anchor.der:
                return True
            if found.verify_signature(trust_anchor):
                return True
            visited.add(found.der)
            current = found
        return False

    def __repr__(self):
        kind = "detached" if self.detached else f"attached/{len(self.content or b'')}B"
        return (f"<CMSSignedData {self.content_type_name} {kind} "
                f"signers={len(self.signers)} certs={len(self.certificates)}>")

    def __str__(self):
        lines = [
            "CMS SignedData",
            f"  Version:      {self.version}",
            f"  ContentType:  {self.content_type_name} ({self.content_type})",
        ]
        if self.detached:
            lines.append(f"  Content:      <detached>")
        else:
            lines.append(f"  Content:      {len(self.content)} bytes")
        lines.append(f"  Digest algs:  {[a.name for a in self.digest_algorithms]}")
        lines.append(f"  Certificates: {len(self.certificates)}")
        if self.crls:
            lines.append(f"  CRLs:         {len(self.crls)}")
        lines.append(f"  Signers:      {len(self.signers)}")
        for i, s in enumerate(self.signers):
            lines.append("")
            lines.append(f"  --- Signer #{i + 1} ---")
            for ln in str(s).splitlines():
                lines.append("  " + ln)
            cert = self.get_cert_for_signer(s)
            if cert is not None:
                lines.append(f"  Cert: {cert.subject}")
        return "\n".join(lines)


# ======================================================================
#  Signing (module-level)
# ======================================================================

def _enc_attribute(oid, value_der):
    """Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }."""
    return der_seq(encode_oid(oid), der_set(value_der))


def _der_set_sorted(*items):
    """SET OF с DER-сортировкой (X.690 §11.6).

    Сортировка: сравнение октетных строк с дополнением нулями справа
    до одинаковой длины (короче → padded → сравнение).
    """
    items = list(items)
    if not items:
        return _der_tlv(TAG_SET, b"")
    max_len = max(len(it) for it in items)
    padded = [(it + b"\x00" * (max_len - len(it)), it) for it in items]
    padded.sort(key=lambda x: x[0])
    return _der_tlv(TAG_SET, b"".join(it for _, it in padded))


def cms_sign(content, key, cert, chain=None, *,
             detached=False, digest="sha256",
             sig_scheme="pkcs1v15",
             signing_time=None, add_signing_time=True):
    """Подписать content, вернуть CMSSignedData.

    :param content: bytes — подписываемые данные.
    :param key: приватный ключ RSA/Ed25519/ECDSA.
    :param cert: Cert — сертификат подписанта.
    :param chain: list[Cert] — промежуточные сертификаты (опционально).
    :param detached: если True, content не включается в SignedData
        (вызывающий хранит его отдельно).
    :param digest: 'sha256' | 'sha384' | 'sha512'. Для Ed25519
        игнорируется — используется sha512 (RFC 8419).
    :param sig_scheme: 'pkcs1v15' (default) | 'pss'. Только для RSA.
    :param signing_time: datetime — если None, берётся now(UTC).
    :param add_signing_time: включать ли атрибут signingTime.
    :returns: CMSSignedData
    """
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("content must be bytes")
    content = bytes(content)
    if not isinstance(cert, Cert):
        raise TypeError("cert must be a Cert/CACert")
    if not hasattr(key, "is_private") or not key.is_private:
        raise X509Error("signing key must be private")
    if not _public_keys_equal(key, cert.public_key):
        raise X509Error("signing key does not match cert")

    # RFC 8419: Ed25519 использует SHA-512 внутри
    if isinstance(key, Ed25519Keys):
        digest_name = "sha512"
    else:
        if digest not in _HASH_OIDS:
            raise X509Error(f"unsupported digest: {digest!r}")
        digest_name = digest

    message_digest = hashlib.new(digest_name, content).digest()

    attrs = [
        _enc_attribute(OID_PKCS9_CONTENT_TYPE,
                       encode_oid(OID_PKCS7_DATA)),
        _enc_attribute(OID_PKCS9_MESSAGE_DIGEST,
                       der_octet(message_digest)),
    ]
    if add_signing_time:
        st = signing_time or datetime.now(timezone.utc)
        attrs.append(_enc_attribute(OID_PKCS9_SIGNING_TIME, _enc_time(st)))

    # DER-сортировка SET OF Attribute (X.690 §11.6) — OpenSSL придирчив.
    # Для подписи — SET (0x31); для хранения в SignerInfo — [0] (0xA0):
    # меняется только первый байт тега.
    attrs_for_signing = _der_set_sorted(*attrs)
    stored_attrs = b"\xA0" + attrs_for_signing[1:]

    sig_alg_der, sig_bytes = _sign_and_build_alg(
        key, attrs_for_signing, digest_name, sig_scheme)

    digest_alg_der = der_seq(encode_oid(_HASH_OIDS[digest_name]), der_null())

    sid = der_seq(cert.issuer.raw, der_int(cert.serial))

    signer_info = der_seq(
        der_int(1),
        sid,
        digest_alg_der,
        stored_attrs,
        sig_alg_der,
        der_octet(sig_bytes),   # RFC 5652 §5.3: signature OCTET STRING
    )

    if detached:
        eci = der_seq(encode_oid(OID_PKCS7_DATA))
    else:
        eci = der_seq(
            encode_oid(OID_PKCS7_DATA),
            _der_tlv(0xA0, der_octet(content)),
        )

    cert_der_list = [cert.der]
    if chain:
        for c in chain:
            if isinstance(c, Cert):
                cert_der_list.append(c.der)
    certs_field = _der_tlv(0xA0, b"".join(cert_der_list))

    # version = 1: SignerInfo v1 (IssuerAndSerialNumber), обычные
    # X.509 (не attribute certificates) — RFC 5652 §5.1
    signed_data = der_seq(
        der_int(1),
        der_set(digest_alg_der),
        eci,
        certs_field,
        der_set(signer_info),
    )

    content_info = der_seq(
        encode_oid(OID_PKCS7_SIGNED),
        _der_tlv(0xA0, signed_data),
    )

    node, _ = ASN1.parse(content_info)
    return CMSSignedData(node)


# ======================================================================
#  Convenience
# ======================================================================

def cms_load(data):
    """Загрузить CMSSignedData из DER/PEM/пути. Алиас на CMSSignedData.load."""
    return CMSSignedData.load(data)


__all__ = [
    "CMSSignedData", "CMSSignerInfo", "cms_sign", "cms_load",
    "OID_PKCS7_DATA",
    "OID_PKCS7_SIGNED", "OID_PKCS7_ENVELOPED",
    "OID_PKCS7_SIGNED_ENVELOPED",
    "OID_PKCS7_DIGESTED", "OID_PKCS7_ENCRYPTED", "OID_PKCS7_AUTH_ENVELOPED",
    "OID_PKCS9_CONTENT_TYPE", "OID_PKCS9_MESSAGE_DIGEST",
    "OID_PKCS9_SIGNING_TIME", "OID_PKCS9_SIGNING_CERT_V2",
    "CONTENT_TYPE_NAMES", "SIGNED_ATTR_NAMES",
]
