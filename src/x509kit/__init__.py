"""
x509kit — X.509 / PKCS#10 / PKCS#12 / RSA / Ed25519 / ECDSA / CRL / OCSP / NC.
Только стандартная библиотека Python.

Поддерживает:
  * ASN.1 DER (strict)
  * RSA PKCS#1 v1.5 + RSASSA-PSS (blinding + CRT)
  * Ed25519 (RFC 8032), ECDSA (P-256/P-384/P-521/secp256k1, RFC 6979)
  * X.509 v3: SAN, BasicConstraints (BC), KeyUsage (KU),
    Extended Key Usage (EKU), Name Constraints (NC + intersection),
    AKI/SKI, CRL Distribution Points (CRL DP), AIA (OCSP + CA Issuers)
  * PKCS#10 CSR, CRL (RFC 5280), OCSP (RFC 6960)
  * PKCS#8 EncryptedPrivateKeyInfo (PBES2 + PBKDF2 + AES-256-CBC/GCM)
  * PKCS#12 (.p12/.pfx) — export/import/verify, совместим с OpenSSL
  * RFC 4518 канонизация DN

═══════════════════════════════════════════════════════════════════════
  Ключи
═══════════════════════════════════════════════════════════════════════

    RSAKeys.generate(2048)
    RSAKeys.from_pem(pem, private=True, password="...")
    k.to_private_pem(password="...") / k.to_public_pem()
    k.sign_pkcs1v15(msg, "sha256") / k.verify_pkcs1v15(msg, sig, "sha256")
    k.sign_pss(msg, "sha256")      / k.verify_pss(msg, sig, "sha256")
    k.size_bits / k.is_private / k.weak

    Ed25519Keys.generate() / Ed25519Keys(seed=bytes(32))
    Ed25519Keys.from_pem(pem, private=True, password="...")
    k.sign(msg) / k.verify(msg, sig) / k.pub

    ECDSAKeys.generate("P-256"|"P-384"|"P-521"|"secp256k1")
    ECDSAKeys.from_pem(pem, private=True, password="...")
    k.sign(msg, "sha256") / k.verify(msg, sig, "sha256")
    k.pub / k.curve_oid / k.point

═══════════════════════════════════════════════════════════════════════
  Сертификаты
═══════════════════════════════════════════════════════════════════════

    Cert(pem_or_der)
    c.subject / c.issuer / c.serial / c.version
    c.not_before / c.not_after / c.is_valid_at(when=None)
    c.public_key / c.spki_der / c.key_algorithm_oid
    c.extensions / c.ext_get(oid) / c.san
    c.dns_names / c.ip_addresses / c.emails / c.uris
        ^ SAN-списки по типу (удобный доступ вместо фильтрации c.san)
    c.crl_distribution_points           — URL'ы CRL Distribution Points
    c.ski / c.aki                       — AKI/SKI идентификаторы
    c.eku / c.has_eku("serverAuth")     — Extended Key Usage
    c.name_constraints                  — Name Constraints (dict|None)
    c.aia / c.aia_ocsp / c.aia_issuers  — AIA (OCSP/CA Issuers URLs)
    c.name_matches(other)               — RFC 4518 канонично
    c.subject_matches_issuer(ca)
    c.weak_hash / c.has_unknown_critical
    c.verify_signature(issuer) / c.is_self_signed()
    c.to_pem() / c.to_der()

    CACert.create_self_signed(subject, keys, days=3650, path_len=None)
    CACert.from_cert(cert, signing_key=None)
    CACert.from_pem(pem, private_key_pem=None)

    ca.issue_csr(csr, days=365, is_ca=False, path_len=None)
    ca.issue_with_key(csr, signing_key, days=365, is_ca=False)
        ^ если CA без приватного ключа или ключ передаётся явно
    ca.verify_cert(cert, crl=None, ocsp_response=None)
    ca.verify_chain([leaf, inter], crl=None)

    ca.revoke(cert_or_serial, reason="keyCompromise")
    ca.to_crl(days=7)
    ca.respond_ocsp(cert_or_request, status="good", reason=None, days=7)
    ca.verify_ocsp_response(response, request=None)

    ca.path_len / ca.key_usage / ca.is_ca / ca.name_constraints

═══════════════════════════════════════════════════════════════════════
  CSR (PKCS#10)
═══════════════════════════════════════════════════════════════════════

    CSR.create(subject, keys, extensions=[...])
    CSR(pem_or_der)
    csr.subject / csr.public_key / csr.spki_der
    csr.san / csr.eku / csr.has_eku("serverAuth") / csr.extensions
    csr.dns_names / csr.ip_addresses / csr.emails / csr.uris
        ^ SAN-списки из extensionRequest
    csr.verify_signature() / csr.to_pem()

═══════════════════════════════════════════════════════════════════════
  CRL (RFC 5280 §5)
═══════════════════════════════════════════════════════════════════════

    CRL(pem_or_der) / load_pem_crls(pem)
    crl.issuer / crl.this_update / crl.next_update / crl.revoked
    crl.is_revoked(cert_or_serial) / crl.revoke_reason(cert_or_serial)
    crl.is_valid_at() / crl.verify_signature(ca) / crl.to_pem()

    CRL_REASONS — keyCompromise, cACompromise, ...

    CRLBuilder()
        .set_issuer(ca).set_validity(days=7)
        .add_revoked(serial_or_cert, reason="keyCompromise")
        .sign(ca_key)

═══════════════════════════════════════════════════════════════════════
  OCSP (RFC 6960)
═══════════════════════════════════════════════════════════════════════

    OCSPRequest.create(issuer, cert_or_serial)
    OCSPRequest.create(issuer=ca, cert=leaf)
    OCSPRequest.create(issuer=ca, serial=12345)
    req.serial / req.nonce / req.cert_id / req.to_der() / req.to_pem()

    OCSPResponse(pem_or_der)
    resp.status / resp.is_successful / resp.responses
    resp.get_status(cert_or_serial)     — 'good'|'revoked'|'unknown'|None
    resp.get_revoke_info(cert)
    resp.verify_signature(issuer) / resp.is_fresh() / resp.nonce

    OCSPResponseBuilder()
        .set_responder(ca).set_validity(days=7).set_nonce(bytes)
        .add_status(cert_or_serial, status="good"|"revoked"|"unknown",
                    reason="keyCompromise")
        .sign(ca_key)

    OCSP_STATUS_NAMES / OCSP_STATUS_CODES
    OID_OCSP / OID_OCSP_BASIC / OID_OCSP_NONCE

═══════════════════════════════════════════════════════════════════════
  CertificateBuilder
═══════════════════════════════════════════════════════════════════════

    CertificateBuilder(is_ca=False)
        .add_subject({"CN": "example.com", "O": "Org", "C": "XX"})
        .add_issuer(ca) / .self_signed()
        .add_public_key(key)             — RSAKeys/Ed25519Keys/ECDSAKeys/SPKI/CSR
        .add_serial_random() / .add_serial(n)
        .add_validity(days=365) / .add_not_before(dt) / .add_not_after(dt)
        .add_san(dns=[], ips=[], emails=[], uris=[])
        .add_san_dns("a.com", "b.com") / .add_san_ip("1.2.3.4")
        .add_san_email(...) / .add_san_uri(...) / .add_san_directory_name(...)
        .add_basic_constraints(path_len=None)
        .add_key_usage("digitalSignature", "keyEncipherment")
        .add_extended_key_usage("serverAuth", "clientAuth")  (.add_eku)
        .add_name_constraints(permitted_dns=[...], excluded_dns=[...],
                              permitted_ip=[...], excluded_ip=[...])
        .add_crl_distribution_point("http://ca.example.com/crl.pem")
        .add_aia(ocsp=["http://..."], ca_issuers=["http://..."])
        .add_ski(hex) / .add_aki(hex)
        .add_extension(oid, critical, value_der) / .add_raw_extension(der)
        .set_ca(path_len=0) / .set_end_entity()
        .set_hash("sha256") / .set_sig_scheme("pss") / .use_pss()
        .sign(ca_key)                    — Cert или CACert

    CertificateBuilder.from_csr(csr, is_ca=False, copy_extensions=True)

═══════════════════════════════════════════════════════════════════════
  CSRBuilder
═══════════════════════════════════════════════════════════════════════

    CSRBuilder()
        .add_subject({...}) / .add_public_key(key)
        .add_san(...) / .add_san_dns(...) / .add_san_ip(...)
        .add_extended_key_usage("serverAuth")
        .set_hash("sha256") / .set_sig_scheme("pss") / .use_pss()
        .sign(signing_key)

═══════════════════════════════════════════════════════════════════════
  Хелперы и OID
═══════════════════════════════════════════════════════════════════════

    ASN1 — низкоуровневый DER-парсер (parse, as_int, as_oid, ...)
        ^ защита: _MAX_DER_SIZE = 50 MB, _MAX_DEPTH = 32
    canonicalize_name(name) / names_equal(a, b)   — RFC 4518
    san_extension(dns_names=[], ips=[], emails=[], uris=[])
    validate_hostname(cert, "example.com")        — RFC 6125
    load_pem_certs / load_pem_csrs / load_pem_bundle / load_pem_crls
        ^ защита: _MAX_PEM_SIZE = 10 MB
    save_pem(path, cert1, cert2, ...)
    pem_encode / pem_decode / verify_chain

    CertBundle([c1, c2, ...])
        .from_pem(data) / .from_file(path) / .to_pem() / .save(path)

    EKU_OIDS — {serverAuth, clientAuth, codeSigning, emailProtection,
                timeStamping, OCSPSigning, anyExtendedKeyUsage, ...}
    EC_CURVES — {OID: {p, a, b, Gx, Gy, n, size}}

    OID_RSA_PSS       = "1.2.840.113549.1.1.10"
    OID_NAME_CONSTR   = "2.5.29.30"
    OID_AIA           = "1.3.6.1.5.5.7.1.1"
    OID_AD_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"
    OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
    OID_PRIME256V1 / OID_SECP384R1 / OID_SECP521R1 / OID_SECP256K1
    OID_PBES2 / OID_PBKDF2 / OID_HMAC_SHA256
    OID_AES_256_CBC = "2.16.840.1.101.3.4.1.42"
    OID_AES_256_GCM = "2.16.840.1.101.3.4.1.46"

═══════════════════════════════════════════════════════════════════════
  PKCS#12 (.p12 / .pfx)
═══════════════════════════════════════════════════════════════════════

    PKCS12 — контейнер: приватный ключ + сертификат + цепочка (RFC 7292)

    PKCS12.build(key, cert, chain=[inter], password="...", name="client")
    pk.to_der() / pk.save("client.p12")

    PKCS12Builder()                   — fluent-обёртка
        .set_key(k) / .add_key(k)
        .set_cert(cert) / .add_cert(cert)
        .add_chain(inter, root)
        .set_password("...")
        .set_name("alice")
        .set_iterations(2048)
        .set_mac_iterations(2048)
        .set_cipher("aes-256-cbc")
        .build()                     — PKCS12
        .save("alice.p12")           — сразу в файл

    PKCS12.load(der, password="...")
    PKCS12.from_file(path, password="...")
    pk.key / pk.cert / pk.chain
    pk.verify_mac(password=None)
    pk.verify_chain(trust_anchor=root, when=None)

    # Совместимо с OpenSSL:
    #   openssl pkcs12 -in file.p12 -info -noout
    #   openssl pkcs12 -in file.p12 -nodes -out extracted.pem

═══════════════════════════════════════════════════════════════════════
  Исключения и предупреждения
═══════════════════════════════════════════════════════════════════════

    X509Error          — базовое исключение
    X509ParseError     — ошибка парсинга DER/PEM
    X509VerifyError    — ошибка проверки подписи/цепочки
    X509Warning        — не-фатальное предупреждение (UserWarning)

    Все ошибки содержат подсказку «Как исправить: ...».

    Сделать warnings ошибками (для CI):
        import warnings; warnings.simplefilter("error", X509Warning)

═══════════════════════════════════════════════════════════════════════
  Пример
═══════════════════════════════════════════════════════════════════════

    from x509kit import CertificateBuilder, Ed25519Keys, RSAKeys

    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "XX", "O": "MyOrg", "CN": "MyOrg Root CA"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))

    leaf_key = RSAKeys.generate(2048)
    leaf = (CertificateBuilder()
        .add_subject({"C": "XX", "O": "MyOrg", "CN": "example.com"})
        .add_issuer(ca).add_public_key(leaf_key)
        .add_serial_random().add_validity(days=365)
        .add_san_dns("example.com", "www.example.com")
        .add_extended_key_usage("serverAuth")
        .use_pss()
        .sign(ca_key))

    assert ca.verify_chain([leaf])
"""

from .x509 import (
    # Ключи
    RSAKeys, Ed25519Keys, ECDSAKeys, EC_CURVES,
    OID_EC_PUBLIC_KEY, OID_PRIME256V1,
    OID_SECP384R1, OID_SECP521R1, OID_SECP256K1,
    # Структуры
    ASN1,
    Name, Cert, CACert, CSR, CertBundle,
    # PKCS#12
    PKCS12, PKCS12Builder,
    # CRL
    CRL, CRLBuilder, CRL_REASONS, CRL_REASONS_REV, load_pem_crls,
    # OCSP
    OCSPRequest, OCSPResponse, OCSPResponseBuilder,
    OCSP_STATUS_NAMES, OCSP_STATUS_CODES,
    OID_OCSP, OID_OCSP_BASIC, OID_OCSP_NONCE,
    # Builders
    CertificateBuilder, CertBuilder, CSRBuilder,
    # Хелперы
    san_extension, validate_hostname,
    canonicalize_name, names_equal,
    load_pem_certs, load_pem_csrs, load_pem_bundle, save_pem,
    pem_encode, pem_decode, verify_chain,
    EKU_OIDS,
    # OID-константы
    OID_RSA_PSS, OID_NAME_CONSTR,
    OID_AIA, OID_AD_CA_ISSUERS,
    OID_PBES2, OID_PBKDF2, OID_HMAC_SHA256,
    OID_AES_256_CBC, OID_AES_256_GCM,
    # Исключения
    X509Error, X509ParseError, X509VerifyError, X509Warning,
    # Версия
    __version__,
)

__all__ = [
    "ASN1",
    # Ключи
    "RSAKeys", "Ed25519Keys", "ECDSAKeys", "EC_CURVES",
    "OID_EC_PUBLIC_KEY", "OID_PRIME256V1",
    "OID_SECP384R1", "OID_SECP521R1", "OID_SECP256K1",
    # Структуры
    "Name", "Cert", "CACert", "CSR", "CertBundle",
    # CRL
    "PKCS12", "PKCS12Builder",
    "CRL", "CRLBuilder", "CRL_REASONS", "CRL_REASONS_REV", "load_pem_crls",
    # OCSP
    "OCSPRequest", "OCSPResponse", "OCSPResponseBuilder",
    "OCSP_STATUS_NAMES", "OCSP_STATUS_CODES",
    "OID_OCSP", "OID_OCSP_BASIC", "OID_OCSP_NONCE",
    # Builders
    "CertificateBuilder", "CertBuilder", "CSRBuilder",
    # Хелперы
    "san_extension", "validate_hostname",
    "canonicalize_name", "names_equal",
    "load_pem_certs", "load_pem_csrs", "load_pem_bundle", "save_pem",
    "pem_encode", "pem_decode", "verify_chain",
    "EKU_OIDS",
    # OID-константы
    "OID_RSA_PSS", "OID_NAME_CONSTR",
    "OID_AIA", "OID_AD_CA_ISSUERS",
    "OID_PBES2", "OID_PBKDF2", "OID_HMAC_SHA256",
    "OID_AES_256_CBC", "OID_AES_256_GCM",
    # Исключения
    "X509Error", "X509ParseError", "X509VerifyError", "X509Warning",
    # Версия
    "__version__",
]