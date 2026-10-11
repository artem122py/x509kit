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
  * ACME (RFC 8555) — совместим с certbot
  * Certificate Transparency (RFC 6962) — SCT parsing
  * CMS (RFC 5652) SignedData — parsing, signing, verification
  * Сетевые фичи: Cert.from_url (в т.ч. mTLS), fetch_crl / fetch_ocsp
    / fetch_issuer, CertBundle.sort_chain
  * HTTP-серверы CRL/OCSP (x509kit.revocation)
  * CLI: x509kit info / keygen / csr / verify / cms / pkcs12 / crl

═══════════════════════════════════════════════════════════════════════
  Ключи
═══════════════════════════════════════════════════════════════════════

    RSAKeys.generate(2048)
    RSAKeys.from_pem(pem, private=True, password="...")
    RSAKeys.from_public_der(spki_der)
    RSAKeys.from_public_bytes(der, fmt="spki"|"pkcs1")   # явный формат
    k.to_private_pem(password="...") / k.to_public_pem()
    k.to_public_der()              — SubjectPublicKeyInfo DER
    k.sign_pkcs1v15(msg, "sha256") / k.verify_pkcs1v15(msg, sig, "sha256")
    k.sign_pss(msg, "sha256")      / k.verify_pss(msg, sig, "sha256")
    k.size_bits / k.is_private / k.weak

    # Шорткат на всех трёх типах ключей:
    k.to_pkcs12(cert, chain=[ca], password="...", name="alice")
        ^ возвращает PKCS12, можно .save("alice.p12")

    Ed25519Keys.generate() / Ed25519Keys(seed=bytes(32))
    Ed25519Keys.from_pem(pem, private=True, password="...")
    Ed25519Keys.from_public_der(spki_der)
    Ed25519Keys.from_public_bytes(32_raw_bytes)         # RFC 8032 §5.1.2
    k.sign(msg) / k.verify(msg, sig) / k.pub
    k.to_public_der() / k.to_public_pem()

    ECDSAKeys.generate("P-256"|"P-384"|"P-521"|"secp256k1")
    ECDSAKeys.from_pem(pem, private=True, password="...")
    ECDSAKeys.from_public_der(spki_der)
    ECDSAKeys.from_public_bytes(sec1, curve="P-256")    # X9.62 §4.3.6
        ^ sec1: 0x04||X||Y (uncompressed) или 0x02/0x03||X (compressed)
        ^ curve обязателен — по длине кривая однозначно не определяется
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
    c.info()                            — вывод в стиле openssl x509 -text
    # Сетевые операции (0.6.0):
    c.fetch_crl(ca=None, timeout=10)         — скачать CRL по CRL DP
        ^ ca — если задан, проверить подпись CRL
        ^ возвращает CRL или None (если нет CRL DP)
    c.fetch_ocsp(issuer, timeout=10)         — OCSP-запрос на aia_ocsp URL
        ^ возвращает dict {status, reason, revoked_at, this_update, ...}
        ^ или None, если URL не указан
    c.fetch_issuer(timeout=10, max_depth=5, trust_anchor=None)
        ^ AIA chasing по ca_issuers URL
        ^ возвращает список Cert от ближайшего к root

    Cert.from_url("https://example.com")     — скачать сертификат с сервера
        ^ принимает "example.com" или "https://host:port"
        ^ client_cert / client_key — для mTLS:
              Cert.from_url(url, client_cert=my_cert, client_key=my_key)
              принимают Cert / PEM-строку / путь / объект ключа
        ^ verify=True — проверять валидность TLS-сертификата
        ^ возвращает Cert

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
        .add_issuer(ca) / .self_signed()    # взаимоисключающие
        .add_public_key(key)             — RSAKeys/Ed25519Keys/ECDSAKeys/SPKI/CSR
        .add_serial_random() / .add_serial(n)

        # Guard: add_subject / add_issuer / add_public_key / add_serial /
        # add_serial_random / self_signed — повторный вызов → X509Error
        # с подсказкой «создай новый CertificateBuilder()».
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
        # Guard: add_subject / add_public_key — повторный вызов → X509Error
        .add_subject({...}) / .add_public_key(key)
        .add_san(...) / .add_san_dns(...) / .add_san_ip(...)
        .add_extended_key_usage("serverAuth")
        .set_hash("sha256") / .set_sig_scheme("pss") / .use_pss()
        .sign(signing_key)

═══════════════════════════════════════════════════════════════════════
  Хелперы и OID
═══════════════════════════════════════════════════════════════════════

    ASN1 — низкоуровневый DER-парсер (parse, as_int, as_oid, ...)
        ^ защита: _MAX_DER_SIZE = 512 KB, _MAX_DEPTH = 32
    canonicalize_name(name) / names_equal(a, b)   — RFC 4518

    Name.from_string("CN=x, O=y, C=XX")           — RFC 4514 parser
        ^ порядок "от конкретного к общему"
        ^ поддерживает escape: "CN=with\\, comma, O=Org"
    Name.from_dict({...})                          — из dict
    san_extension(dns_names=[], ips=[], emails=[], uris=[])
    validate_hostname(cert, "example.com")        — RFC 6125
    load_pem_certs / load_pem_csrs / load_pem_bundle / load_pem_crls
        ^ защита: _MAX_PEM_SIZE = 1 MB
    save_pem(path, cert1, cert2, ...)
    pem_encode / pem_decode / verify_chain

    CertBundle([c1, c2, ...])
        .from_pem(data) / .from_file(path) / .to_pem() / .save(path)
        .sort_chain()                            — порядок leaf → root
            ^ по issuer.raw == subject.raw; возвращает новый CertBundle
        .to_pkcs12(key, password="...", name="...")
            ^ certs[0] — leaf, certs[1:] — chain; возвращает PKCS12

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
  ACME (RFC 8555)
═══════════════════════════════════════════════════════════════════════

    ACMEServer(ca, ca_key, base_url, chain=[...], cert_days=90,
               auto_verify=False)
        ^ минимальный ACME-сервер с http-01 challenge

    srv.directory()
    srv.new_account(jwk, {"termsOfServiceAgreed": True})
    srv.new_order(kid, {"identifiers": [{"type": "dns", "value": "x"}]})
    srv.finalize(order_id, {"csr": b64u(csr.der)})
    srv.get_certificate(cert_id)

    # Persistence (JSON state):
    srv.save("state.json")
    srv = ACMEServer.load(ca, ca_key, "state.json", base_url=...)
    srv = ACMEServer.from_dict(ca, ca_key, data)
    data = srv.to_dict()

    ACMEError — тип urn:ietf:params:acme:error:<kind>

    b64u(data) / b64u_decode(s)          — base64url (RFC 4648 §5)
    jwk_to_key(jwk) / jwk_thumbprint(jwk) — RFC 7517 / RFC 7638
    verify_jws(jws, expected_url=...,     — RFC 7515
               nonce_checker=..., key_resolver=...)

    Поддерживаемые JWS алгоритмы:
        EdDSA (Ed25519), ES256/ES384/ES512, RS256

    Проверено с certbot (ISRG / Let's Encrypt):
        certbot certonly --server http://127.0.0.1:14000/directory ...

    Примеры:
        python examples/13_acme_server.py --auto-verify
        python examples/14_acme_client.py

═══════════════════════════════════════════════════════════════════════
  Certificate Transparency (RFC 6962 §3.3)
═══════════════════════════════════════════════════════════════════════

    cert.sct_list      — список embedded Signed Certificate Timestamps
        каждый: {version, log_id, timestamp_iso, hash_alg, sig_alg, ...}
    cert.has_sct       — True, если SCT present
    OID_SCT            — "1.3.6.1.4.1.11129.2.4.2"

    Пример: python examples/15_ct_sct.py www.google.com

═══════════════════════════════════════════════════════════════════════
  Revocation servers — HTTP CRL/OCSP (x509kit.revocation, 0.6.0)
═══════════════════════════════════════════════════════════════════════

    from x509kit.revocation import make_revocation_server, run_in_thread

    ca = CACert.from_pem(pem, private_key_pem=key_pem)
    ca.revoke(leaf, reason="keyCompromise")

    srv = make_revocation_server(ca, host="127.0.0.1", port=0)
    run_in_thread(srv)                          — daemon-thread
    print(srv.base_url())                       — http://127.0.0.1:NNNNN

    # Endpoints:
    #   GET  /crl.pem    — CRL (PEM), пересобирается раз в crl_cache_seconds
    #   GET  /crl.der    — CRL (DER)
    #   POST /ocsp       — OCSP-запрос (DER) → OCSP-ответ (DER)
    #   GET  /           — HTML-статус

    make_revocation_handler(ca, crl_days=7, crl_cache_seconds=60)
        ^ возвращает класс BaseHTTPRequestHandler (для встраивания)

    RevocationHTTPServer(addr, ca, ...)
        .base_url() / .ca

    run_in_thread(srv) — обёртка над threading.Thread(daemon=True)

═══════════════════════════════════════════════════════════════════════
  CMS SignedData (RFC 5652) — parse / sign / verify
═══════════════════════════════════════════════════════════════════════

    from x509kit import cms_sign, CMSSignedData

    # Attached (content внутри .p7s)
    sd = cms_sign(b"hello", key=signing_key, cert=signing_cert,
                   chain=[ca])
    sd.save("message.p7s")
    assert sd.verify(trust_anchor=ca)

    # Detached (content отдельно)
    sd = cms_sign(b"hello", key=signing_key, cert=signing_cert,
                   detached=True)
    sd.save("message.p7s.sig")
    sd2 = CMSSignedData.load("message.p7s.sig")
    assert sd2.verify(detached_data=b"hello", trust_anchor=ca)

    # Параметры cms_sign:
    #   detached=False             — content в контейнере
    #   digest='sha256'            — 'sha256'|'sha384'|'sha512'
    #                                (для Ed25519 игнорируется, SHA-512)
    #   sig_scheme='pkcs1v15'      — 'pkcs1v15'|'pss' (только RSA)
    #   signing_time=None          — datetime.now(UTC) по умолчанию
    #   add_signing_time=True      — включать ли signed-атрибут signingTime

    # Загрузка и парсинг
    sd = CMSSignedData.load("message.p7s")
    sd.version / sd.content_type / sd.content / sd.detached
    sd.digest_algorithms / sd.certificates / sd.crls / sd.signers

    # Поля SignerInfo
    for s in sd.signers:
        s.sid_kind          — 'issuer_and_serial' | 'subject_key_id'
        s.issuer / s.serial — для IssuerAndSerialNumber
        s.subject_key_id    — для SubjectKeyIdentifier
        s.digest_algorithm.name
        s.signature_algorithm.name
        s.signature         — bytes
        s.signing_time      — datetime или None
        s.message_digest    — bytes или None
        s.content_type_attr — OID или None
        s.signed_attrs      — dict {oid: [DER value, ...]}

    # Verify
    sd.verify()                                    — подпись + messageDigest
    sd.verify(trust_anchor=ca)                     — плюс цепочка
    sd.verify(detached_data=b"hello")              — для detached
    sd.verify(allow_weak_hash=False)               — запрет SHA-1

    # Утилиты
    sd.get_cert_for_signer(s) — Cert подписанта из sd.certificates
    sd.to_der() / sd.to_pem() / sd.save(path)
    cms_load(path_or_der_or_pem) — алиас CMSSignedData.load

    # OID-константы
    OID_PKCS7_SIGNED / OID_PKCS7_DATA / OID_PKCS7_ENVELOPED
    OID_PKCS9_CONTENT_TYPE / OID_PKCS9_MESSAGE_DIGEST / OID_PKCS9_SIGNING_TIME
    CMS_CONTENT_TYPE_NAMES / CMS_SIGNED_ATTR_NAMES

    НЕ реализовано: EnvelopedData / DigestedData / EncryptedData /
    AuthenticatedData, CAdES-BES/LT/LTA, timestamping, external TSA.
    Проверено с OpenSSL CLI (openssl cms -sign / -verify).

═══════════════════════════════════════════════════════════════════════
  CLI (x509kit.cli, entry point "x509kit")
═══════════════════════════════════════════════════════════════════════

После `pip install -e .` (или обычной установки) доступна команда
`x509kit`:

    $ x509kit --version
    $ x509kit --help

    # --- info: как `openssl x509 -text` ---
    $ x509kit info cert.pem
    $ x509kit info https://example.com         # fetch + parse
    $ x509kit info -                           # stdin
    $ x509kit info https://example.com --verify   # проверять TLS-цепочку

    # --- keygen ---
    $ x509kit keygen --type ed25519 --out key.pem
    $ x509kit keygen --type rsa --bits 4096 --out rsa.pem
    $ x509kit keygen --type ec --curve P-384 --out ec.pem
    $ x509kit keygen --type ed25519 --password hunter2 --out enc.pem
    $ x509kit keygen --type ed25519 --out -    # stdout

    # --- csr: info / create ---
    $ x509kit csr info req.csr
    $ x509kit csr create --key key.pem \
        --subject "CN=x.com, O=MyOrg, C=XX" \
        --san dns=x.com --san dns=www.x.com \
        --san ip=192.0.2.1 \
        --san email=admin@x.com \
        --san uri=https://x.com \
        --hash sha384 \
        --out req.csr

    # --- verify: цепочка сертификатов ---
    $ x509kit verify --ca ca.pem leaf.pem
    $ x509kit verify --ca ca.pem --untrusted inter.pem leaf.pem

    # --- cms: verify SignedData ---
    $ x509kit cms verify msg.p7s --ca ca.pem
    $ x509kit cms verify msg.p7s.sig --content data.bin --ca ca.pem

    # --- pkcs12: info ---
    $ x509kit pkcs12 info alice.p12 --password hunter2

    # --- crl: info ---
    $ x509kit crl info revoked.crl.pem

Exit codes:
    0 — успех
    1 — runtime error (файл не найден, парсинг, verify failed)
    2 — ошибка использования (argparse, неизвестный --san kind)

Примеры через python-модуль (без entry point):

    $ python -m x509kit.cli info cert.pem

См. также: examples/ — все примеры запускаются напрямую.
CLI не включает: renew, ACME-клиент, генерацию CA из JSON-конфига —
это библиотечные вызовы (см. секции выше).

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
    OID_AIA, OID_AD_CA_ISSUERS, OID_SCT,
    OID_PBES2, OID_PBKDF2, OID_HMAC_SHA256,
    OID_AES_256_CBC, OID_AES_256_GCM,
    # Исключения
    X509Error, X509ParseError, X509VerifyError, X509Warning,
    # Версия
    __version__,
)

from .acme import (
    ACMEServer, ACMEError,
    b64u, b64u_decode,
    jwk_to_key, jwk_thumbprint, verify_jws,
)


from .revocation import (
    make_revocation_server, make_revocation_handler,
    RevocationHTTPServer, run_in_thread,
)

from .cms import (
    CMSSignedData, CMSSignerInfo, cms_sign, cms_load,
    OID_PKCS7_SIGNED,
    OID_PKCS9_CONTENT_TYPE, OID_PKCS9_MESSAGE_DIGEST,
    OID_PKCS9_SIGNING_TIME,
    CONTENT_TYPE_NAMES as CMS_CONTENT_TYPE_NAMES,
    SIGNED_ATTR_NAMES as CMS_SIGNED_ATTR_NAMES,
)

__all__ = [
    "make_revocation_server", "make_revocation_handler",
    "RevocationHTTPServer", "run_in_thread",
    # CMS (RFC 5652)
    "CMSSignedData", "CMSSignerInfo", "cms_sign", "cms_load",
    "OID_PKCS7_SIGNED",
    "OID_PKCS9_CONTENT_TYPE", "OID_PKCS9_MESSAGE_DIGEST",
    "OID_PKCS9_SIGNING_TIME",
    "CMS_CONTENT_TYPE_NAMES", "CMS_SIGNED_ATTR_NAMES",
    "ACMEServer", "ACMEError",
    "b64u", "b64u_decode",
    "jwk_to_key", "jwk_thumbprint", "verify_jws",
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
    "OID_AIA", "OID_AD_CA_ISSUERS", "OID_SCT",
    "OID_PBES2", "OID_PBKDF2", "OID_HMAC_SHA256",
    "OID_AES_256_CBC", "OID_AES_256_GCM",
    # Исключения
    "X509Error", "X509ParseError", "X509VerifyError", "X509Warning",
    # Версия
    "__version__",
]