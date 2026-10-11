# Test Index

Все проверки живут в `test_all.py`, сгруппированы по функциям-секциям.
Запуск одной командой:

    python test_all.py

В конце печатается `Пройдено: N/N | Провалено: 0 | Пропущено: 0`.
Ненулевой exit code означает регрессию. `check_docs.py`,
`check_no_hidden.py` и `compat_test.py` — отдельные гейты CI.

Свежий счётчик проверок:

    python -c "import re,sys; s=open('test_all.py').read(); \
        print(len(re.findall(r'T\.(?:ok|expect|fail|skip)\\\\(', s)))"

---

## 1. `test_rsa` — RSA self-tests

- `RSAKeys.generate(2048)` → 2048-битный ключ
- PKCS#1 v1.5 sign/verify round-trip
- Tampered message → False
- Tampered signature → False
- Детерминизм PKCS#1 v1.5 (одинаковый вход → одинаковая подпись)
- Хэши sha256 / sha384 / sha512
- RSASSA-PSS sign/verify + tampered
- `generate(1024)` отвергается (ValueError)
- `generate(2048, e=3)` отвергается
- Приватный PEM round-trip

## 2. `test_ed25519` — Ed25519 (RFC 8032)

- RFC 8032 test vector 1: seed → pub, sign, verify
- RFC 8032 test vector 2: pub, signature byte-exact
- Детерминизм: дважды подписать одно и то же — одинаково
- Отказ при S >= L
- Отказ при битом R

## 3. `test_ecdsa` — ECDSA + RFC 6979

- Sign/verify на P-256 / P-384 / P-521 / secp256k1
- Tampered message → False
- Детерминизм RFC 6979 (дважды → одинаково)
- RFC 6979 Appendix A.2.5 test vectors (P-256, SHA-256):
  сообщения "sample" и "test", r и s byte-exact
- `n.bit_length()` для P-256 (256) и P-521 (521)

## 4. `test_aes` — AES-256 + AES-GCM

- FIPS 197 §C.3 AES-256 encrypt одного блока
- FIPS 197 decrypt
- AES-256-CBC round-trip
- NIST SP 800-38D Test 1 (пустой PT): ct пустой, tag совпадает
- NIST SP 800-38D Test 2 (один блок): ct и tag byte-exact
- GCM round-trip с AAD
- GCM tampered tag → `X509Error`

## 5. `test_encrypted_keys` — PKCS#8 EncryptedPrivateKeyInfo

- RSA / Ed25519 / ECDSA × AES-256-CBC / AES-256-GCM
- `ENCRYPTED PRIVATE KEY` PEM-обёртка
- Round-trip с правильным паролем
- Неверный пароль → `X509Error`
- Незашифрованный PEM начинается с `RSA PRIVATE KEY`

## 6. `test_chain` — Цепочки сертификатов

Параметризовано по типам ключей: RSA-2048, Ed25519,
ECDSA P-256 / P-384 / P-521 / secp256k1.

- Root self-signed verify
- Inter ← root, leaf ← inter подписи валидны
- `verify_chain([leaf, inter])` от root
- `inter.verify_chain([leaf])`
- Обратный порядок → False
- Без intermediate → False
- Истёкший leaf → False
- Чужой root → False
- CSR self-signature
- CSR tampered → False
- `validate_hostname`: exact / wildcard / wrong / IP
- Cert PEM round-trip
- Tampered leaf → False (или parse error)

## 7. `test_mixed` — Все типы CA → все типы leaf

- Для каждого CA-типа (RSA / Ed25519 / EC-P256 / EC-P384)
  выпустить листья всех 4 типов, все verify_chain → True

## 8. `test_cryptography` — Cross-verify с `cryptography`

RSA PKCS#1 v1.5 и Ed25519, в обе стороны. Skip, если
`cryptography` не установлена.

## 9. `test_ecdsa_cryptography` — ECDSA cross-verify

P-256 / P-384 / P-521: наш sign → их verify, их sign → наш verify.
Skip без `cryptography`.

**Важно:** байт-в-байт сравнение подписей тут не работает —
`cryptography` использует рандомный `k` (до версии 43.0.0),
наш — RFC 6979. Совпадение проверяется только по verify.

## 10. `test_name_constraints` — Name Constraints

- Round-trip: permitted/excluded DNS + IP сохраняются
- Enforcement при выпуске: разрешённый leaf OK
- `evil.org` (вне permitted) → `X509Error`
- `app.bad.example.com` (в excluded) → `X509Error`
- IP вне subnet → `X509Error`
- NC intersection: sub-CA разрешает больше родителя → False

## 11. `test_crl` — CRL (RFC 5280)

- 3 листа выпущены и валидны
- CRL подпись, `is_valid_at`
- `is_revoked` для отозванного и неотозванного
- `revoke_reason == "keyCompromise"`
- `verify_cert(a, crl=crl)` → True
- `verify_cert(b, crl=crl)` → False
- CRL PEM round-trip

## 12. `test_ocsp` — OCSP (RFC 6960)

- `OCSPRequest.create` (serial, nonce)
- Request round-trip
- `OCSPResponse` successful, подпись, свежесть
- Nonce echo
- `get_status` → "good"
- `verify_ocsp_response` с request
- Revoked status + revoke_info
- `verify_cert` с good OCSP → True
- `verify_cert` с revoked OCSP → False

## 13. `test_aia` — Authority Information Access

- `leaf.aia_ocsp` / `leaf.aia_issuers`
- `ca.aia_ocsp`
- Полный dict `{ocsp, ca_issuers}`
- Строка как один URL принимается

## 14. `test_canonicalization` — RFC 4518 DN

- Raw не совпадает, canonical — совпадает
- NFKC: fullwidth → ASCII, ligature ﬁ → fi
- Пробелы схлопнуты
- `subject_matches_issuer` / `name_matches` на Cert
- `names_equal` регистронезависимо

## 15. `test_pem_roundtrip`

- Cert PEM round-trip: `Cert(cert.to_pem()).der == cert.der`
- CertBundle из 3 сертификатов round-trip

## 16. `test_name_from_string` — RFC 4514

- Round-trip == `from_dict`
- `str()` содержит CN
- Round-trip через строку
- Escape запятой (`\,`), escape backslash (`\\`)
- Пустая строка → `X509Error`
- Нет `=` → `X509Error`

## 17. `test_cert_from_url`

- `Cert.from_url` определён
- Реальный fetch (если есть сеть) возвращает `Cert`
- Пустой URL → ошибка

## 18. `test_cert_info` — `openssl x509 -text` стиль

- Начинается с `Certificate:`
- Есть `Version: 3`, `Serial Number:`, `Signature Algorithm:`
- `Issuer:`, `Validity`, `Not Before:`, `Not After :`, `Subject:`
- `Subject Public Key Info:` + `Public Key Algorithm: ED25519`
- `X509v3 extensions:` + `X509v3 Subject Alternative Name`
- SAN-значение (`info.example`) присутствует

## 19. `test_pkcs12_shortcuts` — Шорткаты PKCS#12

- `key.to_pkcs12(cert, chain=[ca], password=...)`
- MAC valid, `verify_chain(trust_anchor=ca)`
- Round-trip: key/cert совпадают
- `CertBundle.to_pkcs12(key, ...)`
- Bundle round-trip: chain len=1
- Все три типа ключей (RSA / Ed25519 / ECDSA) → to_pkcs12 + MAC
- Пустой bundle → `X509Error`

## 20. `test_sct_parsing` — Certificate Transparency

- Синтетический SCT list: version, log_id, timestamp, alg
- Битый SCT list не крашит (возвращает список)
- Cert без SCT: `has_sct=False`, `sct_list=[]`

## 21. `test_acme_persistence` — ACME save/load

- Первый сервер: account + order
- `save(path)` → файл создан
- `load` восстанавливает account / order / authz / challenges
- `kid` совпадает
- `get_order` работает после загрузки
- `to_dict` / `from_dict` round-trip

## 22. `test_revocation_network` — CRL/OCSP через HTTP

Сервер `make_revocation_server(ca, "127.0.0.1", 0)` в фоне.

- `leaf.fetch_crl(ca=ca)` получен, leaf не в CRL
- `leaf.fetch_ocsp(issuer=ca)` получен, status="good"
- После `ca.revoke(leaf, reason="keyCompromise")`:
  - `fetch_crl` показывает leaf, reason keyCompromise
  - `fetch_ocsp` показывает status="revoked", reason keyCompromise
- Cert без URL: `fetch_crl() → None`, `fetch_ocsp() → None`
- `Cert.from_url` принимает `client_cert` / `client_key`
- `CertBundle.sort_chain`: первый элемент — leaf

## 23. `test_cms_parsing` — CMS (RFC 5652) parsing

- Version, content_type, attached content
- Detached: `content is None`, `detached=True`
- SignerInfo: sid_kind, serial, digest name, sig name
- PEM round-trip и DER round-trip
- `get_cert_for_signer` возвращает None, если сертификатов нет

## 24. `test_cms_sign_verify` — CMS sign / verify

Для RSA-2048 / Ed25519 / EC-P256:

- Attached: parse, content round-trip, certs embedded (leaf+ca)
- `verify()` без trust anchor
- `verify(trust_anchor=ca)` → True
- `signingTime` / `messageDigest` / `contentType` атрибуты
- `get_cert_for_signer` находит leaf
- Detached: verify без data → False, с data → True,
  с tampered data → False
- Wrong trust anchor → False
- PEM round-trip
- `add_signing_time=False` → атрибута нет, verify OK
- Key/cert mismatch → `X509Error`

## 25. `test_cli` — CLI

- `--version` → rc=0, содержит версию
- `info` файла: rc=0, subject / issuer / Version: 3 / SAN
- `info -` (stdin)
- `info` несуществующего файла → rc=1
- `verify --ca` OK → rc=0
- `verify` с wrong anchor → rc=1
- `keygen ed25519` → файл создан, ключ reloadable
- `keygen --password`: `ENCRYPTED PRIVATE KEY`, decryptable,
  wrong password отвергается
- `csr create` с SAN dns ×2 → subject, SANs, signature valid
- `csr create --san bogus` → rc=2
- `csr info` → показывает CN
- `cms verify` attached / detached / detached без `--content`
- `pkcs12 info --password` → MAC valid, subject
- `crl info` → issuer, revoked count
- Неизвестная команда → rc=2

## 26. `test_builder_dup_guards` — Защита от дублей

- `CertificateBuilder.add_subject / add_issuer / add_public_key /
  add_serial` при повторном вызове → `X509Error("уже задан")`
- `add_serial` после `add_serial_random` → X509Error
- `add_serial_random` дважды → X509Error
- `self_signed()` после `add_issuer` → X509Error
- `CSRBuilder.add_subject / add_public_key` дважды → X509Error
- Happy path не сломан

## 27. `test_from_public_bytes` — Явные фабрики

- Ed25519: `from_public_bytes(32 bytes)`, wrong size, str → TypeError
- ECDSA: uncompressed на всех 4 кривых
- ECDSA: compressed P-256 / P-384 / P-521
- ECDSA: wrong size / not on curve / bad curve name → X509Error
- RSA: `from_public_bytes(spki)` и `fmt="pkcs1"`
- RSA: `fmt="raw"` → X509Error
- Sign оригиналом, verify распарсенным (все три типа)

## 28. `test_zero_pubkey_defense` — Zero public key / small-order

- `Ed25519Keys(pub=identity)` → X509Error
- `Ed25519Keys(pub=order-4)` → X509Error
- `from_public_bytes(identity)` → X509Error
- `_ed_has_small_order` прямой тест
- Атака: forged signature с identity-ключом отвергается для
  сообщений `b"transfer $1M"`, `b"admin=true"`, `b""`, `b"x"*1000`
- RFC 8032 vector всё ещё принимается
- RSA `n=0`, `n<0`, `e=0`, `e=1`, `e=2` → X509Error
- RSA SPKI с `n=0` → X509Error
- Happy path не сломан

## 29. `test_ecdsa_invalid_point` — ECDSA invalid curve

- `_ec_decode_point("")` → None
- `_ec_decode_point(0x00)` → None (point at infinity)
- `_ec_decode_point(0x04||0*64)` → None ((0,0))
- `_ec_decode_point(0x02||0*32)`: либо None, либо валидная
  точка на кривой (для P-256 — валидная)
- `_ec_decode_point(0x05...)` → None (неизвестный tag)
- `_ec_decode_point(x ≥ p)` → None
- `ECDSAKeys.from_public_bytes(0x00 / (0,0))` → X509Error
- `ECDSAKeys(point=...)`: (0,0), (1,1), x out of p, non-int,
  not tuple → X509Error/TypeError
- Forged sig отвергается, даже если обойти конструктор
- Legit key round-trip P-256 / P-384 / P-521 / secp256k1

## 30. `test_weak_rsa_warning_paths` — Слабый RSA

Warning выдаётся ровно один раз из `RSAKeys.__init__`
на пользовательское создание. Парсинг `Cert`/`CSR`/`CRL`/`OCSP`/`CMS`
передаёт `_warn_weak=False`, warning не дублируется.

- `RSAKeys(n=1024)` напрямую → 1 warning
- `from_public_der(pkcs1)` → 1 warning
- `from_public_bytes(fmt="pkcs1")` → 1 warning
- `from_private_der` → 1 warning
- `RSAKeys(n=2048)` → 0 warnings
- `CertificateBuilder` с weak key → ровно 1 warning
- `stacklevel` указывает на пользовательский код, не на `x509.py`

---

## Итого

- **30 секций** в `test_all.py`
- **481 проверка** (пересчитывается автоматически)
- Плюс отдельные гейты: `check_docs.py`, `check_no_hidden.py`,
  `check_dispatcher.py`, `compat_test.py`, `fuzz_x509.py`,
  `flask/test_live_ca.py`, `flask/test_mtls.py`

## Проверено внешними инструментами

| Компонент | Внешний верификатор |
|---|---|
| RSA PKCS#1 / PSS | `cryptography`, `openssl pkeyutl` |
| Ed25519 | RFC 8032 test vectors (byte-exact), `cryptography` |
| ECDSA | RFC 6979 test vectors (byte-exact), `cryptography` |
| AES-256-CBC | FIPS 197 test vector |
| AES-256-GCM | NIST SP 800-38D test vectors |
| X.509 | `openssl x509 -text`, `openssl verify` |
| Полная цепочка | Python `ssl` TLS handshake |
| CRL | `openssl crl -text`, `openssl verify -crl_check` |
| PKCS#12 | `openssl pkcs12 -info -nodes` |
| PKCS#8 encrypted | `openssl pkey` |
| mTLS | `openssl s_client -cert -key` |
| CMS (RFC 5652) | `openssl cms -verify` |
