# Test Index

Все проверки в `test_all.py`, сгруппированные по функциям.
Негативные тесты (try/except) показаны один раз — только то,
что должно произойти.

## `test_rsa` (10)

- generate(2048) → 2048-битный
- PKCS#1 v1.5 sign/verify
- tampered message → False
- tampered signature → False
- детерминизм (PKCS#1 v1.5)
- PSS sign/verify
- PSS: tampered → False
- private PEM round-trip
- generate(1024) отвергается
- e=3 отвергается

## `test_ed25519` (8)

- RFC 8032 test1: pubkey
- RFC 8032 test1: signature
- RFC 8032 test1: verify
- RFC 8032 test2: pubkey
- RFC 8032 test2: signature
- детерминизм Ed25519
- отказ при S >= L
- отказ при битом R

## `test_ecdsa` (7)

- RFC 6979: детерминизм
- RFC 6979 'sample': r
- RFC 6979 'sample': s
- RFC 6979 'test': r
- RFC 6979 'test': s
- P-256 n.bit_length == 256
- P-521 n.bit_length == 521

## `test_aes` (9)

- FIPS 197 AES-256 encrypt
- FIPS 197 AES-256 decrypt
- AES-256-CBC round-trip
- NIST GCM empty: ct пустой
- NIST GCM empty: tag
- NIST GCM block: ct
- NIST GCM block: tag
- GCM round-trip с AAD
- GCM: tampered tag → X509Error

## `test_encrypted_keys` (2)

- plain RSA PEM (не шифрован)
- GCM: неверный пароль → X509Error

## `test_chain` (18)

- root self-signed
- inter ← root
- leaf ← inter
- verify_chain([leaf, inter])
- inter.verify_chain([leaf])
- порядок наоборот → False
- без intermediate → False
- истёкший leaf → False
- чужой root → False
- CSR self-signature
- CSR tampered → False
- hostname exact
- hostname wildcard
- hostname wrong
- hostname IP ok
- cert PEM round-trip
- tampered leaf → False
- tampered leaf: parse отказал

## `test_mixed` (0)


## `test_cryptography` (5)

- их RSA sign → наш verify
- Ed25519: seed → pubkey
- их Ed25519 sign → наш verify
- наш RSA sign → их verify
- наш Ed25519 sign → их verify

## `test_ecdsa_cryptography` (0)


## `test_name_constraints` (10)

- NC: расширение есть
- NC: permitted dns
- NC: permitted ip
- NC: excluded dns
- NC: excluded ip
- NC: допустимый leaf выпущен
- NC: verify_chain
- NC intersection: sub-CA разрешает больше → False
- NC: IP вне subnet → X509Error
- NC intersection: нарушение поймано при выпуске

## `test_crl` (9)

- 3 листа выпущены
- CRL: подпись
- CRL: is_valid_at
- CRL: a не отозван
- CRL: b отозван
- CRL: reason keyCompromise
- CRL: verify_cert(a, crl=crl)
- CRL: verify_cert(b, crl=crl) → False
- CRL: PEM round-trip

## `test_ocsp` (13)

- OCSPRequest serial
- OCSPRequest nonce
- OCSPRequest round-trip
- OCSPResponse successful
- OCSPResponse signature
- OCSPResponse fresh
- OCSPResponse nonce echo
- OCSPResponse status good
- verify_ocsp_response с request
- OCSP revoked status
- OCSP revoke info
- verify_cert с good OCSP
- verify_cert с revoked OCSP → False

## `test_aia` (5)

- AIA: leaf.aia_ocsp
- AIA: leaf.aia_issuers
- AIA: ca.aia_ocsp
- AIA: полный dict
- AIA: строка как один URL

## `test_canonicalization` (13)

- raw не совпадает
- канонично совпадает
- NFKC: fullwidth → ascii
- NFKC: ligature ﬁ → fi
- пробелы схлопнуты
- subject_matches_issuer(ca)
- subject_matches_issuer(leaf) → False
- name_matches(ca) → False
- leaf.subject_matches_issuer(ca)
- ca.name_matches(ca) → True
- names_equal(leaf.subject, ca.subject) → False
- names_equal(ca.subject, ca.subject) → True
- names_equal регистронезависимо

## `test_pem_roundtrip` (2)

- cert PEM round-trip
- bundle round-trip

## `test_name_from_string` (7)

- round-trip == from_dict
- str содержит CN
- round-trip через str
- escape запятой
- escape backslash
- пустая строка → X509Error
- нет '=' → X509Error

## `test_cert_from_url` (5)

- Cert.from_url определён
- возвращает Cert
- subject есть
- SAN есть
- пустой URL → X509Error

## `test_cert_info` (0)


## `test_pkcs12_shortcuts` (10)

- key.to_pkcs12 → PKCS12
- to_pkcs12: MAC valid
- to_pkcs12: chain ok
- to_pkcs12 round-trip: key matches
- to_pkcs12 round-trip: cert matches
- bundle.to_pkcs12 → PKCS12
- bundle.to_pkcs12: MAC valid
- bundle round-trip: cert matches
- bundle round-trip: chain len=1
- пустой bundle → X509Error

---

**Итого:** 19 функций, 133 проверок.
