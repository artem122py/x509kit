# -*- coding: utf-8 -*-
"""
check_docs.py - проверка полноты докстринга и экспортов x509kit.

Проверяет:
  1. Структура модуля (version, docstring, __all__, дубли)
  2. Все имена из __all__ реально импортируются
  3. Все секции докстринга на месте
  4. Ключевые классы упомянуты в докстринге
  5. Ключевые методы упомянуты
  6. Ключевые OID-константы упомянуты
  7. Фичи в шапке докстринга

Запуск:
    python check_docs.py
"""

import re
import sys

import x509kit

OK = "\033[32m\xe2\x9c\x93\033[0m"
BAD = "\033[31m\xe2\x9c\x97\033[0m"
WARN = "\033[33m\xc2\xb7\033[0m"

problems = []
warnings = []


def section(title):
    print()
    print("-" * 72)
    print(f"  {title}")
    print("-" * 72)


def ok(msg):
    print(f"  {OK} {msg}")


def fail(msg, hint=None):
    problems.append(msg)
    line = f"  {BAD} {msg}"
    if hint:
        line += f"\n      -> {hint}"
    print(line)


def warn(msg, hint=None):
    warnings.append(msg)
    line = f"  {WARN} {msg}"
    if hint:
        line += f"\n      -> {hint}"
    print(line)


# ---- 1. Структура ----

section("1. Структура модуля")

if getattr(x509kit, "__version__", None):
    ok(f"__version__ = {x509kit.__version__!r}")
else:
    fail("__version__ отсутствует")

doc = x509kit.__doc__ or ""

if len(doc) > 500:
    ok(f"docstring: {len(doc)} символов")
else:
    fail("docstring слишком короткий")

all_list = list(getattr(x509kit, "__all__", []) or [])
if all_list:
    ok(f"__all__: {len(all_list)} имён")
else:
    fail("__all__ пуст")

dupes = [n for n in set(all_list) if all_list.count(n) > 1]
if dupes:
    fail(f"дубли в __all__: {dupes}")
else:
    ok("нет дублей в __all__")


# ---- 2. Все имена доступны ----

section("2. Все имена из __all__ доступны")

missing = [n for n in all_list if not hasattr(x509kit, n)]
if missing:
    fail(f"недоступны: {missing}", "проверь импорт в __init__.py")
else:
    ok(f"все {len(all_list)} имён доступны")


# ---- 3. Секции докстринга ----

section("3. Секции докстринга")

required_sections = [
    ("Ключи",              ["Ключи"]),
    ("Сертификаты",        ["Сертификаты"]),
    ("CSR",                ["CSR", "PKCS#10"]),
    ("CRL",                ["CRL"]),
    ("OCSP",               ["OCSP"]),
    ("PKCS#12",            ["PKCS#12", ".p12"]),
    ("CertificateBuilder", ["CertificateBuilder"]),
    ("CSRBuilder",         ["CSRBuilder"]),
    ("Хелперы",            ["Хелперы", "OID"]),
    ("Исключения",         ["Исключения"]),
    ("Пример",             ["Пример"]),
]

for label, patterns in required_sections:
    hit = any(re.search(re.escape(p), doc, re.IGNORECASE) for p in patterns)
    if hit:
        ok(f"секция «{label}»")
    else:
        fail(f"секция «{label}» отсутствует", f"искали: {patterns}")


# ---- 4. Ключевые классы ----

section("4. Ключевые классы в докстринге")

key_classes = [
    "RSAKeys", "Ed25519Keys", "ECDSAKeys",
    "Cert", "CACert", "CSR", "CRL",
    "OCSPRequest", "OCSPResponse", "OCSPResponseBuilder",
    "CertificateBuilder", "CSRBuilder", "CRLBuilder",
    "PKCS12", "CertBundle", "Name",
]

for name in key_classes:
    if name in doc:
        ok(f"упомянут {name}")
    elif name in all_list:
        fail(f"{name} в __all__, но не в докстринге")
    else:
        warn(f"{name} не упомянут")


# ---- 5. Ключевые методы ----

section("5. Ключевые методы в докстринге")

key_methods = [
    "add_subject", "add_issuer", "self_signed",
    "add_public_key", "add_serial_random", "add_validity",
    "add_san_dns", "add_san_ip", "add_san_email", "add_san_uri",
    "add_basic_constraints", "add_key_usage",
    "add_extended_key_usage", "add_name_constraints",
    "add_crl_distribution_point", "add_aia",
    "add_ski", "add_aki", "set_sig_scheme", "use_pss", "sign",
    "from_csr",
    "verify_signature", "verify_chain", "verify_cert",
    "is_self_signed", "is_valid_at", "name_matches",
    "subject_matches_issuer",
    "issue_csr", "issue_with_key", "respond_ocsp",
    "sign_pkcs1v15", "sign_pss", "to_private_pem", "from_pem",
    "is_revoked", "revoke", "to_crl",
    "to_der", "to_pem", "save",
    "validate_hostname", "san_extension",
    "canonicalize_name", "names_equal",
    "load_pem_certs", "load_pem_crls",
    "set_key", "set_cert", "add_chain",
]

for name in key_methods:
    if name in doc:
        ok(f"метод {name}")
    else:
        warn(f"метод {name} не в докстринге")


# ---- 6. OID-константы ----

section("6. OID-константы в докстринге")

key_oids = [
    "OID_RSA_PSS", "OID_NAME_CONSTR", "OID_AIA", "OID_AD_CA_ISSUERS",
    "OID_EC_PUBLIC_KEY", "OID_PRIME256V1", "OID_SECP384R1",
    "OID_SECP521R1", "OID_SECP256K1",
    "OID_PBES2", "OID_PBKDF2", "OID_HMAC_SHA256",
    "OID_AES_256_CBC", "OID_AES_256_GCM",
    "OID_OCSP", "OID_OCSP_BASIC", "OID_OCSP_NONCE",
]

for name in key_oids:
    if name in doc:
        ok(f"OID {name}")
    else:
        fail(f"OID {name} не в докстринге")


# ---- 7. Фичи в шапке ----

section("7. Фичи в шапке докстринга")

features = [
    ("ASN.1 DER",         ["ASN\\.1", "DER"]),
    ("RSA PKCS#1 + PSS",  ["PKCS#1", "PSS"]),
    ("Ed25519",           ["Ed25519", "RFC 8032"]),
    ("ECDSA",             ["ECDSA", "P-256"]),
    ("X.509 v3",          ["X\\.509"]),
    ("SAN",               ["SAN"]),
    ("BasicConstraints",  ["BasicConstraints"]),
    ("KeyUsage",          ["KeyUsage"]),
    ("EKU",               ["Extended Key Usage", "EKU"]),
    ("Name Constraints",  ["Name Constraints"]),
    ("AKI/SKI",           ["AKI", "SKI"]),
    ("CRL DP",            ["CRL Distribution", "CRL DP"]),
    ("AIA",               ["AIA", "Authority Information"]),
    ("PKCS#10",           ["PKCS#10"]),
    ("CRL",               ["CRL"]),
    ("OCSP",              ["OCSP"]),
    ("PKCS#8 Encrypted",  ["PKCS#8", "EncryptedPrivateKeyInfo"]),
    ("PKCS#12",           ["PKCS#12", ".p12"]),
    ("RFC 4518",          ["RFC 4518", "канонизация"]),
]

for label, patterns in features:
    hit = any(re.search(p, doc) for p in patterns)
    if hit:
        ok(f"фича «{label}»")
    else:
        fail(f"фича «{label}» отсутствует в шапке")


# ---- Итог ----

print()
print("=" * 72)
if not problems:
    msg = f"  \033[32mВСЁ ОК\033[0m"
    if warnings:
        msg += f" — {len(warnings)} предупреждений"
    print(msg)
else:
    print(f"  \033[31mПРОБЛЕМ: {len(problems)}\033[0m  |  предупреждений: {len(warnings)}")
    print()
    for p in problems:
        print(f"    - {p}")
print("=" * 72)

sys.exit(0 if not problems else 1)
