# -*- coding: utf-8 -*-
"""
check_dispatcher.py — показывает, где используется крипто-диспетчер
и где остались прямые isinstance-цепочки на типах ключей.

Запуск:
    python check_dispatcher.py
"""

import re
from pathlib import Path


CANDIDATES = [
    Path("src/x509kit/x509.py"),
    Path("x509kit/x509.py"),
    Path("x509.py"),
]


def main():
    src_path = next((p for p in CANDIDATES if p.exists()), None)
    if src_path is None:
        print("[!] x509.py не найден."); return 1

    src = src_path.read_text(encoding="utf-8")
    lines = src.splitlines()

    print(f"Файл: {src_path}")
    print("=" * 72)

    # --- 1. Определения диспетчера ---
    print("\n1. Диспетчер крипто-операций")
    print("-" * 72)
    defs = [
        ("_sign_and_build_alg", "подпись + AlgorithmIdentifier"),
        ("_verify_signed_data", "проверка подписи"),
        ("_public_keys_equal", "сравнение публичных ключей"),
    ]
    for name, desc in defs:
        found = f"def {name}(" in src
        mark = "\033[32m✓\033[0m" if found else "\033[31m✗\033[0m"
        print(f"  {mark} {name:24s} — {desc}")

    # --- 2. Где диспетчер вызывается ---
    print("\n2. Вызовы диспетчера (по функциям)")
    print("-" * 72)

    # найдём все def/class на верхнем уровне
    current = "<module>"
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:def|class)\s+(\w+)", line)
        if m and len(m.group(1)) <= 4:
            current = m.group(2)

        for name in ("_sign_and_build_alg", "_verify_signed_data",
                     "_public_keys_equal"):
            # не считаем строку с "def <name>"
            if f"def {name}" in line:
                continue
            if name in line:
                print(f"  • {current:30s} → {name}")
                break

    # --- 3. Оставшиеся isinstance-цепочки на типах ключей ---
    print("\n3. Оставшиеся прямые isinstance на типах ключей")
    print("-" * 72)

    # Ищем строки, где в одной строке встречается isinstance(...RSAKeys) и isinstance(...Ed25519Keys)
    # или где подряд два isinstance на ключевых типах
    key_types = ("RSAKeys", "Ed25519Keys", "ECDSAKeys")
    suspicious = []
    for i, line in enumerate(lines):
        # пропустим определение диспетчера и комментарии
        if "_sign_and_build_alg" in line or "_verify_signed_data" in line or "_public_keys_equal" in line:
            continue
        # считаем isinstance, где встречается хотя бы один ключевой тип
        isinst = re.findall(r"isinstance\([^,]+,\s*\(?([A-Za-z0-9_]+)", line)
        key_hits = [t for t in isinst if t in key_types]
        if len(key_hits) >= 1:
            # посмотрим на 3 строки вокруг — если рядом ещё isinstance на ключевой тип
            context = "\n".join(lines[max(0, i-1):min(len(lines), i+2)])
            key_hits_ctx = [t for t in re.findall(
                r"isinstance\([^,]+,\s*\(?([A-Za-z0-9_]+)", context) if t in key_types]
            if len(key_hits_ctx) >= 2:
                suspicious.append((i+1, line.rstrip()))

    if suspicious:
        for ln, text in suspicious:
            print(f"  строка {ln:5d}: {text.strip()[:80]}")
    else:
        print("  (пусто — цепочек не найдено)")

    # --- 4. Что патчилось через диспетчер ---
    print("\n4. Заменённые места (по docstring/структуре)")
    print("-" * 72)
    targets = [
        "Cert.verify_signature",
        "CSR.verify_signature",
        "CRL.verify_signature",
        "OCSPResponse.verify_signature",
        "CSRBuilder.sign",
        "CRLBuilder.sign",
        "OCSPResponseBuilder.sign",
        "CACert._keys_match",
        "_spki_pub_matches",
        "CertificateBuilder.sign (issuer_pub)",
    ]
    for t in targets:
        # mark если в тексте нет прямых isinstance на типах ключей рядом
        # (грубая эвристика)
        marker = ""
        if t == "Cert.verify_signature" and "_verify_signed_data(\n            self.tbs_der" in src:
            marker = "\033[32m✓\033[0m"
        elif t == "CSR.verify_signature" and "_verify_signed_data(\n            self.cri_der" in src:
            marker = "\033[32m✓\033[0m"
        elif t == "CACert._keys_match" and "return _public_keys_equal(signing_key" in src:
            marker = "\033[32m✓\033[0m"
        elif t == "_spki_pub_matches" and "return _public_keys_equal(pub, key)" in src:
            marker = "\033[32m✓\033[0m"
        else:
            marker = "\033[33m·\033[0m"
        print(f"  {marker} {t}")

    print()
    print("=" * 72)
    print("Легенда: ✓ — через диспетчер, · — вероятно, ещё прямые isinstance")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())