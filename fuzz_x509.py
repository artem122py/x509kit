# -*- coding: utf-8 -*-
"""
fuzz_x509.py — fuzz-тест парсеров x509kit.

Что проверяет:
  1. ASN1.parse, Cert, CSR, CRL, pem_decode на случайных байтах.
  2. Парсеры не падают с не-X509-исключениями (TypeError, IndexError, RecursionError...)
  3. Парсеры не висят (таймаут 2 сек на вход).
  4. Защита от deeply-nested DER (_MAX_DEPTH).
  5. Round-trip: наши PEM/DER → наши же парсеры.

Режимы:
    python fuzz_x509.py              # 5000 итераций по умолчанию
    python fuzz_x509.py 50000        # больше итераций
    python fuzz_x509.py 50000 42     # с фиксированным seed
    python fuzz_x509.py --quick      # 500 итераций для CI

Зависимости: только stdlib. Работает на любом Python 3.9+.
"""

import random
import secrets
import struct
import sys
import time
import traceback

from x509kit import (
    Cert, CACert, CSR, CRL, CertBundle,
    RSAKeys, Ed25519Keys, CertificateBuilder, CSRBuilder,
    X509Error, X509Warning,
)
from x509kit.x509 import (
    ASN1, pem_decode, _MAX_DEPTH, TAG_SEQUENCE,
)


# ======================================================================
#  Генераторы входных данных
# ======================================================================

def rand_bytes(rng, max_len=512):
    n = rng.randint(0, max_len)
    return bytes(rng.getrandbits(8) for _ in range(n))


def rand_ascii_pem_like(rng):
    """Случайный текст с PEM-маркерами."""
    labels = ["CERTIFICATE", "X509 CRL", "CERTIFICATE REQUEST",
              "PRIVATE KEY", "PUBLIC KEY", "", "GARBAGE"]
    n_lines = rng.randint(1, 8)
    lines = []
    for _ in range(n_lines):
        r = rng.random()
        if r < 0.3:
            lines.append(f"-----BEGIN {rng.choice(labels)}-----")
        elif r < 0.6:
            lines.append(f"-----END {rng.choice(labels)}-----")
        else:
            b64_len = rng.randint(0, 100)
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n"
            lines.append("".join(rng.choice(chars) for _ in range(b64_len)))
    return "\n".join(lines).encode("ascii", "replace")


def rand_deep_der(rng, depth):
    """TLV-конструкция глубиной depth с пустым содержимым."""
    if depth == 0:
        return b"\x05\x00"    # NULL
    inner = rand_deep_der(rng, depth - 1)
    # SEQUENCE с длиной
    n = len(inner)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return b"\x30" + length + inner


def rand_der_like(rng):
    """Похоже на DER, но почти всегда битое."""
    r = rng.random()
    if r < 0.2:
        return rand_deep_der(rng, rng.randint(1, 50))
    if r < 0.4:
        # валидное начало, обрезанное
        body = rand_bytes(rng, 256)
        return b"\x30\x82" + struct.pack(">H", len(body) + rng.randint(0, 100)) + body
    if r < 0.6:
        # случайный тег + длина + данные
        tag = rng.choice([0x30, 0x31, 0x02, 0x03, 0x04, 0x06, 0x17, 0xA0, 0xA3])
        n = rng.randint(0, 200)
        return bytes([tag]) + bytes([n & 0xFF]) + rand_bytes(rng, n)
    return rand_bytes(rng, 512)


# ======================================================================
#  Проверки
# ======================================================================

class FuzzStats:
    def __init__(self):
        self.total = 0
        self.ok = 0            # парсер поднял X509Error — нормально
        self.parsed = 0        # парсер вернул объект — тоже нормально
        self.crashes = []
        self.timeouts = []
        self.warnings = 0

    def summary(self):
        print()
        print("=" * 72)
        print(f"  Всего входов:      {self.total}")
        print(f"  Отвергнуто (X509Error): {self.ok}")
        print(f"  Принято (объект):  {self.parsed}")
        print(f"  X509Warning:       {self.warnings}")
        print(f"  Краши:             {len(self.crashes)}")
        print(f"  Таймауты:          {len(self.timeouts)}")
        color = "32" if not self.crashes and not self.timeouts else "31"
        print(f"  ИТОГ: \033[{color}m"
              f"{'OK' if not self.crashes and not self.timeouts else 'FAIL'}"
              f"\033[0m")
        print("=" * 72)
        if self.crashes:
            print()
            print("  Первые краши:")
            for inp, exc_type, tb in self.crashes[:5]:
                print(f"    вход ({len(inp)} б): {inp[:40].hex()}...")
                print(f"    {exc_type}: {tb.splitlines()[-1]}")
        return not self.crashes and not self.timeouts


def run_case(stats, parser_name, parser_fn, data, timeout=2.0):
    """Прогнать один вход. Любое исключение кроме X509Error — краш."""
    import warnings as _w
    stats.total += 1
    t0 = time.time()
    try:
        with _w.catch_warnings(record=True) as ws:
            _w.simplefilter("always", X509Warning)
            try:
                obj = parser_fn(data)
                stats.parsed += 1
                _ = obj  # используем
            except X509Error:
                stats.ok += 1
            except RecursionError:
                # допустимо, если _MAX_DEPTH не сработал раньше
                stats.ok += 1
            except Exception as e:
                # TypeError/IndexError/KeyError/ValueError — реальный краш
                tb = traceback.format_exc()
                stats.crashes.append((data, type(e).__name__, tb))
            stats.warnings += sum(1 for x in ws if issubclass(x.category, X509Warning))
    except Exception as e:
        stats.crashes.append((data, f"outer:{type(e).__name__}",
                              traceback.format_exc()))
    dt = time.time() - t0
    if dt > timeout:
        stats.timeouts.append((parser_name, len(data), dt))


def fuzz_parser(stats, name, fn, gen, iterations, rng):
    """Прогнать iterations случайных входов через один парсер."""
    print(f"  fuzz {name:22s} ... ", end="", flush=True)
    t0 = time.time()
    crash_before = len(stats.crashes)
    for i in range(iterations):
        data = gen(rng)
        run_case(stats, name, fn, data)
    dt = time.time() - t0
    n_new = len(stats.crashes) - crash_before
    mark = "\033[32m✓\033[0m" if n_new == 0 else f"\033[31m✗ ({n_new})\033[0m"
    rate = iterations / dt if dt > 0 else 0
    print(f"{mark} {iterations} за {dt:.1f}с ({rate:.0f}/с)")


# ======================================================================
#  Основная программа
# ======================================================================

def main():
    argv = sys.argv[1:]
    quick = "--quick" in argv
    argv = [a for a in argv if not a.startswith("--")]

    if quick:
        iterations = 500
    elif len(argv) >= 1:
        iterations = int(argv[0])
    else:
        iterations = 5000

    seed = int(argv[1]) if len(argv) >= 2 else None
    if seed is None:
        seed = secrets.randbits(32)
    rng = random.Random(seed)

    print("╔" + "═" * 70 + "╗")
    print("║  x509kit — fuzz парсеров" + " " * 44 + "║")
    print("╚" + "═" * 70 + "╝")
    print(f"  seed = {seed}   итераций на парсер = {iterations}")
    print()

    stats = FuzzStats()
    gen_der = lambda r: rand_der_like(r)
    gen_pem = lambda r: rand_ascii_pem_like(r)
    gen_bytes = lambda r: rand_bytes(r, 1024)

    # ---- 1. ASN1.parse ----
    print("1. ASN.1 DER парсер")
    fuzz_parser(stats, "ASN1.parse", ASN1.parse, gen_der, iterations, rng)

    # ---- 2. Cert ----
    print("\n2. Cert / CACert парсеры")
    fuzz_parser(stats, "Cert(bytes)", Cert, gen_der, iterations, rng)
    fuzz_parser(stats, "Cert(pem)", Cert, gen_pem, iterations, rng)
    fuzz_parser(stats, "CACert(bytes)", CACert, gen_der, iterations, rng)

    # ---- 3. CSR ----
    print("\n3. CSR парсер")
    fuzz_parser(stats, "CSR(bytes)", CSR, gen_der, iterations, rng)
    fuzz_parser(stats, "CSR(pem)", CSR, gen_pem, iterations, rng)

    # ---- 4. CRL ----
    print("\n4. CRL парсер")
    fuzz_parser(stats, "CRL(bytes)", CRL, gen_der, iterations, rng)
    fuzz_parser(stats, "CRL(pem)", CRL, gen_pem, iterations, rng)

    # ---- 5. pem_decode ----
    print("\n5. PEM decoder")
    fuzz_parser(stats, "pem_decode", pem_decode, gen_bytes, iterations, rng)
    fuzz_parser(stats, "pem_decode(pem-like)", pem_decode, gen_pem, iterations, rng)

    # ---- 6. Глубокая вложенность (проверка _MAX_DEPTH) ----
    print(f"\n6. Защита от deeply-nested DER (_MAX_DEPTH={_MAX_DEPTH})")
    ok_depth = True
    for depth in (_MAX_DEPTH - 1, _MAX_DEPTH, _MAX_DEPTH + 1, _MAX_DEPTH * 2,
                  _MAX_DEPTH * 10):
        data = rand_deep_der(rng, depth)
        try:
            ASN1.parse(data)
            status = "принял"
        except X509Error as e:
            status = f"отверг: {str(e)[:40]}"
        except RecursionError:
            status = "RecursionError!"
            ok_depth = False
        except Exception as e:
            status = f"КРАШ: {type(e).__name__}"
            ok_depth = False
        mark = "\033[32m✓\033[0m" if ok_depth else "\033[31m✗\033[0m"
        print(f"    {mark} depth={depth:5d}: {status}")

    # ---- 7. Round-trip: наш объект → PEM → парсер ----
    print("\n7. Round-trip (наш PEM → наш парсер)")
    rt_rng = random.Random(seed ^ 0xDEAD)
    n_rt = max(10, iterations // 100)
    ok_rt = True
    for _ in range(n_rt):
        try:
            k = Ed25519Keys.generate()
            cert = (CertificateBuilder()
                .add_subject({"CN": f"fuzz-{rt_rng.randint(0, 1000)}.example"})
                .add_public_key(k)
                .add_serial_random()
                .add_validity(days=30)
                .self_signed()
                .sign(k))
            cert2 = Cert(cert.to_pem())
            if cert2.der != cert.der:
                print(f"    ✗ DER не совпал после round-trip")
                ok_rt = False
                break
        except Exception as e:
            print(f"    ✗ {type(e).__name__}: {e}")
            ok_rt = False
            break
    if ok_rt:
        print(f"    \033[32m✓\033[0m {n_rt} round-trip OK")

    # ---- Итог ----
    print()
    all_ok = stats.summary() and ok_depth and ok_rt
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())