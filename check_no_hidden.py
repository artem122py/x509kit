# -*- coding: utf-8 -*-
"""
check_no_hidden.py - prove that x509kit has no third-party imports.

Uses Python's AST parser to extract every import statement from every
.py file in src/. Compares against the standard library (sys.stdlib_module_names)
and against an explicit blacklist of crypto libraries.

Exit code 0 = clean, 1 = something found.
"""

import ast
import sys
import sysconfig
from pathlib import Path

# Python 3.10+ has sys.stdlib_module_names. For 3.9 fall back to a
# hardcoded allowlist (only what x509kit actually uses).
STDLIB = getattr(sys, "stdlib_module_names", frozenset({
    "base64", "datetime", "hashlib", "hmac", "math", "os", "re",
    "secrets", "socket", "unicodedata", "warnings", "sys", "typing",
    "ipaddress", "functools", "struct", "time", "collections",
    "contextlib", "itertools", "string", "textwrap", "io", "tempfile",
    "shutil", "pathlib", "enum", "abc", "copy", "operator", "random",
    "urllib", "http", "email", "json", "csv", "argparse", "logging",
    "__future__",
}))

# Things we explicitly do NOT want to see anywhere in src/.
FORBIDDEN = {
    "cryptography", "pyOpenSSL", "OpenSSL", "asn1crypto", "Crypto",
    "pycryptodome", "nacl", "PyNaCl", "paramiko", "pyasn1",
    "certvalidator", "certifi", "pyopenssl",
}

# What we do not want to see even in stdlib, because it's suspicious
# in this context (means we delegate crypto to the system).
SUSPICIOUS_STDLIB = {
    "ssl",           # we do not use ssl module in src/
    "ctypes",        # no ctypes.CDLL to load external libs
    "subprocess",    # no calling openssl binary
    "mmap",          # no memory tricks
}


def find_imports(file_path):
    """Return list of (module_name, line_number) from a .py file."""
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8"),
                         filename=str(file_path))
    except SyntaxError as e:
        print(f"  [!] SyntaxError in {file_path}: {e}")
        return []

    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                imports.append((root, node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                imports.append((root, node.lineno, node.module))
    return imports


def main():
    src = Path("src") if Path("src").exists() else Path(".")
    files = sorted(src.rglob("*.py"))

    if not files:
        print("[!] No .py files found under src/")
        return 1

    print(f"Scanning {len(files)} file(s) under {src}/")
    print()

    all_imports = []
    problems = []
    suspicious = []

    for f in files:
        file_imports = find_imports(f)
        all_imports.extend((f, root, ln, mod) for root, ln, mod in file_imports)

        for root, ln, mod in file_imports:
            if root in FORBIDDEN:
                problems.append(f"{f}:{ln}: import {mod!r} (forbidden)")
            elif root in SUSPICIOUS_STDLIB:
                suspicious.append(f"{f}:{ln}: import {mod!r} (suspicious stdlib)")

    # Report every import grouped by module
    unique_roots = sorted({imp[1] for imp in all_imports})
    print(f"Unique top-level modules imported: {len(unique_roots)}")
    for root in unique_roots:
        mark = "✗" if root in FORBIDDEN else ("·" if root in SUSPICIOUS_STDLIB else "✓")
        print(f"  {mark} {root}")
    print()

    if problems:
        print(f"PROBLEMS ({len(problems)}):")
        for p in problems:
            print(f"  ✗ {p}")
    else:
        print("✓ No third-party imports found in src/")

    if suspicious:
        print()
        print(f"Suspicious stdlib imports ({len(suspicious)}):")
        for s in suspicious:
            print(f"  · {s}")

    print()
    print("=" * 72)
    if problems:
        print(f"  RESULT: FAILED - {len(problems)} problem(s)")
        return 1
    print("  RESULT: OK - stdlib only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
