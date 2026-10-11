# -*- coding: utf-8 -*-
"""
x509kit.cli — команды командной строки.

Установка entry point:
    pyproject.toml → [project.scripts]
        x509kit = "x509kit.cli:main"

После `pip install -e .` доступна команда `x509kit`.

Примеры:
    x509kit info cert.pem
    x509kit info https://example.com
    x509kit info -                       # из stdin
    x509kit keygen --type ed25519 --out key.pem
    x509kit keygen --type rsa --bits 4096 --password hunter2 --out key.pem
    x509kit csr info req.csr
    x509kit csr create --key key.pem --subject "CN=x.com, O=MyOrg" \\
        --san dns=x.com --san dns=www.x.com --out req.csr
    x509kit verify --ca ca.pem --untrusted inter.pem leaf.pem
    x509kit cms verify msg.p7s --ca ca.pem
    x509kit cms verify msg.p7s.sig --content data.bin --ca ca.pem
    x509kit pkcs12 info alice.p12 --password hunter2
    x509kit crl info revoked.crl.pem
    x509kit --version
"""

from __future__ import annotations

import argparse
import os
import sys

from .x509 import (
    Cert, CACert, CSR, CRL, PKCS12,
    RSAKeys, Ed25519Keys, ECDSAKeys,
    CSRBuilder,
    Name,
    X509Error,
)
from .cms import CMSSignedData
from . import __version__


# ======================================================================
#  helpers
# ======================================================================

def _eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def _tmpdir():
    """Кросс-платформенный tmp: TMPDIR → ~/.cache → cwd.

    На Termux /tmp обычно отсутствует, поэтому gettempdir() может
    бросить FileNotFoundError. Проверяем явно.
    """
    import tempfile
    for base in (os.environ.get("TMPDIR"),
                 os.path.expanduser("~/.cache"),
                 os.path.expanduser("~"),
                 os.getcwd()):
        if not base:
            continue
        try:
            os.makedirs(base, exist_ok=True)
            # Пробуем создать реальный temp
            test = tempfile.NamedTemporaryFile(dir=base, delete=True)
            test.close()
            return base
        except OSError:
            continue
    return None  # пусть tempfile решит сам


def _read_bytes(source):
    """Прочитать байты из файла, '-' = stdin."""
    if source == "-":
        return sys.stdin.buffer.read()
    with open(os.path.expanduser(source), "rb") as f:
        return f.read()


def _write_bytes(dest, data):
    """Записать байты в файл, '-' или None = stdout."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if dest in (None, "-"):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        path = os.path.expanduser(dest)
        with open(path, "wb") as f:
            f.write(data)
        try:
            if "PRIVATE KEY" in data[:200].decode("ascii", "ignore"):
                os.chmod(path, 0o600)
        except Exception:
            pass


def _load_private_key(source, password=None):
    """Попробовать три типа ключей по очереди."""
    data = _read_bytes(source)
    last_err = None
    for cls in (Ed25519Keys, RSAKeys, ECDSAKeys):
        try:
            return cls.from_pem(data, private=True, password=password)
        except Exception as e:
            last_err = e
            continue
    raise X509Error(f"cannot load private key from {source!r}: {last_err}")


def _parse_san_kv(s):
    """'dns=x.com' → ('dns', 'x.com')."""
    kind, sep, value = s.partition("=")
    if not sep or not kind.strip() or not value.strip():
        raise X509Error(
            f"--san must be KIND=VALUE, got {s!r}",
            "примеры: dns=example.com, ip=1.2.3.4, email=a@b, uri=https://x",
        )
    return kind.strip().lower(), value.strip()


# ======================================================================
#  info
# ======================================================================

def cmd_info(args):
    src = args.source
    if src.startswith(("http://", "https://")):
        cert = Cert.from_url(src, verify=args.verify)
    else:
        cert = Cert(_read_bytes(src))
    print(cert.info())
    return 0


# ======================================================================
#  keygen
# ======================================================================

def cmd_keygen(args):
    t = args.type
    if t == "rsa":
        key = RSAKeys.generate(args.bits)
    elif t == "ed25519":
        key = Ed25519Keys.generate()
    elif t == "ec":
        key = ECDSAKeys.generate(args.curve)
    else:
        _eprint(f"unknown key type: {t}")
        return 2

    pem = key.to_private_pem(password=args.password)
    _write_bytes(args.out, pem)
    if args.out not in (None, "-"):
        _eprint(f"wrote {args.out}")
    return 0


# ======================================================================
#  csr info / csr create
# ======================================================================

def cmd_csr_info(args):
    csr = CSR(_read_bytes(args.file))
    print(csr)
    return 0


def cmd_csr_create(args):
    key = _load_private_key(args.key, args.key_password)

    b = CSRBuilder()
    b.add_subject(Name.from_string(args.subject))
    b.add_public_key(key)

    for kv in (args.san or []):
        try:
            kind, value = _parse_san_kv(kv)
        except X509Error as e:
            _eprint(f"x509kit csr create: {e}")
            return 2
        if kind == "dns":
            b.add_san_dns(value)
        elif kind == "ip":
            b.add_san_ip(value)
        elif kind == "email":
            b.add_san_email(value)
        elif kind == "uri":
            b.add_san_uri(value)
        else:
            _eprint(f"unknown --san kind: {kind!r} (dns|ip|email|uri)")
            return 2

    csr = b.sign(key, hash_name=args.hash)
    _write_bytes(args.out, csr.to_pem())
    if args.out not in (None, "-"):
        _eprint(f"wrote {args.out}")
    return 0


# ======================================================================
#  verify
# ======================================================================

def cmd_verify(args):
    leaf = Cert(_read_bytes(args.leaf))
    anchor = CACert(_read_bytes(args.ca))

    chain = [leaf]
    for path in (args.untrusted or []):
        chain.append(Cert(_read_bytes(path)))

    try:
        ok = anchor.verify_chain(chain)
    except X509Error as e:
        _eprint(f"verify error: {e}")
        return 1

    if ok:
        print(f"{args.leaf}: OK")
        return 0
    _eprint(f"{args.leaf}: FAILED")
    return 1


# ======================================================================
#  cms verify
# ======================================================================

def cmd_cms_verify(args):
    sd = CMSSignedData.load(args.file)

    if sd.detached:
        if not args.content:
            _eprint("CMS is detached: --content PATH is required")
            return 2
        content = _read_bytes(args.content)
    else:
        content = None

    anchor = None
    if args.ca:
        anchor = CACert(_read_bytes(args.ca))

    ok = sd.verify(trust_anchor=anchor, detached_data=content)
    if ok:
        print(f"{args.file}: CMS OK"
              + (f" (signers={sd.signer_count})" if sd.signer_count else ""))
        return 0
    _eprint(f"{args.file}: CMS FAILED")
    return 1


# ======================================================================
#  pkcs12 info
# ======================================================================

def cmd_pkcs12_info(args):
    p = PKCS12.load(_read_bytes(args.file), password=args.password or "")
    print(f"MAC valid:    {p.verify_mac()}")
    print(f"Key type:     {type(p.key).__name__}")
    print(f"Cert subject: {p.cert.subject}")
    print(f"Cert issuer:  {p.cert.issuer}")
    print(f"Cert serial:  0x{p.cert.serial:x}")
    print(f"Chain length: {len(p.chain)}")
    return 0


# ======================================================================
#  crl info
# ======================================================================

def cmd_crl_info(args):
    crl = CRL(_read_bytes(args.file))
    print(crl)
    return 0


# ======================================================================
#  parser
# ======================================================================

def _build_parser():
    p = argparse.ArgumentParser(
        prog="x509kit",
        description="Pure-Python X.509 / CSR / CRL / OCSP / PKCS#12 / CMS toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example commands:\n"
            "  x509kit info cert.pem\n"
            "  x509kit info https://example.com\n"
            "  x509kit keygen --type ed25519 --out key.pem\n"
            "  x509kit csr create --key key.pem --subject 'CN=x.com' "
            "--san dns=x.com --out req.csr\n"
            "  x509kit verify --ca ca.pem --untrusted inter.pem leaf.pem\n"
            "  x509kit cms verify msg.p7s --ca ca.pem\n"
            "  x509kit pkcs12 info alice.p12 --password pw\n"
            "  x509kit crl info revoked.crl.pem\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"x509kit {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    # --- info ---
    c = sub.add_parser("info", help="Показать сертификат в стиле openssl x509 -text")
    c.add_argument("source",
                   help="файл сертификата, https://URL, или '-' (stdin)")
    c.add_argument("--verify", action="store_true",
                   help="проверять TLS-сертификат при fetch по URL")
    c.set_defaults(func=cmd_info)

    # --- keygen ---
    c = sub.add_parser("keygen", help="Сгенерировать приватный ключ")
    c.add_argument("--type", choices=["rsa", "ed25519", "ec"],
                   default="ed25519")
    c.add_argument("--bits", type=int, default=2048,
                   help="RSA size in bits (only for --type rsa)")
    c.add_argument("--curve", default="P-256",
                   choices=["P-256", "P-384", "P-521", "secp256k1"],
                   help="EC curve (only for --type ec)")
    c.add_argument("--password", default=None,
                   help="если задан — PKCS#8 EncryptedPrivateKeyInfo")
    c.add_argument("--out", default="-",
                   help="файл вывода; '-' или пусто = stdout")
    c.set_defaults(func=cmd_keygen)

    # --- csr info / create ---
    c = sub.add_parser("csr", help="PKCS#10 CSR: info или create")
    csr_sub = c.add_subparsers(dest="csr_action", required=True,
                                metavar="ACTION")

    ci = csr_sub.add_parser("info", help="Показать CSR")
    ci.add_argument("file")
    ci.set_defaults(func=cmd_csr_info)

    cc = csr_sub.add_parser("create", help="Создать CSR из приватного ключа")
    cc.add_argument("--key", required=True,
                    help="файл приватного ключа (PEM)")
    cc.add_argument("--key-password", default=None)
    cc.add_argument("--subject", required=True,
                    help="RFC 4514 DN, например 'CN=x.com, O=MyOrg, C=XX'")
    cc.add_argument("--san", action="append", default=[],
                    metavar="KIND=VALUE",
                    help="dns=x.com | ip=1.2.3.4 | email=a@b | uri=https://x")
    cc.add_argument("--hash", default="sha256",
                    choices=["sha256", "sha384", "sha512"])
    cc.add_argument("--out", default="-")
    cc.set_defaults(func=cmd_csr_create)

    # --- verify ---
    c = sub.add_parser("verify", help="Проверить цепочку сертификатов")
    c.add_argument("--ca", required=True, help="trust anchor (CA cert)")
    c.add_argument("--untrusted", action="append", default=[],
                   metavar="PATH", help="промежуточный сертификат (можно много)")
    c.add_argument("leaf", help="листовой сертификат")
    c.set_defaults(func=cmd_verify)

    # --- cms verify ---
    c = sub.add_parser("cms", help="CMS (RFC 5652) SignedData")
    cms_sub = c.add_subparsers(dest="cms_action", required=True,
                                metavar="ACTION")
    cv = cms_sub.add_parser("verify", help="Проверить CMS SignedData")
    cv.add_argument("file", help=".p7s / .p7m / CMS DER или PEM")
    cv.add_argument("--content", default=None,
                    help="content для detached CMS")
    cv.add_argument("--ca", default=None, help="trust anchor (опционально)")
    cv.set_defaults(func=cmd_cms_verify)

    # --- pkcs12 info ---
    c = sub.add_parser("pkcs12", help="PKCS#12 (.p12/.pfx)")
    p12_sub = c.add_subparsers(dest="p12_action", required=True,
                                metavar="ACTION")
    pi = p12_sub.add_parser("info", help="Показать PKCS#12")
    pi.add_argument("file")
    pi.add_argument("--password", default="")
    pi.set_defaults(func=cmd_pkcs12_info)

    # --- crl info ---
    c = sub.add_parser("crl", help="CRL (RFC 5280)")
    crl_sub = c.add_subparsers(dest="crl_action", required=True,
                                metavar="ACTION")
    cri = crl_sub.add_parser("info", help="Показать CRL")
    cri.add_argument("file")
    cri.set_defaults(func=cmd_crl_info)

    return p


# ======================================================================
#  main
# ======================================================================

def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        rc = args.func(args)
    except X509Error as e:
        _eprint(f"x509kit: {e}")
        return 1
    except (OSError, FileNotFoundError) as e:
        _eprint(f"x509kit: {e}")
        return 1
    return int(rc or 0)


if __name__ == "__main__":
    sys.exit(main())
