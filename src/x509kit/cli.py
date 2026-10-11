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
    Cert, CACert, CSR, CRL, PKCS12, CertBundle,
    RSAKeys, Ed25519Keys, ECDSAKeys,
    CertificateBuilder, CSRBuilder, CRLBuilder,
    Name,
    X509Error,
    _public_keys_equal,
    OCSPRequest, OCSPResponse,
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


def _add_san_entries(builder, sans):
    """Прокинуть ['dns=x', 'ip=1.2.3.4', ...] в builder.add_san_*."""
    for kv in (sans or []):
        try:
            kind, value = _parse_san_kv(kv)
        except X509Error as e:
            _eprint(f"x509kit: {e}")
            return False
        if kind == "dns":
            builder.add_san_dns(value)
        elif kind == "ip":
            builder.add_san_ip(value)
        elif kind == "email":
            builder.add_san_email(value)
        elif kind == "uri":
            builder.add_san_uri(value)
        else:
            _eprint(f"unknown --san kind: {kind!r} (dns|ip|email|uri)")
            return False
    return True


def _load_any_key(source, password=None):
    """Загрузить ключ, пробуя все типы и приватный/публичный.

    Возвращает объект ключа (RSAKeys / Ed25519Keys / ECDSAKeys).
    """
    data = _read_bytes(source)
    last = None
    # сначала приватный
    for cls in (Ed25519Keys, RSAKeys, ECDSAKeys):
        try:
            return cls.from_pem(data, private=True, password=password)
        except Exception as e:
            last = e
    # потом публичный
    for cls in (Ed25519Keys, RSAKeys, ECDSAKeys):
        try:
            return cls.from_pem(data, private=False)
        except Exception as e:
            last = e
    raise X509Error(f"cannot load key from {source!r}: {last}")


def _fmt_fingerprint(hex_str, colon=True):
    if not colon:
        return hex_str
    return ":".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)).upper()


def _parse_serial(s):
    """'0x1234' | '4660' → int."""
    s = str(s).strip()
    return int(s, 16) if s.startswith(("0x", "0X")) else int(s)


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

def cmd_cert_generate(args):
    """Самоподписанный сертификат из приватного ключа.

    Использование:
        x509kit cert generate --key k.pem --subject "CN=example.com" \
            --days 365 --san dns=example.com --out cert.pem
        x509kit cert generate --key k.pem --subject "CN=My CA" \
            --is-ca --path-len 0 --days 3650 --out ca.pem
    """
    key = _load_private_key(args.key, args.key_password)

    try:
        builder = CertificateBuilder(is_ca=bool(args.is_ca))
        builder.add_subject(Name.from_string(args.subject))
        builder.add_public_key(key)
        builder.add_serial_random()
        builder.add_validity(days=args.days)
        if args.is_ca:
            builder.add_basic_constraints(path_len=args.path_len)
            builder.add_key_usage("keyCertSign", "cRLSign")
        else:
            builder.add_basic_constraints()
            builder.add_key_usage("digitalSignature", "keyEncipherment")

        if not _add_san_entries(builder, args.san):
            return 2

        if args.eku:
            builder.add_extended_key_usage(*args.eku)

        if args.crl_dp:
            builder.add_crl_distribution_point(*args.crl_dp)

        if args.aia_ocsp or args.aia_issuers:
            builder.add_aia(ocsp=args.aia_ocsp, ca_issuers=args.aia_issuers)

        builder.self_signed()
        cert = builder.sign(key, hash_name=args.hash)
    except X509Error as e:
        _eprint(f"x509kit cert generate: {e}")
        return 1

    _write_bytes(args.out, cert.to_pem())
    if args.out not in (None, "-"):
        _eprint(f"wrote {args.out} (self-signed, "
                f"{'CA' if args.is_ca else 'leaf'})")
    return 0


def cmd_cert_sign(args):
    """Выпустить сертификат из CSR с помощью CA-ключа.

    Использование:
        x509kit cert sign --ca ca.pem --ca-key ca-key.pem \
            --csr req.csr --days 90 --out leaf.pem
    """
    ca = Cert(_read_bytes(args.ca))
    ca_key = _load_private_key(args.ca_key, args.ca_key_password)
    csr = CSR(_read_bytes(args.csr))

    if not csr.verify_signature():
        _eprint(f"x509kit cert sign: CSR signature is invalid")
        return 1

    try:
        builder = CertificateBuilder.from_csr(
            csr, is_ca=bool(args.is_ca),
            copy_extensions=not args.no_copy_ext,
        )
        builder.add_issuer(ca)
        builder.add_serial_random()
        builder.add_validity(days=args.days)
        if args.is_ca:
            builder.add_basic_constraints(path_len=args.path_len)
            builder.add_key_usage("keyCertSign", "cRLSign")
        else:
            builder.add_basic_constraints()
            if args.eku:
                builder.add_extended_key_usage(*args.eku)
        cert = builder.sign(ca_key, hash_name=args.hash)
    except X509Error as e:
        _eprint(f"x509kit cert sign: {e}")
        return 1

    _write_bytes(args.out, cert.to_pem())
    if args.out not in (None, "-"):
        _eprint(f"wrote {args.out} (issued by '{ca.subject}')")
    return 0


def cmd_cert_fingerprint(args):
    """Отпечаток сертификата: DER или SPKI."""
    import hashlib

    cert = Cert(_read_bytes(args.file))
    target = cert.spki_der if args.spki else cert.der
    h = hashlib.new(args.algo, target).hexdigest()
    print(_fmt_fingerprint(h, colon=not args.no_colon))
    return 0


def cmd_cert_chain(args):
    """Упорядочить цепочку сертификатов leaf → root."""
    data = _read_bytes(args.file)
    bundle = CertBundle.from_pem(data)
    if len(bundle) == 0:
        _eprint("x509kit cert chain: no certificates found")
        return 1
    sorted_b = bundle.sort_chain()
    pem = sorted_b.to_pem()
    if args.out in (None, "-"):
        sys.stdout.buffer.write(pem.encode())
        sys.stdout.buffer.flush()
    else:
        path = os.path.expanduser(args.out)
        with open(path, "w") as f:
            f.write(pem)
        _eprint(f"wrote {args.out} ({len(sorted_b)} certs, leaf → root)")
    return 0


def cmd_cert_matches_key(args):
    """Проверить, что приватный/публичный ключ соответствует сертификату."""
    cert = Cert(_read_bytes(args.cert))
    try:
        key = _load_any_key(args.key, args.key_password)
    except X509Error as e:
        _eprint(f"x509kit cert matches-key: {e}")
        return 1
    ok = _public_keys_equal(cert.public_key, key)
    if ok:
        print(f"{args.cert} matches {args.key}")
        return 0
    _eprint(f"{args.cert} does NOT match {args.key}")
    return 1


def cmd_key_info(args):
    """Распечатать информацию о ключе (PEM)."""
    try:
        key = _load_any_key(args.file, args.password)
    except X509Error as e:
        _eprint(f"x509kit key info: {e}")
        return 1
    print(f"Type:     {type(key).__name__}")
    print(f"Private:  {bool(key.is_private)}")
    if isinstance(key, RSAKeys):
        print(f"Bits:     {key.size_bits}")
        print(f"Exponent: {key.e} (0x{key.e:x})")
        if key.n:
            h = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big").hex()
            print(f"Modulus:  {h[:32]}…{h[-16:]}")
    elif isinstance(key, Ed25519Keys):
        print(f"Bits:     256")
        print(f"Public:   {key.pub.hex()}")
    elif isinstance(key, ECDSAKeys):
        curve_name = key.curve.get("name", key.curve_oid)
        print(f"Curve:    {curve_name} ({key.curve_oid})")
        print(f"Bits:     {key.size_bits}")
        x, y = key.point
        size = key.curve["size"]
        print(f"X:        {x.to_bytes(size, 'big').hex()}")
        print(f"Y:        {y.to_bytes(size, 'big').hex()}")
    return 0


def cmd_key_pub(args):
    """Извлечь публичный ключ из приватного (или вернуть публичный как есть)."""
    try:
        key = _load_any_key(args.file, args.password)
    except X509Error as e:
        _eprint(f"x509kit key pub: {e}")
        return 1
    pem = key.to_public_pem()
    _write_bytes(args.out, pem)
    if args.out not in (None, "-"):
        _eprint(f"wrote {args.out}")
    return 0


def cmd_key_convert(args):
    """PEM ↔ DER (тот же ключ, другая кодировка)."""
    try:
        key = _load_any_key(args.file, args.password)
    except X509Error as e:
        _eprint(f"x509kit key convert: {e}")
        return 1
    is_priv = key.is_private
    if args.format == "pem":
        data = key.to_private_pem() if is_priv else key.to_public_pem()
    else:  # der
        data = key.to_private_der() if is_priv else key.to_public_der()
    _write_bytes(args.out, data)
    if args.out not in (None, "-"):
        _eprint(f"wrote {args.out} ({'private' if is_priv else 'public'} "
                f"{args.format})")
    return 0


def cmd_csr_verify(args):
    """Проверить подпись PKCS#10 CSR."""
    csr = CSR(_read_bytes(args.file))
    if csr.verify_signature():
        print(f"{args.file}: OK")
        return 0
    _eprint(f"{args.file}: FAILED")
    return 1


def cmd_crl_create(args):
    """Выпустить CRL из CA-сертификата и ключа."""
    ca = Cert(_read_bytes(args.ca))
    ca_key = _load_private_key(args.ca_key, args.ca_key_password)

    b = CRLBuilder()
    b.set_issuer(ca)
    b.set_validity(days=args.days)
    if args.crl_number is not None:
        b.set_crl_number(args.crl_number)
    if args.hash:
        b.set_hash(args.hash)

    for s in (args.revoke or []):
        try:
            serial = _parse_serial(s)
        except ValueError:
            _eprint(f"x509kit crl create: bad serial {s!r}")
            return 2
        try:
            b.add_revoked(serial, reason=args.reason)
        except X509Error as e:
            _eprint(f"x509kit crl create: {e}")
            return 1

    try:
        crl = b.sign(ca_key)
    except X509Error as e:
        _eprint(f"x509kit crl create: {e}")
        return 1

    _write_bytes(args.out, crl.to_pem())
    if args.out not in (None, "-"):
        _eprint(f"wrote {args.out} ({len(crl.revoked)} revoked)")
    return 0


def cmd_p12_export(args):
    """Разложить .p12 в cert.pem / key.pem / chain.pem."""
    p = PKCS12.load(_read_bytes(args.file), password=args.password or "")

    outdir = os.path.expanduser(args.out_dir or ".")
    os.makedirs(outdir, exist_ok=True)

    cert_path = os.path.join(outdir, "cert.pem")
    key_path = os.path.join(outdir, "key.pem")
    chain_path = os.path.join(outdir, "chain.pem")

    with open(cert_path, "w") as f:
        f.write(p.cert.to_pem())
    with open(key_path, "w") as f:
        f.write(p.key.to_private_pem())
    os.chmod(key_path, 0o600)

    written = ["cert.pem", "key.pem"]
    if p.chain:
        with open(chain_path, "w") as f:
            f.write("".join(c.to_pem() for c in p.chain))
        written.append(f"chain.pem ({len(p.chain)})")

    _eprint(f"wrote {outdir}: " + ", ".join(written))
    return 0


def cmd_p12_create(args):
    """Собрать .p12 из key + cert (+ chain)."""
    key = _load_private_key(args.key, args.key_password)
    cert = Cert(_read_bytes(args.cert))
    chain = []
    if args.chain:
        b = CertBundle.from_pem(_read_bytes(args.chain))
        chain = list(b.certs)
    try:
        p12 = key.to_pkcs12(cert, chain=chain,
                             password=args.password or "",
                             name=args.name)
    except X509Error as e:
        _eprint(f"x509kit p12 create: {e}")
        return 1
    path = p12.save(args.out)
    _eprint(f"wrote {path}")
    return 0


def cmd_verify(args):
    leaf = Cert(_read_bytes(args.leaf))
    anchor = CACert(_read_bytes(args.ca))

    chain = [leaf]
    for path in (args.untrusted or []):
        chain.append(Cert(_read_bytes(path)))

    crl = None
    if getattr(args, "crl", None):
        try:
            crl = CRL(_read_bytes(args.crl))
        except X509Error as e:
            _eprint(f"x509kit verify: cannot read CRL: {e}")
            return 1

    ocsp_response = None
    if getattr(args, "ocsp_response", None):
        try:
            ocsp_response = OCSPResponse(_read_bytes(args.ocsp_response))
        except X509Error as e:
            _eprint(f"x509kit verify: cannot read OCSP response: {e}")
            return 1

    try:
        if len(chain) == 1:
            ok = anchor.verify_cert(leaf, crl=crl, ocsp_response=ocsp_response)
        else:
            ok = anchor.verify_chain(chain, crl=crl)
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

def cmd_version(args):
    """`x509kit version` — то же, что `x509kit --version`."""
    print(f"x509kit {__version__}")
    return 0


def cmd_hash(args):
    """`x509kit hash FILE [FILE...] [--algo sha256]` — hex-хэш файла.

    Полезно для скриптов: проверить sha256 сертификата без `sha256sum`.
    """
    import hashlib

    algo = args.algo
    if algo not in ("sha1", "sha224", "sha256", "sha384", "sha512"):
        _eprint(f"x509kit hash: unsupported algo {algo!r}")
        return 2

    rc = 0
    for src in args.files:
        try:
            data = _read_bytes(src)
        except OSError as e:
            _eprint(f"x509kit hash: {e}")
            rc = 1
            continue
        h = hashlib.new(algo, data).hexdigest()
        # GNU-style: "<hex>  <filename>"
        print(f"{h}  {src}")
    return rc


def _build_parser():
    p = argparse.ArgumentParser(
        prog="x509kit",
        description="Pure-Python X.509 / CSR / CRL / OCSP / PKCS#12 / CMS toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example commands:\n"
            "  x509kit version\n"
            "  x509kit info cert.pem\n"
            "  x509kit info https://example.com\n"
            "  x509kit hash cert.pem\n"
            "  x509kit cert generate --key k.pem --subject 'CN=x.com' "
            "--san dns=x.com --days 90 --out c.pem\n"
            "  x509kit cert sign --ca ca.pem --ca-key ca.key "
            "--csr req.csr --days 90 --out leaf.pem\n"
            "  x509kit cert fingerprint cert.pem\n"
            "  x509kit cert chain bundle.pem --out sorted.pem\n"
            "  x509kit cert matches-key cert.pem key.pem\n"
            "  x509kit key info key.pem\n"
            "  x509kit key pub key.pem --out pub.pem\n"
            "  x509kit key convert key.pem --format der --out key.der\n"
            "  x509kit csr verify req.csr\n"
            "  x509kit crl create --ca ca.pem --ca-key ca.key "
            "--revoke 0x1234 --days 7 --out crl.pem\n"
            "  x509kit p12 export alice.p12 --password pw --out-dir ./out\n"
            "  x509kit p12 create --key k.pem --cert c.pem "
            "--password pw --out alice.p12\n"
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

    sub = p.add_subparsers(dest="cmd", required=False, metavar="COMMAND")

    # --- version (подкоманда) ---
    c = sub.add_parser("version",
                       help="Показать версию (то же, что --version)")
    c.set_defaults(func=cmd_version)

    # --- hash (файл → hex-хэш) ---
    c = sub.add_parser("hash", help="Хэш файлов (по умолчанию SHA-256)")
    c.add_argument("files", nargs="+",
                   help="файлы; '-' = stdin")
    c.add_argument("--algo", default="sha256",
                   choices=["sha1", "sha224", "sha256", "sha384", "sha512"])
    c.set_defaults(func=cmd_hash)

    # --- cert generate / cert sign ---
    c = sub.add_parser("cert", help="Сертификаты: generate / sign")
    cert_sub = c.add_subparsers(dest="cert_action", required=True,
                                 metavar="ACTION")

    cg = cert_sub.add_parser("generate",
                             help="Самоподписанный сертификат из ключа")
    cg.add_argument("--key", required=True, help="приватный ключ PEM")
    cg.add_argument("--key-password", default=None)
    cg.add_argument("--subject", required=True,
                    help="RFC 4514 DN, напр. 'CN=example.com, O=MyOrg'")
    cg.add_argument("--days", type=int, default=365)
    cg.add_argument("--san", action="append", default=[],
                    metavar="KIND=VALUE",
                    help="dns=x.com | ip=1.2.3.4 | email=a@b | uri=https://x")
    cg.add_argument("--is-ca", action="store_true",
                    help="CA:TRUE + keyCertSign (для root CA)")
    cg.add_argument("--path-len", type=int, default=None,
                    help="BasicConstraints.path_len (только для --is-ca)")
    cg.add_argument("--eku", action="append", default=[],
                    help="serverAuth | clientAuth | codeSigning | ...")
    cg.add_argument("--crl-dp", action="append", default=[],
                    metavar="URL", help="CRL Distribution Point URL")
    cg.add_argument("--aia-ocsp", action="append", default=[],
                    metavar="URL", help="AIA OCSP responder URL")
    cg.add_argument("--aia-issuers", action="append", default=[],
                    metavar="URL", help="AIA CA Issuers URL")
    cg.add_argument("--hash", default="sha256",
                    choices=["sha256", "sha384", "sha512"])
    cg.add_argument("--out", default="-")
    cg.set_defaults(func=cmd_cert_generate)

    cs = cert_sub.add_parser("sign", help="Выпустить сертификат из CSR (CA)")
    cs.add_argument("--ca", required=True, help="CA-сертификат (PEM)")
    cs.add_argument("--ca-key", required=True, help="приватный ключ CA")
    cs.add_argument("--ca-key-password", default=None)
    cs.add_argument("--csr", required=True, help="PKCS#10 CSR")
    cs.add_argument("--days", type=int, default=365)
    cs.add_argument("--is-ca", action="store_true",
                    help="выпустить sub-CA (CA:TRUE + keyCertSign)")
    cs.add_argument("--path-len", type=int, default=None)
    cs.add_argument("--eku", action="append", default=[],
                    help="serverAuth | clientAuth | ...")
    cs.add_argument("--no-copy-ext", action="store_true",
                    help="не копировать extensions из CSR (SAN и др.)")
    cs.add_argument("--hash", default="sha256",
                    choices=["sha256", "sha384", "sha512"])
    cs.add_argument("--out", default="-")
    cs.set_defaults(func=cmd_cert_sign)

    # cert info — алиас на верхнеуровневый info
    ci = cert_sub.add_parser("info", help="Показать сертификат (openssl x509 -text)")
    ci.add_argument("source", help="файл, URL или '-'")
    ci.add_argument("--verify", action="store_true",
                    help="проверять TLS при fetch по URL")
    ci.set_defaults(func=cmd_info)

    # cert verify — алиас на верхнеуровневый verify
    cv = cert_sub.add_parser("verify", help="Проверить цепочку")
    cv.add_argument("--ca", required=True, help="trust anchor (CA cert)")
    cv.add_argument("--untrusted", action="append", default=[],
                    metavar="PATH", help="промежуточный сертификат (можно много)")
    cv.add_argument("--crl", default=None, help="CRL для проверки отзыва")
    cv.add_argument("--ocsp-response", default=None,
                    help="OCSP-ответ (DER) для проверки отзыва")
    cv.add_argument("leaf")
    cv.set_defaults(func=cmd_verify)

    # cert fingerprint
    cf = cert_sub.add_parser("fingerprint", help="Отпечаток сертификата")
    cf.add_argument("file")
    cf.add_argument("--algo", default="sha256",
                    choices=["sha1", "sha224", "sha256", "sha384", "sha512"])
    cf.add_argument("--spki", action="store_true",
                    help="отпечаток SPKI, а не всего DER")
    cf.add_argument("--no-colon", action="store_true",
                    help="без двоеточий (для скриптов)")
    cf.set_defaults(func=cmd_cert_fingerprint)

    # cert chain
    cc = cert_sub.add_parser("chain", help="Упорядочить цепочку leaf → root")
    cc.add_argument("file", help="PEM с несколькими сертификатами")
    cc.add_argument("--out", default="-")
    cc.set_defaults(func=cmd_cert_chain)

    # cert matches-key
    cm = cert_sub.add_parser("matches-key",
                             help="Ключ соответствует сертификату?")
    cm.add_argument("cert")
    cm.add_argument("key")
    cm.add_argument("--key-password", default=None)
    cm.set_defaults(func=cmd_cert_matches_key)

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

    # --- key: info / pub / convert ---
    c = sub.add_parser("key", help="Приватные/публичные ключи: info / pub / convert")
    key_sub = c.add_subparsers(dest="key_action", required=True,
                                metavar="ACTION")

    ki = key_sub.add_parser("info", help="Информация о ключе")
    ki.add_argument("file")
    ki.add_argument("--password", default=None)
    ki.set_defaults(func=cmd_key_info)

    kp = key_sub.add_parser("pub", help="Извлечь публичный ключ")
    kp.add_argument("file")
    kp.add_argument("--password", default=None)
    kp.add_argument("--out", default="-")
    kp.set_defaults(func=cmd_key_pub)

    kc = key_sub.add_parser("convert", help="PEM ↔ DER")
    kc.add_argument("file")
    kc.add_argument("--password", default=None)
    kc.add_argument("--format", choices=["pem", "der"], default="pem")
    kc.add_argument("--out", default="-")
    kc.set_defaults(func=cmd_key_convert)

    # --- csr info / create ---
    c = sub.add_parser("csr", help="PKCS#10 CSR: info или create")
    csr_sub = c.add_subparsers(dest="csr_action", required=True,
                                metavar="ACTION")

    ci = csr_sub.add_parser("info", help="Показать CSR")
    ci.add_argument("file")
    ci.set_defaults(func=cmd_csr_info)

    cv = csr_sub.add_parser("verify", help="Проверить подпись CSR")
    cv.add_argument("file")
    cv.set_defaults(func=cmd_csr_verify)

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
    c.add_argument("--crl", default=None, help="CRL для проверки отзыва")
    c.add_argument("--ocsp-response", default=None,
                   help="OCSP-ответ (DER) для проверки отзыва")
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
    c = sub.add_parser("pkcs12", aliases=["p12"],
                        help="PKCS#12 (.p12/.pfx); алиас: p12")
    p12_sub = c.add_subparsers(dest="p12_action", required=True,
                                metavar="ACTION")
    pi = p12_sub.add_parser("info", help="Показать PKCS#12")
    pi.add_argument("file")
    pi.add_argument("--password", default="")
    pi.set_defaults(func=cmd_pkcs12_info)

    pe = p12_sub.add_parser("export", help="Разложить .p12 в cert/key/chain")
    pe.add_argument("file")
    pe.add_argument("--password", default="")
    pe.add_argument("--out-dir", default=".", metavar="DIR",
                    help="куда положить cert.pem / key.pem / chain.pem")
    pe.set_defaults(func=cmd_p12_export)

    pc = p12_sub.add_parser("create", help="Собрать .p12 из key + cert")
    pc.add_argument("--key", required=True)
    pc.add_argument("--key-password", default=None)
    pc.add_argument("--cert", required=True, help="листовой сертификат PEM")
    pc.add_argument("--chain", default=None,
                    help="файл с промежуточными сертификатами")
    pc.add_argument("--password", default="")
    pc.add_argument("--name", default=None,
                    help="friendlyName (по умолчанию CN из cert)")
    pc.add_argument("--out", required=True)
    pc.set_defaults(func=cmd_p12_create)

    # --- crl info ---
    c = sub.add_parser("crl", help="CRL (RFC 5280)")
    crl_sub = c.add_subparsers(dest="crl_action", required=True,
                                metavar="ACTION")
    cri = crl_sub.add_parser("info", help="Показать CRL")
    cri.add_argument("file")
    cri.set_defaults(func=cmd_crl_info)

    crc = crl_sub.add_parser("create", help="Выпустить CRL")
    crc.add_argument("--ca", required=True, help="CA-сертификат")
    crc.add_argument("--ca-key", required=True, help="приватный ключ CA")
    crc.add_argument("--ca-key-password", default=None)
    crc.add_argument("--revoke", action="append", default=[],
                     metavar="SERIAL",
                     help="серийник отозванного (можно много; 0x-hex или dec)")
    crc.add_argument("--reason", default=None,
                     help="причина отзыва (keyCompromise и т.п.)")
    crc.add_argument("--days", type=int, default=7)
    crc.add_argument("--crl-number", type=int, default=None)
    crc.add_argument("--hash", default="sha256",
                     choices=["sha256", "sha384", "sha512"])
    crc.add_argument("--out", default="-")
    crc.set_defaults(func=cmd_crl_create)

    return p


# ======================================================================
#  main
# ======================================================================

def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Без команды — печатаем справку и выходим с кодом 0.
    # Так `x509kit` ведёт себя как `git` / `openssl` без аргументов.
    if getattr(args, "cmd", None) is None:
        parser.print_help()
        return 0

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
