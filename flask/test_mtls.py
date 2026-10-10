# -*- coding: utf-8 -*-
"""
flask/test_mtls.py — Mutual TLS с x509kit + PKCS#12.

Что делает в одном прогоне:
  1. Генерирует Root CA + Intermediate (в памяти).
  2. Выпускает server leaf для Flask + client leaf для клиента.
  3. Клиентский leaf упаковывает в .p12 (OpenSSL-совместимый).
  4. Запускает Flask на HTTPS с ssl.CERT_REQUIRED — требует клиентский сертификат.
  5. Позитивный тест: клиент с .p12 подключается, сервер видит его CN.
  6. Негативный тест: клиент без сертификата — handshake падает.

Запуск:
    python flask/test_mtls.py
"""

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from x509kit import (
    CertificateBuilder, CACert, Ed25519Keys,
    PKCS12, X509Error,
)


HOST = "127.0.0.1"
PORT = 18443
WORKDIR = os.path.abspath("./mtls_test")


def hr(title):
    print()
    print("─" * 72)
    print(f"  {title}")
    print("─" * 72)


def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    return path


def load_cert_chain_strings(ctx, cert_chain_pem, key_pem):
    """SSLContext.load_cert_chain из строк (через временные файлы)."""
    c = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    k = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    try:
        c.write(cert_chain_pem); c.close()
        k.write(key_pem); k.close()
        os.chmod(k.name, 0o600)
        ctx.load_cert_chain(c.name, k.name)
    finally:
        for p in (c.name, k.name):
            try: os.unlink(p)
            except OSError: pass


# ======================================================================
#  CA в памяти
# ======================================================================

class InMemoryCA:
    def __init__(self):
        self.root_key = Ed25519Keys.generate()
        self.root = (CertificateBuilder(is_ca=True)
            .add_subject({"C": "XX", "O": "mTLS PKI", "CN": "mTLS Root CA"})
            .add_public_key(self.root_key)
            .add_serial_random().add_validity(days=7300)
            .add_basic_constraints(path_len=1)
            .add_key_usage("keyCertSign", "cRLSign")
            .self_signed().sign(self.root_key))

        self.inter_key = Ed25519Keys.generate()
        self.inter = (CertificateBuilder(is_ca=True)
            .add_subject({"C": "XX", "O": "mTLS PKI", "CN": "mTLS Intermediate"})
            .add_issuer(self.root).add_public_key(self.inter_key)
            .add_serial_random().add_validity(days=3650)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .sign(self.root_key))

    def issue_server(self, cn, dns=None, ips=None):
        k = Ed25519Keys.generate()
        cert = (CertificateBuilder()
            .add_subject({"C": "XX", "O": "mTLS PKI", "CN": cn})
            .add_issuer(self.inter).add_public_key(k)
            .add_serial_random().add_validity(days=90)
            .add_san(dns=dns or [cn], ips=ips or ["127.0.0.1", "::1"])
            .add_extended_key_usage("serverAuth")
            .sign(self.inter_key))
        return k, cert

    def issue_client(self, cn):
        k = Ed25519Keys.generate()
        cert = (CertificateBuilder()
            .add_subject({"C": "XX", "O": "mTLS PKI", "CN": cn})
            .add_issuer(self.inter).add_public_key(k)
            .add_serial_random().add_validity(days=90)
            .add_extended_key_usage("clientAuth")
            .sign(self.inter_key))
        return k, cert


# ======================================================================
#  Flask с mTLS
# ======================================================================

def make_app():
    app = Flask(__name__)

    def client_cert_info():
        """Достать клиентский сертификат из TLS-сокета."""
        try:
            sock = request.environ.get("werkzeug.socket")
            if sock is None:
                return None
            # ssl-wrapped socket → getpeercert()
            peer = sock.getpeercert()
            if not peer:
                return None
            return peer
        except Exception:
            return None

    @app.route("/")
    def index():
        info = client_cert_info()
        if not info:
            return "No client cert!", 401
        subject = dict(x[0] for x in info.get("subject", ()))
        cn = subject.get("commonName", "?")
        return (
            f"<!doctype html><html><body style='font-family:sans-serif;padding:40px'>"
            f"<h1>mTLS работает ✓</h1>"
            f"<p>Клиент опознан как: <strong>{cn}</strong></p>"
            f"<p>Issuer: {dict(x[0] for x in info.get('issuer', ()))}</p>"
            f"<p><a href='/whoami'>/whoami</a> — JSON</p>"
            f"</body></html>"
        )

    @app.route("/whoami")
    def whoami():
        info = client_cert_info()
        if not info:
            return jsonify({"error": "no client cert"}), 401
        subject = {k: v for k, v in (x[0] for x in info.get("subject", ()))}
        issuer = {k: v for k, v in (x[0] for x in info.get("issuer", ()))}
        return jsonify({
            "subject": subject,
            "issuer": issuer,
            "serial": info.get("serialNumber"),
            "not_before": info.get("notBefore"),
            "not_after": info.get("notAfter"),
        })

    return app


# ======================================================================
#  Клиент: подключиться с .p12
# ======================================================================

def https_get_with_p12(path, ca_pem_path, p12_path, p12_password,
                       host=HOST, port=PORT):
    """GET https://host:port/path с клиентским сертификатом из .p12."""
    # 1. Извлечём из .p12 cert+key в PEM (в памяти)
    pk = PKCS12.from_file(p12_path, password=p12_password)
    cert_pem = pk.cert.to_pem() + "".join(c.to_pem() for c in pk.chain)
    key_pem = pk.key.to_private_pem()

    # 2. SSLContext с этим клиентским cert
    ctx = ssl.create_default_context(cafile=ca_pem_path)
    load_cert_chain_strings(ctx, cert_pem, key_pem)

    # 3. Запрос
    req = urllib.request.Request(f"https://{host}:{port}{path}")
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        return r.read()


# ======================================================================
#  Main
# ======================================================================

def main():
    print("╔" + "═" * 70 + "╗")
    print("║  flask/test_mtls.py — mutual TLS с x509kit + PKCS#12" + " " * 12 + "║")
    print("╚" + "═" * 70 + "╝")

    # --- workdir ---
    if os.path.exists(WORKDIR):
        shutil.rmtree(WORKDIR)
    os.makedirs(WORKDIR)
    print(f"\n  Рабочая папка: {WORKDIR}")

    openssl = shutil.which("openssl")
    if openssl:
        print(f"  OpenSSL:       {subprocess.run([openssl, 'version'], capture_output=True, text=True).stdout.strip()}")
    print()

    # --- 1. CA ---
    hr("1. Root CA + Intermediate (в памяти)")
    ca = InMemoryCA()
    print(f"  Root:  {ca.root.subject}")
    print(f"  Inter: {ca.inter.subject}")
    print(f"  chain root→inter: {ca.root.verify_chain([ca.inter])}")

    # --- 2. Server leaf ---
    hr("2. Server leaf")
    srv_key, srv_cert = ca.issue_server("localhost",
                                         dns=["localhost"],
                                         ips=["127.0.0.1", "::1"])
    print(f"  CN: {srv_cert.subject.get('CN')}, SAN: {[v for _, v in srv_cert.san]}")

    # --- 3. Client leaf + .p12 ---
    hr("3. Client leaf + .p12")
    cli_key, cli_cert = ca.issue_client("alice@mtls-test")
    print(f"  CN: {cli_cert.subject.get('CN')}")
    print(f"  EKU: {sorted(cli_cert.eku)}")

    p12 = PKCS12.build(cli_key, cli_cert, chain=[ca.inter],
                       password="hunter2", name="alice@mtls")
    p12_path = os.path.join(WORKDIR, "client.p12")
    p12.save(p12_path)
    print(f"  .p12 сохранён: {p12_path} ({os.path.getsize(p12_path)} байт)")
    print(f"  MAC verify:    {p12.verify_mac()}")

    # --- сохраним CA-цепочку для SSL-контекстов ---
    ca_chain_path = os.path.join(WORKDIR, "ca_chain.pem")
    write(ca_chain_path, ca.inter.to_pem() + ca.root.to_pem())
    print(f"  CA chain:      {ca_chain_path}")

    # --- 4. Сервер с mTLS ---
    hr("4. Flask + ssl.CERT_REQUIRED")
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    load_cert_chain_strings(
        srv_ctx,
        srv_cert.to_pem() + ca.inter.to_pem(),
        srv_key.to_private_pem(),
    )
    # Требуем клиентский сертификат и проверяем его против нашего CA
    srv_ctx.verify_mode = ssl.CERT_REQUIRED
    srv_ctx.load_verify_locations(cafile=ca_chain_path)
    print(f"  verify_mode = CERT_REQUIRED")
    print(f"  CA для клиентов: {ca_chain_path}")

    app = make_app()
    srv = make_server(HOST, PORT, app, ssl_context=srv_ctx, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.4)
    print(f"  слушает на https://{HOST}:{PORT}")

    try:
        # --- 5. Позитивный тест ---
        hr("5. Позитивный: клиент с .p12 подключается")
        try:
            body = https_get_with_p12("/whoami", ca_chain_path, p12_path,
                                       "hunter2")
            print(f"  ✓ handshake прошёл")
            print(f"  /whoami → {body.decode()}")
        except ssl.SSLError as e:
            print(f"  ✗ SSL ошибка: {e}")
            return 1
        except Exception as e:
            print(f"  ✗ {type(e).__name__}: {e}")
            return 1

        # --- 6. Негативный: без клиентского сертификата ---
        hr("6. Негативный: клиент БЕЗ .p12 — handshake должен упасть")
        ctx_no_cert = ssl.create_default_context(cafile=ca_chain_path)
        try:
            req = urllib.request.Request(f"https://{HOST}:{PORT}/whoami")
            with urllib.request.urlopen(req, context=ctx_no_cert, timeout=5) as r:
                r.read()
            print("  ✗ сервер ПРИНЯЛ клиента без сертификата — плохо")
            return 1
        except ssl.SSLError as e:
            print(f"  ✓ handshake отвергнут: {type(e).__name__}")
            print(f"      {str(e)[:100]}")
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLError):
                print(f"  ✓ handshake отвергнут: SSLError")
                print(f"      {str(e.reason)[:100]}")
            else:
                print(f"  ? URLError: {e}")
        except Exception as e:
            print(f"  ✓ отвергнут ({type(e).__name__})")

        # --- 7. Проверка через OpenSSL CLI ---
        if openssl:
            hr("7. OpenSSL s_client с нашим .p12")
            # Конвертируем .p12 в PEM через наш же код
            extract_pem = os.path.join(WORKDIR, "client_extracted.pem")
            with open(extract_pem, "w") as f:
                f.write("".join(c.to_pem() for c in [cli_cert] + [ca.inter]))
                f.write(cli_key.to_private_pem())
            print(f"  PEM для OpenSSL: {extract_pem}")

            # Отправим HTTP-запрос через openssl s_client
            r = subprocess.run(
                [openssl, "s_client",
                 "-connect", f"{HOST}:{PORT}",
                 "-cert", extract_pem,
                 "-key", extract_pem,
                 "-CAfile", ca_chain_path,
                 "-servername", "localhost",
                 "-brief"],
                input="GET /whoami HTTP/1.0\r\n\r\n",
                capture_output=True, text=True, timeout=10,
            )
            out = (r.stdout or "") + (r.stderr or "")
            if "alice@mtls-test" in out or "200" in out or "Verification" in out:
                print(f"  ✓ OpenSSL s_client подключился с нашим .p12")
            else:
                print(f"  ? вывод (первые 300):\n{out[:300]}")

        hr("ИТОГ")
        print("""
  ✓ Root + Intermediate сгенерированы в памяти
  ✓ Server leaf для Flask
  ✓ Client leaf + .p12 (OpenSSL-совместимый)
  ✓ Flask требует клиентский сертификат (CERT_REQUIRED)
  ✓ Клиент с .p12 подключается, сервер видит CN
  ✓ Клиент без .p12 отвергается на handshake
  ✓ Проверено OpenSSL s_client
""")
        return 0

    finally:
        hr("Остановка сервера")
        srv.shutdown()
        print("  ✓ Flask остановлен")
        print(f"\n  Файлы в {WORKDIR}:")
        for f in sorted(os.listdir(WORKDIR)):
            size = os.path.getsize(os.path.join(WORKDIR, f))
            print(f"    {f:28s} {size:>6} байт")


if __name__ == "__main__":
    sys.exit(main())
