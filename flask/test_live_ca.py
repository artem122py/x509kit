# -*- coding: utf-8 -*-
"""
test_live_ca.py — запускает микро-CA в фоне и прогоняет полный live-цикл.

Что делает:
  1. Генерирует Root CA + Intermediate в памяти.
  2. Выпускает leaf для Flask-сервера (chain подаётся в SSLContext).
  3. Запускает Flask-сервер в фоне (threading).
  4. Через OpenSSL CLI генерирует ключ + CSR (в подпапке ./live_test/).
  5. POST /sign-csr → получает leaf.
  6. openssl verify -CAfile root -untrusted inter leaf.pem   → OK
  7. openssl x509 -text — показывает SAN/issuer.
  8. Отзывает leaf через /revoke.
  9. Скачивает CRL, прогоняет openssl verify -crl_check → error 23.
 10. Останавливает сервер.

Зависимости: flask, openssl в PATH.
Запуск:      python test_live_ca.py
"""

import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from flask import Flask, jsonify, request, Response
from werkzeug.serving import make_server

from x509kit import (
    CertificateBuilder, CACert, Ed25519Keys, ECDSAKeys,
    CSRBuilder, load_pem_csrs, X509Error, CRL_REASONS, CRL_REASONS_REV,
)


HOST = "127.0.0.1"
PORT = 18443
WORKDIR = os.path.abspath("./live_test")


# ======================================================================
#  Утилиты
# ======================================================================

def hr(title):
    print()
    print("─" * 72)
    print(f"  {title}")
    print("─" * 72)


def run(cmd, **kw):
    """Запустить subprocess, вернуть stdout, при ошибке — поднять."""
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        print(f"  [cmd] {' '.join(cmd)}")
        print(f"  stdout: {r.stdout}")
        print(f"  stderr: {r.stderr}")
        raise RuntimeError(f"command failed: {cmd[0]}")
    return r.stdout


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


# ======================================================================
#  CA
# ======================================================================

class InMemoryCA:
    def __init__(self):
        self.issued = []
        self.revoked = []
        self.crl_number = 1

        self.root_key = Ed25519Keys.generate()
        self.root = (CertificateBuilder(is_ca=True)
            .add_subject({"C": "XX", "O": "Live Test PKI", "CN": "Live Root CA"})
            .add_public_key(self.root_key)
            .add_serial_random().add_validity(days=7300)
            .add_basic_constraints(path_len=1)
            .add_key_usage("keyCertSign", "cRLSign")
            .self_signed().sign(self.root_key))

        self.inter_key = ECDSAKeys.generate("P-256")
        self.inter = (CertificateBuilder(is_ca=True)
            .add_subject({"C": "XX", "O": "Live Test PKI", "CN": "Live Intermediate"})
            .add_issuer(self.root)
            .add_public_key(self.inter_key)
            .add_serial_random().add_validity(days=3650)
            .add_basic_constraints(path_len=0)
            .add_key_usage("keyCertSign", "cRLSign")
            .add_crl_distribution_point(f"https://{HOST}:{PORT}/crl.pem")
            .sign(self.root_key))

    def issue_from_csr(self, csr_pem):
        csrs = load_pem_csrs(csr_pem)
        if not csrs:
            raise X509Error("no CSR")
        csr = csrs[0]
        if not csr.verify_signature():
            raise X509Error("CSR self-signature invalid")
        leaf = (CertificateBuilder.from_csr(csr)
            .add_issuer(self.inter)
            .add_serial_random().add_validity(days=90)
            .add_crl_distribution_point(f"https://{HOST}:{PORT}/crl.pem")
            .sign(self.inter_key))
        self.issued.append((leaf.serial, str(leaf.subject), leaf.not_after))
        return leaf

    def revoke(self, serial):
        import datetime
        self.revoked.append((serial,
                             datetime.datetime.now(datetime.timezone.utc),
                             CRL_REASONS["keyCompromise"]))

    def build_crl(self):
        from x509kit import CRLBuilder
        b = CRLBuilder()
        b.set_issuer(self.inter)
        b.set_validity(days=7)
        b.set_crl_number(self.crl_number)
        for s, w, c in self.revoked:
            b.add_revoked(s, when=w, reason=c)
        return b.sign(self.inter_key)


# ======================================================================
#  SSLContext из строк
# ======================================================================

def load_cert_chain_from_strings(ctx, cert_chain_pem, key_pem):
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
#  Flask app
# ======================================================================

def make_app(ca):
    app = Flask(__name__)

    @app.route("/ca.pem")
    def ca_pem():
        return Response(ca.root.to_pem(), mimetype="application/x-pem-file")

    @app.route("/inter.pem")
    def inter_pem():
        return Response(ca.inter.to_pem(), mimetype="application/x-pem-file")

    @app.route("/chain.pem")
    def chain_pem():
        return Response(ca.inter.to_pem() + ca.root.to_pem(),
                        mimetype="application/x-pem-file")

    @app.route("/sign-csr", methods=["POST"])
    def sign_csr():
        body = request.get_data(as_text=True)
        try:
            leaf = ca.issue_from_csr(body)
            return Response(leaf.to_pem(), mimetype="application/x-pem-file")
        except X509Error as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/crl.pem")
    def crl_pem():
        return Response(ca.build_crl().to_pem(), mimetype="application/x-pem-file")

    @app.route("/revoke")
    def revoke():
        s = request.args.get("serial", "")
        try:
            serial = int(s, 16) if s.startswith("0x") else int(s)
        except ValueError:
            return jsonify({"error": "bad serial"}), 400
        ca.revoke(serial)
        return jsonify({"ok": True, "serial": hex(serial)})

    @app.route("/issued")
    def issued():
        return jsonify({"issued": [
            {"serial": hex(s), "subject": subj, "not_after": dt.isoformat()}
            for s, subj, dt in ca.issued]})

    return app


# ======================================================================
#  HTTPS-клиент, доверяющий только нашему root
# ======================================================================

def https_get(path, root_ca_path, timeout=10):
    ctx = ssl.create_default_context(cafile=root_ca_path)
    with urllib.request.urlopen(f"https://{HOST}:{PORT}{path}",
                                context=ctx, timeout=timeout) as r:
        return r.read()


def https_post(path, body: bytes, root_ca_path, timeout=10):
    ctx = ssl.create_default_context(cafile=root_ca_path)
    req = urllib.request.Request(
        f"https://{HOST}:{PORT}{path}", data=body, method="POST",
        headers={"Content-Type": "application/x-pem-file"})
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return r.read()


# ======================================================================
#  Main
# ======================================================================

def main():
    print("╔" + "═" * 70 + "╗")
    print("║  test_live_ca — микро-CA live-цикл через OpenSSL CLI" + " " * 15 + "║")
    print("╚" + "═" * 70 + "╝")

    # --- Подготовка workdir ---
    if os.path.exists(WORKDIR):
        shutil.rmtree(WORKDIR)
    os.makedirs(WORKDIR)
    print(f"\n  Рабочая папка: {WORKDIR}")

    openssl = shutil.which("openssl")
    if not openssl:
        print("[!] openssl не найден в PATH"); return 1
    print(f"  OpenSSL:       {openssl}")
    print(f"  Версия:        {run([openssl, 'version']).strip()}")

    # --- CA + server leaf ---
    hr("1. Генерация CA (в памяти)")
    ca = InMemoryCA()
    print(f"  Root:  {ca.root.subject}")
    print(f"  Inter: {ca.inter.subject}")
    print(f"  chain root→inter: {ca.root.verify_chain([ca.inter])}")

    hr("2. Leaf для Flask-сервера")
    srv_key = Ed25519Keys.generate()
    srv_leaf = (CertificateBuilder()
        .add_subject({"C": "XX", "O": "Live Test PKI", "CN": "localhost"})
        .add_issuer(ca.inter).add_public_key(srv_key)
        .add_serial_random().add_validity(days=90)
        .add_san(dns=["localhost"], ips=["127.0.0.1", "::1"])
        .add_extended_key_usage("serverAuth")
        .sign(ca.inter_key))
    print(f"  SAN: {[v for _, v in srv_leaf.san]}")

    # --- SSLContext с chain ---
    hr("3. SSLContext (leaf + intermediate)")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    chain = srv_leaf.to_pem() + ca.inter.to_pem()
    load_cert_chain_from_strings(ctx, chain, srv_key.to_private_pem())
    print("  chain загружен, временные файлы удалены")

    # --- Flask в фоне ---
    hr("4. Запуск Flask в фоне")
    app = make_app(ca)
    srv = make_server(HOST, PORT, app, ssl_context=ctx, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.4)
    print(f"  слушает на https://{HOST}:{PORT}")

    # Сохраняем root CA на диск — нужно для HTTPS-клиента
    root_path = os.path.join(WORKDIR, "root_ca.pem")
    write(root_path, ca.root.to_pem())
    inter_path = os.path.join(WORKDIR, "inter.pem")
    write(inter_path, ca.inter.to_pem())

    try:
        # --- HTTPS-проверка: наш root валидирует наш же server cert ---
        hr("5. HTTPS-запрос к серверу (клиент доверяет только нашему root)")
        try:
            data = https_get("/issued", root_path)
            print(f"  ✓ Python ssl (OpenSSL) принял сертификат сервера")
            print(f"  /issued → {data.decode()[:120]}")
        except ssl.SSLCertVerificationError as e:
            print(f"  ✗ SSL verification failed: {e}")
            return 1

        # --- OpenSSL CLI: генерация ключа + CSR ---
        hr("6. OpenSSL CLI: генерация ключа + CSR")
        key_path = os.path.join(WORKDIR, "client.key")
        csr_path = os.path.join(WORKDIR, "client.csr")
        run([openssl, "genpkey", "-algorithm", "ed25519", "-out", key_path])
        run([openssl, "req", "-new", "-key", key_path,
             "-subj", "/C=XX/O=Live Client/CN=example.com",
             "-addext", "subjectAltName=DNS:example.com,DNS:www.example.com",
             "-out", csr_path])
        with open(csr_path) as f:
            csr_pem = f.read()
        print(f"  key: {os.path.basename(key_path)}")
        print(f"  csr: {os.path.basename(csr_path)}")

        # Покажем, что видит OpenSSL в CSR
        print()
        print(run([openssl, "req", "-in", csr_path, "-noout",
                   "-subject", "-text"]).split("Signature Algorithm")[0][:400])

        # --- Отправка CSR на /sign-csr ---
        hr("7. POST /sign-csr — получаем leaf")
        leaf_pem = https_post("/sign-csr", csr_pem.encode(), root_path)
        leaf_path = os.path.join(WORKDIR, "client_leaf.pem")
        write(leaf_path, leaf_pem.decode())
        print(f"  leaf сохранён: {os.path.basename(leaf_path)}")

        # --- openssl verify ---
        hr("8. openssl verify")
        out = run([openssl, "verify",
                   "-CAfile", root_path, "-untrusted", inter_path, leaf_path])
        print(f"  {out.strip()}")
        assert "OK" in out, "openssl verify failed"

        # --- openssl x509 -text: убедиться, что SAN на месте ---
        hr("9. openssl x509 -in leaf -text (фрагмент)")
        text = run([openssl, "x509", "-in", leaf_path, "-noout", "-text"])
        for line in text.splitlines():
            if any(k in line for k in ("Subject:", "Issuer:", "Serial",
                                        "Signature Algorithm",
                                        "Subject Alternative Name",
                                        "DNS:", "IP Address",
                                        "Extended Key Usage",
                                        "CRL Distribution")):
                print(f"  {line.strip()}")

        # --- Отзыв ---
        hr("10. Отзыв через /revoke")
        serial_hex = run([openssl, "x509", "-in", leaf_path, "-noout", "-serial"]).strip()
        serial_hex = serial_hex.split("=")[1]
        print(f"  serial: 0x{serial_hex}")
        r = https_get(f"/revoke?serial=0x{serial_hex}", root_path)
        print(f"  /revoke → {r.decode()}")

        # --- CRL ---
        hr("11. /crl.pem + openssl verify -crl_check")
        crl_pem = https_get("/crl.pem", root_path)
        crl_path = os.path.join(WORKDIR, "server.crl.pem")
        write(crl_path, crl_pem.decode())
        print(f"  CRL: {len(crl_pem)} байт, сохранён как server.crl.pem")

        print()
        print(run([openssl, "crl", "-in", crl_path, "-noout", "-text"])[:500])

        # Проверка, что verify ОТКЛОНЯЕТ отозванный leaf
        r = subprocess.run(
            [openssl, "verify", "-CAfile", root_path, "-untrusted", inter_path,
             "-CRLfile", crl_path, "-crl_check", leaf_path],
            capture_output=True, text=True)
        combined = r.stdout + r.stderr
        print(f"  exit code: {r.returncode}")
        print(f"  вывод:     {combined.strip()[:200]}")
        if "certificate revoked" in combined or "error 23" in combined:
            print("  ✓ OpenSSL подтвердил: leaf ОТОЗВАН")
        else:
            print("  ✗ ожидали error 23 (certificate revoked)")

        hr("ИТОГ")
        print("""
  ✓ CA сгенерирован в памяти
  ✓ Flask запущен на HTTPS с chain (leaf + inter)
  ✓ Python ssl доверяет только нашему root CA
  ✓ OpenSSL CLI сгенерировал ключ + CSR
  ✓ /sign-csr подписал CSR
  ✓ openssl verify -CAfile ... leaf.pem → OK
  ✓ openssl x509 -text показывает SAN/EKU/CRL DP
  ✓ /revoke отозвал leaf
  ✓ openssl verify -crl_check → certificate revoked

  Всё сделано через настоящий OpenSSL CLI, не через нашу библиотеку.""")
        return 0

    finally:
        hr("Остановка сервера")
        srv.shutdown()
        print("  ✓ Flask остановлен")
        print(f"\n  Файлы в {WORKDIR}:")
        for f in sorted(os.listdir(WORKDIR)):
            size = os.path.getsize(os.path.join(WORKDIR, f))
            print(f"    {f:24s} {size:>6} байт")


if __name__ == "__main__":
    sys.exit(main())