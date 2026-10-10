# -*- coding: utf-8 -*-
"""
x509kit.revocation — HTTP-серверы для CRL и OCSP.

Позволяют раздавать revocation-данные от имени CA через HTTP.

    from x509kit.revocation import make_revocation_server

    srv = make_revocation_server(ca, host="127.0.0.1", port=8080)
    srv.serve_forever()

Endpoints:
    GET  /crl.pem          — текущий CRL
    POST /ocsp             — OCSP-запрос (DER) → OCSP-ответ (DER)
    GET  /                 — простой статус HTML
"""

from __future__ import annotations

import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from .x509 import CACert, OCSPRequest, X509Error


# ======================================================================
#  HTTP handler
# ======================================================================

def make_revocation_handler(ca: CACert, *,
                             crl_days: int = 7,
                             crl_cache_seconds: int = 60):
    """Возвращает класс BaseHTTPRequestHandler для CA.

    crl_days — срок действия CRL при генерации.
    crl_cache_seconds — сколько секунд кэшировать CRL (0 = всегда пересоздавать).
    """
    cache = {"crl_der": None, "crl_pem": None, "ts": 0.0}

    def get_crl_pem():
        import time as _t
        now = _t.time()
        if crl_cache_seconds > 0 and cache["crl_pem"] is not None:
            if now - cache["ts"] < crl_cache_seconds:
                return cache["crl_pem"]
        crl = ca.to_crl(days=crl_days)
        cache["crl_pem"] = crl.to_pem()
        cache["crl_der"] = crl.der
        cache["ts"] = now
        return cache["crl_pem"]

    class Handler(BaseHTTPRequestHandler):
        server_version = "x509kit-revocation/1.0"

        def log_message(self, fmt, *args):
            # тихий режим — переопределяем, если нужно логировать
            import sys as _sys
            _sys.stderr.write(f"[revocation] {fmt % args}\n")

        # ---- helpers ----
        def _send(self, status, body, ctype, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        # ---- GET ----
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/crl.pem", "/crl", "/crl.der"):
                try:
                    if path.endswith(".der"):
                        import time as _t
                        get_crl_pem()  # обновляет кэш
                        body = cache["crl_der"]
                        self._send(200, body, "application/pkix-crl")
                    else:
                        pem = get_crl_pem()
                        self._send(200, pem.encode(),
                                   "application/x-pem-file")
                except Exception as e:
                    self._send(500, f"CRL generation failed: {e}".encode(),
                               "text/plain")
                return

            if path in ("/", "/index.html"):
                body = f"""<!doctype html>
<html><body style="font-family:monospace;padding:20px">
<h2>x509kit revocation server</h2>
<p>CA: <b>{ca.subject}</b></p>
<p>Revoked: <b>{len(ca._revoked)}</b></p>
<ul>
<li><a href="/crl.pem">/crl.pem</a> — CRL (PEM)</li>
<li><a href="/crl.der">/crl.der</a> — CRL (DER)</li>
<li>POST /ocsp — OCSP (DER in/out)</li>
</ul>
</body></html>""".encode()
                self._send(200, body, "text/html; charset=utf-8")
                return

            self._send(404, b"not found", "text/plain")

        # ---- POST (OCSP) ----
        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if path not in ("/ocsp", "/"):
                self._send(404, b"not found", "text/plain")
                return

            n = int(self.headers.get("Content-Length", "0"))
            if n == 0 or n > 64 * 1024:
                self._send(400, b"missing or too-large body", "text/plain")
                return
            body = self.rfile.read(n)

            try:
                req = OCSPRequest(body)
            except X509Error as e:
                self._send(400, f"bad OCSPRequest: {e}".encode(),
                           "text/plain")
                return

            try:
                # Автоопределение статуса: good/revoked из ca._revoked
                resp = ca.respond_ocsp(req, days=1)
            except X509Error as e:
                # Ошибка сервера — вернуть OCSP error response
                from .x509 import der_seq, _der_tlv
                # статус 2 = internalError
                err_body = der_seq(_der_tlv(0x0A, b"\x02"))
                self._send(200, err_body, "application/ocsp-response")
                return

            self._send(200, resp.der, "application/ocsp-response")

    return Handler


# ======================================================================
#  HTTP server wrapper
# ======================================================================

class RevocationHTTPServer(HTTPServer):
    """HTTPServer с привязанным CA. Удобно для запуска в потоке."""

    def __init__(self, addr, ca: CACert, *,
                 crl_days: int = 7, crl_cache_seconds: int = 60):
        Handler = make_revocation_handler(
            ca, crl_days=crl_days, crl_cache_seconds=crl_cache_seconds,
        )
        super().__init__(addr, Handler)
        self.ca = ca

    def base_url(self) -> str:
        host, port = self.server_address[:2]
        if host in ("0.0.0.0", "::", ""):
            host = "127.0.0.1"
        return f"http://{host}:{port}"


def make_revocation_server(ca: CACert, host: str = "127.0.0.1",
                            port: int = 8080, *,
                            crl_days: int = 7,
                            crl_cache_seconds: int = 60) -> RevocationHTTPServer:
    """Создать HTTP-сервер, раздающий CRL и OCSP от имени CA."""
    if not isinstance(ca, CACert):
        raise TypeError("ca must be CACert")
    if ca._signing_key is None:
        raise X509Error(
            "CA must have a private key (use CACert.from_cert(cert, "
            "signing_key=...) or from_pem(..., private_key_pem=...))")
    return RevocationHTTPServer(
        (host, port), ca,
        crl_days=crl_days, crl_cache_seconds=crl_cache_seconds,
    )


def run_in_thread(srv: RevocationHTTPServer):
    """Запустить сервер в фоне. Возвращает threading.Thread."""
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
