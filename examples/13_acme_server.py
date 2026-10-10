"""13 - Минимальный ACME-сервер.

Run: python examples/13_acme_server.py [--auto-verify] [--port 14000]

--auto-verify — не делать реальный http-01 fetch (для локальных тестов).
               В продакшене НЕ использовать.

Endpoints:
  GET  /directory         — метаданные сервера
  HEAD /new-nonce         — свежий nonce
  POST /new-account       — создать аккаунт
  POST /new-order         — создать order
  POST /authz/<id>        — получить authz
  POST /challenge/<id>    — активировать challenge
  POST /finalize/<id>     — финализировать order (CSR)
  POST /cert/<id>         — скачать сертификат
"""
import argparse
import json
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from x509kit import CertificateBuilder, CACert, Ed25519Keys
from x509kit.acme import (
    ACMEServer, ACMEError, b64u, verify_jws,
)


def build_ca():
    key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "XX", "O": "ACME Demo", "CN": "ACME Demo Root"})
        .add_public_key(key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(key))
    return ca, key


def make_handler(acme: ACMEServer):
    class Handler(BaseHTTPRequestHandler):
        server_ref = acme

        def log_message(self, fmt, *args):
            sys.stderr.write(f"[acme] {fmt % args}\n")

        # ---- helpers ----
        def _send(self, status: int, body: bytes, ctype: str,
                  extra_headers=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Replay-Nonce", self.server_ref.new_nonce())
            # RFC 8555 §7.1: многие клиенты (в т.ч. certbot) требуют rel="up"
            self.send_header("Link",
                f'<{self.server_ref.base_url}/directory>;rel="up"')
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, obj, extra_headers=None):
            body = json.dumps(obj, separators=(",", ":")).encode()
            self._send(status, body, "application/json", extra_headers)

        def _problem(self, err: ACMEError):
            from x509kit.acme import _acme_problem
            body = json.dumps(_acme_problem(err), separators=(",", ":")).encode()
            self._send(err.status, body, "application/problem+json")

        def _read_jws(self):
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n)
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception as e:
                raise ACMEError("malformed", f"not JSON: {e}")

        def _verify(self, jws, url):
            try:
                return verify_jws(
                    jws,
                    expected_url=url,
                    nonce_checker=self.server_ref.consume_nonce,
                    key_resolver=self.server_ref.account_key,
                )
            except Exception as e:
                # Convert nonce/signature errors to ACME problem
                msg = str(e)
                kind = "badNonce" if "nonce" in msg.lower() else "malformed"
                raise ACMEError(kind, msg, 400)

        # ---- HTTP verbs ----
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/directory":
                self._json(200, self.server_ref.directory())
            else:
                self._problem(ACMEError("malformed", f"GET {path}", 404))

        def do_HEAD(self):
            path = self.path.split("?", 1)[0]
            if path == "/new-nonce":
                self.send_response(200)
                self.send_header("Replay-Nonce", self.server_ref.new_nonce())
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            url = self.server_ref.base_url + path

            try:
                jws = self._read_jws()
                result = self._verify(jws, url)
                self._dispatch(path, result)
            except ACMEError as e:
                self._problem(e)
            except Exception as e:
                self._problem(ACMEError("serverInternal", str(e), 500))

        def _dispatch(self, path, result):
            S = self.server_ref

            if path == "/new-account":
                kid, created = S.new_account(result.jwk, result.payload)
                view = S.account_view(kid)
                status = 201 if created else 200
                self._json(status, view, {"Location": kid})
                return

            if path == "/new-order":
                if result.kid is None:
                    raise ACMEError("malformed", "kid required", 400)
                view = S.new_order(result.kid, result.payload)
                order_url = f"{S.base_url}/order/{view['id']}"
                self._json(201, view, {"Location": order_url})
                return

            if path.startswith("/order/"):
                order_id = path[len("/order/"):]
                if not order_id:
                    raise ACMEError("malformed",
                                    "order URL is missing id", 404)
                self._json(200, S.get_order(order_id))
                return

            if path.startswith("/authz/"):
                authz_id = path[len("/authz/"):]
                self._json(200, S.get_authz(authz_id))
                return

            if path.startswith("/challenge/"):
                chal_id = path[len("/challenge/"):]
                # payload обычно {}
                self._json(200, S.trigger_challenge(chal_id))
                return

            if path.startswith("/finalize/"):
                order_id = path[len("/finalize/"):]
                self._json(200, S.finalize(order_id, result.payload))
                return

            if path.startswith("/cert/"):
                cert_id = path[len("/cert/"):]
                pem = S.get_certificate(cert_id)
                self._send(200, pem.encode(),
                           "application/pem-certificate-chain")
                return

            raise ACMEError("malformed", f"unknown path: {path}", 404)

    return Handler


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=14000)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--auto-verify", action="store_true",
                   help="challenge valid без реальной проверки (только для тестов!)")
    args = p.parse_args()

    ca, ca_key = build_ca()
    base_url = f"http://{args.host}:{args.port}"
    acme = ACMEServer(ca, ca_key, base_url,
                      cert_days=90,
                      auto_verify=args.auto_verify)

    Handler = make_handler(acme)
    srv = HTTPServer((args.host, args.port), Handler)

    print(f"ACME server: {base_url}/directory")
    print(f"Directory:   {base_url}/directory")
    print(f"auto_verify: {args.auto_verify}")
    print("Ctrl+C to stop.")
    print()
    print("Test with: python examples/14_acme_client.py")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
