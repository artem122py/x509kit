"""04 - Mutual TLS server: requires a client certificate.

Run: python examples/04_mtls_server.py

The script starts a server in a background thread, then makes two
requests: one with a client cert, one without. The second must fail.
"""
import http.server
import os
import ssl
import tempfile
import threading
import urllib.request

from x509kit import CertificateBuilder, Ed25519Keys

HOST, PORT = "127.0.0.1", 8443

# --- CA ---
ca_key = Ed25519Keys.generate()
ca = (CertificateBuilder(is_ca=True)
    .add_subject({"C": "XX", "O": "Demo", "CN": "Demo Root CA"})
    .add_public_key(ca_key)
    .add_serial_random().add_validity(days=3650)
    .add_basic_constraints(path_len=0)
    .add_key_usage("keyCertSign", "cRLSign")
    .self_signed().sign(ca_key))

# --- Server leaf ---
srv_key = Ed25519Keys.generate()
srv_cert = (CertificateBuilder()
    .add_subject({"CN": "localhost"})
    .add_issuer(ca).add_public_key(srv_key)
    .add_serial_random().add_validity(days=90)
    .add_san(dns=["localhost"], ips=["127.0.0.1"])
    .add_extended_key_usage("serverAuth")
    .sign(ca_key))

# --- Client leaf ---
cli_key = Ed25519Keys.generate()
cli_cert = (CertificateBuilder()
    .add_subject({"CN": "alice"})
    .add_issuer(ca).add_public_key(cli_key)
    .add_serial_random().add_validity(days=90)
    .add_extended_key_usage("clientAuth")
    .sign(ca_key))

# --- Write temp PEM files ---
def temp_pem(text):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    f.write(text); f.close()
    return f.name

srv_pem     = temp_pem(srv_cert.to_pem() + ca.to_pem())
srv_key_pem = temp_pem(srv_key.to_private_pem())
ca_pem      = temp_pem(ca.to_pem())
cli_pem     = temp_pem(cli_cert.to_pem() + ca.to_pem())
cli_key_pem = temp_pem(cli_key.to_private_pem())

# --- Server context: require client cert ---
srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
srv_ctx.load_cert_chain(srv_pem, srv_key_pem)
srv_ctx.verify_mode = ssl.CERT_REQUIRED
srv_ctx.load_verify_locations(cafile=ca_pem)

# --- Handler ---
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.connection.getpeercert()
        cn = dict(x[0] for x in peer["subject"]).get("commonName", "?")
        body = f"Hello, {cn}!\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

srv = http.server.HTTPServer((HOST, PORT), Handler)
srv.socket = srv_ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# --- Test 1: client WITH cert ---
ctx1 = ssl.create_default_context(cafile=ca_pem)
ctx1.load_cert_chain(cli_pem, cli_key_pem)
with urllib.request.urlopen(f"https://{HOST}:{PORT}/", context=ctx1) as r:
    print(f"With client cert:    {r.read().decode().strip()}")

# --- Test 2: client WITHOUT cert ---
ctx2 = ssl.create_default_context(cafile=ca_pem)
try:
    urllib.request.urlopen(f"https://{HOST}:{PORT}/", context=ctx2)
    print("Without client cert: ACCEPTED (this would be a bug)")
except ssl.SSLError as e:
    print(f"Without client cert: rejected ({type(e).__name__})")

srv.shutdown()

# --- Cleanup ---
for p in (srv_pem, srv_key_pem, ca_pem, cli_pem, cli_key_pem):
    os.unlink(p)
