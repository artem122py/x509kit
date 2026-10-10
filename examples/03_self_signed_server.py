"""03 - HTTPS server with a self-signed certificate.

Run: python examples/03_self_signed_server.py
Then open: https://127.0.0.1:8443/
Browser will warn (self-signed). That is expected.
"""
import http.server
import os
import ssl
import tempfile

from x509kit import CertificateBuilder, Ed25519Keys

HOST, PORT = "127.0.0.1", 8443

# --- Generate key + cert in memory ---
key = Ed25519Keys.generate()
cert = (CertificateBuilder()
    .add_subject({"C": "XX", "O": "Local Dev", "CN": HOST})
    .add_public_key(key)
    .add_serial_random().add_validity(days=30)
    .add_san(dns=[HOST, "localhost"], ips=["127.0.0.1", "::1"])
    .add_extended_key_usage("serverAuth")
    .self_signed().sign(key))

# --- ssl.SSLContext wants file paths, so use tempfiles ---
def write_temp(text):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    f.write(text); f.close()
    return f.name

cert_path = write_temp(cert.to_pem())
key_path = write_temp(key.to_private_pem())

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(cert_path, key_path)

os.unlink(cert_path)
os.unlink(key_path)

# --- Handler ---
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"HTTPS works (self-signed)\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

# --- Serve ---
srv = http.server.HTTPServer((HOST, PORT), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

print(f"Listening on https://{HOST}:{PORT}/")
print("Browser will warn (self-signed). Ctrl+C to stop.")
try:
    srv.serve_forever()
except KeyboardInterrupt:
    print("\nStopped.")
