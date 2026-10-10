"""08 - Fetch and parse a real HTTPS server certificate.

Run: python examples/08_parse_real_cert.py [hostname]
Default host: example.com

Requires network access. No files written.
"""
import socket
import ssl
import sys

from x509kit import Cert, validate_hostname

HOST = sys.argv[1] if len(sys.argv) > 1 else "example.com"
PORT = 443

# --- Fetch the DER cert from the wire ---
ctx = ssl.create_default_context()
with socket.create_connection((HOST, PORT), timeout=5) as sock:
    with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
        der = ssock.getpeercert(binary_form=True)

# --- Parse with x509kit ---
cert = Cert(der)

print(f"Certificate of {HOST}")
print(f"  Subject:      {cert.subject}")
print(f"  Issuer:       {cert.issuer}")
print(f"  Serial:       0x{cert.serial:x}")
print(f"  Not before:   {cert.not_before.isoformat()}")
print(f"  Not after:    {cert.not_after.isoformat()}")
print(f"  Sig alg:      {cert.signature_algorithm_name}")
print(f"  Pubkey:       {cert.public_key}")
print()
print(f"  SAN DNS:      {cert.dns_names}")
print(f"  SAN IP:       {cert.ip_addresses}")
print(f"  EKU:          {sorted(cert.eku)}")
print(f"  CRL DP:       {cert.crl_distribution_points}")
print(f"  AIA OCSP:     {cert.aia_ocsp}")
print()
print(f"  Expired:      {not cert.is_valid_at()}")
print(f"  validate_hostname(cert, {HOST!r}): {validate_hostname(cert, HOST)}")
