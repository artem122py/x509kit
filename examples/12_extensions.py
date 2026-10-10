"""12 - Certificate with every supported extension.

Run: python examples/12_extensions.py
"""
from x509kit import CertificateBuilder, Ed25519Keys

key = Ed25519Keys.generate()
cert = (CertificateBuilder()
    .add_subject({"CN": "kitchen-sink.test"})
    .add_public_key(key)
    .add_serial_random().add_validity(days=30)
    .add_san(dns=["kitchen-sink.test", "www.kitchen-sink.test"],
             ips=["192.0.2.1", "2001:db8::1"],
             emails=["admin@kitchen-sink.test"],
             uris=["https://kitchen-sink.test/"])
    .add_basic_constraints(path_len=None)
    .add_key_usage("digitalSignature", "keyEncipherment")
    .add_extended_key_usage("serverAuth", "clientAuth")
    .add_crl_distribution_point("http://ca.test/crl.pem")
    .add_aia(ocsp=["http://ocsp.test"],
             ca_issuers=["http://ca.test/ca.pem"])
    .self_signed().sign(key))

print("Extensions in this certificate:")
for ext in cert.extensions:
    kind = "critical" if ext.critical else "non-critical"
    print(f"  {ext.oid:25s}  ({kind})")

print()
print("Parsed values:")
print(f"  SAN (raw):    {cert.san}")
print(f"  DNS names:    {cert.dns_names}")
print(f"  IP addresses: {cert.ip_addresses}")
print(f"  Emails:       {cert.emails}")
print(f"  URIs:         {cert.uris}")
print(f"  CRL DP:       {cert.crl_distribution_points}")
print(f"  AIA OCSP:     {cert.aia_ocsp}")
print(f"  AIA issuers:  {cert.aia_issuers}")
print(f"  EKU:          {sorted(cert.eku)}")
print(f"  has serverAuth: {cert.has_eku('serverAuth')}")
