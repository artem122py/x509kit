"""15 - Certificate Transparency: разбор SCT из реального сертификата.

Run: python examples/15_ct_sct.py [hostname]
Default: www.google.com (у них всегда есть embedded SCT)

Работает через Cert.from_url — нужна сеть.
"""
import sys

from x509kit import Cert


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "www.google.com"
    print(f"Fetching certificate from {host}...")
    try:
        cert = Cert.from_url(host)
    except Exception as e:
        print(f"[!] не удалось получить сертификат: {type(e).__name__}: {e}")
        print("    нужна сеть. Попробуй с другим хостом:")
        print("        python examples/15_ct_sct.py cloudflare.com")
        return 1

    print(f"Subject: {cert.subject}")
    print(f"Issuer:  {cert.issuer}")
    print()

    scts = cert.sct_list
    if not scts:
        print("Нет embedded SCT (Certificate Transparency).")
        print("Обычно они есть у Google, Cloudflare, Let's Encrypt.")
        return 0

    print(f"Найдено SCT: {len(scts)}")
    for i, sct in enumerate(scts, 1):
        print()
        print(f"  [{i}] Version:    {sct['version']}")
        print(f"      Log ID:     {sct['log_id'][:32]}…")
        print(f"      Timestamp:  {sct['timestamp_iso']}")
        print(f"      Hash alg:   {sct['hash_alg']}")
        print(f"      Sig alg:    {sct['sig_alg']}")
        print(f"      Signature:  {len(sct['_signature_bytes'])} bytes")

    return 0


if __name__ == "__main__":
    sys.exit(main())
