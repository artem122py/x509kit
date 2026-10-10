"""16 - Полный revocation-стек: выпуск, отзыв, CRL/OCSP через HTTP.

Run: python examples/16_revocation.py

Что делает:
  1. Создаёт CA в памяти.
  2. Выпускает 3 leaf-сертификата с CRL DP и AIA OCSP.
  3. Поднимает HTTP-сервер revocation (CRL + OCSP).
  4. Клиент через Cert.fetch_crl() и Cert.fetch_ocsp() проверяет статус.
  5. Отзывает один сертификат на CA и повторяет проверку.
"""
import threading
import time
import urllib.request

from x509kit import (
    CertificateBuilder, CACert, Ed25519Keys,
    make_revocation_server,
)


def main():
    # ---- 1. CA ----
    print("=== 1. Root CA ===")
    ca_key = Ed25519Keys.generate()
    ca = (CertificateBuilder(is_ca=True)
        .add_subject({"C": "XX", "O": "Revocation Demo", "CN": "Revocation Root"})
        .add_public_key(ca_key)
        .add_serial_random().add_validity(days=3650)
        .add_basic_constraints(path_len=0)
        .add_key_usage("keyCertSign", "cRLSign")
        .self_signed().sign(ca_key))
    print(f"  {ca.subject}")

    # ---- 2. Сервер revocation (нужен URL в листьях) ----
    print()
    print("=== 2. Revocation HTTP server ===")
    srv = make_revocation_server(ca, "127.0.0.1", 0,
                                  crl_days=7, crl_cache_seconds=1)
    port = srv.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    print(f"  {base_url}/")
    print(f"  CRL: {base_url}/crl.pem")

    # ---- 3. Листья с AIA/CRL DP ----
    print()
    print("=== 3. Issue 3 leaves with CRL DP + AIA OCSP ===")
    leaves = []
    for name in ("a.example", "b.example", "c.example"):
        leaf = (CertificateBuilder()
            .add_subject({"CN": name})
            .add_issuer(ca)
            .add_public_key(Ed25519Keys.generate())
            .add_serial_random().add_validity(days=30)
            .add_san_dns(name)
            .add_crl_distribution_point(f"{base_url}/crl.pem")
            .add_aia(ocsp=[f"{base_url}/ocsp"])
            .sign(ca_key))
        leaves.append(leaf)
        print(f"  {name}: serial=0x{leaf.serial:x}")
        print(f"    CRL DP:   {leaf.crl_distribution_points}")
        print(f"    AIA OCSP: {leaf.aia_ocsp}")

    # ---- 4. Проверка ДО отзыва ----
    print()
    print("=== 4. Fetch CRL + OCSP (before revocation) ===")
    for leaf in leaves:
        crl = leaf.fetch_crl(ca=ca)
        in_crl = crl.is_revoked(leaf)
        ocsp = leaf.fetch_ocsp(issuer=ca)
        print(f"  {leaf.subject.get('CN')}:")
        print(f"    CRL entries: {len(crl.revoked)}, in CRL: {in_crl}")
        print(f"    OCSP status: {ocsp['status']}")

    # ---- 5. Отзыв ----
    print()
    print("=== 5. Revoke b.example ===")
    ca.revoke(leaves[1], reason="keyCompromise")
    print(f"  b.example revoked, reason=keyCompromise")

    # ---- 6. Проверка ПОСЛЕ отзыва ----
    print()
    print("=== 6. Fetch CRL + OCSP (after revocation) ===")
    time.sleep(0.1)
    for leaf in leaves:
        cn = leaf.subject.get("CN")
        crl = leaf.fetch_crl(ca=ca)
        ocsp = leaf.fetch_ocsp(issuer=ca)
        print(f"  {cn}:")
        print(f"    in CRL:      {crl.is_revoked(leaf)}")
        print(f"    OCSP status: {ocsp['status']}"
              + (f" (reason={ocsp['reason']})" if ocsp['reason'] else ""))

    # ---- 7. Прямая проверка через urllib ----
    print()
    print("=== 7. Raw HTTP check ===")
    with urllib.request.urlopen(f"{base_url}/crl.pem", timeout=5) as r:
        crl_pem = r.read().decode()
    print(f"  /crl.pem: {len(crl_pem)} chars, first line:")
    print(f"    {crl_pem.splitlines()[0]}")

    print()
    print("Done. Server still running; Ctrl+C to exit.")
    srv.shutdown()


if __name__ == "__main__":
    main()
