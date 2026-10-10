"""14 - Минимальный ACME-клиент для локального сервера.

Run (в другом терминале, пока сервер работает):
    python examples/14_acme_client.py

Создаёт аккаунт Ed25519, заказывает сертификат для "example.local",
проходит http-01 challenge (auto_verify), финализирует и скачивает cert.
"""
import json
import sys
import urllib.request
from base64 import urlsafe_b64decode, urlsafe_b64encode

from x509kit import CSRBuilder, Ed25519Keys


def b64u(data):
    if isinstance(data, str):
        data = data.encode()
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def http(method, url, body=None, headers=None):
    req = urllib.request.Request(url, method=method)
    if body is not None:
        req.data = body if isinstance(body, bytes) else body.encode()
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req) as r:
        data = r.read()
        return r.status, dict(r.headers), data


def jws_body(payload: dict, protected_extra: dict, key):
    protected = dict(protected_extra)
    protected_b64 = b64u(json.dumps(protected, separators=(",", ":")))
    payload_b64 = b64u(json.dumps(payload, separators=(",", ":")))
    signing_input = (protected_b64 + "." + payload_b64).encode()
    sig = key.sign(signing_input)
    return json.dumps({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64u(sig),
    }, separators=(",", ":")).encode()


def main():
    BASE = "http://127.0.0.1:14000"

    # --- 1. Directory ---
    print("[1] GET /directory")
    _, _, body = http("GET", f"{BASE}/directory")
    directory = json.loads(body)
    print(f"    newAccount: {directory['newAccount']}")

    # --- 2. new-nonce ---
    print("[2] HEAD /new-nonce")
    _, hdrs, _ = http("HEAD", directory["newNonce"])
    nonce = hdrs["Replay-Nonce"]
    print(f"    nonce: {nonce[:16]}…")

    # --- 3. Ключ аккаунта ---
    account_key = Ed25519Keys.generate()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64u(account_key.pub),
    }

    # --- 4. new-account ---
    print("[3] POST /new-account")
    body = jws_body(
        {"termsOfServiceAgreed": True, "contact": []},
        {"alg": "EdDSA", "jwk": jwk, "nonce": nonce,
         "url": directory["newAccount"]},
        account_key,
    )
    status, hdrs, _ = http("POST", directory["newAccount"], body,
                            {"Content-Type": "application/jose+json"})
    kid = hdrs["Location"]
    nonce = hdrs["Replay-Nonce"]
    print(f"    kid: {kid}")

    # --- 5. new-order ---
    print("[4] POST /new-order")
    order_payload = {
        "identifiers": [{"type": "dns", "value": "example.local"}],
    }
    body = jws_body(
        order_payload,
        {"alg": "EdDSA", "kid": kid, "nonce": nonce,
         "url": directory["newOrder"]},
        account_key,
    )
    _, hdrs, raw = http("POST", directory["newOrder"], body,
                        {"Content-Type": "application/jose+json"})
    nonce = hdrs["Replay-Nonce"]
    order = json.loads(raw)
    print(f"    status: {order['status']}")
    authz_url = order["authorizations"][0]

    # --- 6. authz ---
    print("[5] POST /authz/<id>  (POST-as-GET)")
    body = jws_body({}, {"alg": "EdDSA", "kid": kid, "nonce": nonce,
                          "url": authz_url}, account_key)
    _, hdrs, raw = http("POST", authz_url, body,
                        {"Content-Type": "application/jose+json"})
    nonce = hdrs["Replay-Nonce"]
    authz = json.loads(raw)
    chal_url = authz["challenges"][0]["url"]
    print(f"    authz status: {authz['status']}")
    print(f"    challenge:    {authz['challenges'][0]['type']}")

    # --- 7. Trigger challenge ---
    print("[6] POST /challenge/<id>")
    body = jws_body({}, {"alg": "EdDSA", "kid": kid, "nonce": nonce,
                          "url": chal_url}, account_key)
    _, hdrs, raw = http("POST", chal_url, body,
                        {"Content-Type": "application/jose+json"})
    nonce = hdrs["Replay-Nonce"]
    chal = json.loads(raw)
    print(f"    challenge status: {chal['status']}")
    if chal["status"] != "valid":
        print(f"    error: {chal.get('error', {}).get('detail', '?')}")
        sys.exit(1)

    # --- 8. Finalize ---
    print("[7] POST /finalize/<order>")
    leaf_key = Ed25519Keys.generate()
    csr = (CSRBuilder()
        .add_subject({"CN": "example.local"})
        .add_public_key(leaf_key)
        .add_san_dns("example.local")
        .sign(leaf_key))
    finalize_payload = {"csr": b64u(csr.der)}
    body = jws_body(
        finalize_payload,
        {"alg": "EdDSA", "kid": kid, "nonce": nonce,
         "url": order["finalize"]},
        account_key,
    )
    _, hdrs, raw = http("POST", order["finalize"], body,
                        {"Content-Type": "application/jose+json"})
    nonce = hdrs["Replay-Nonce"]
    order2 = json.loads(raw)
    cert_url = order2["certificate"]
    print(f"    order status: {order2['status']}")
    print(f"    certificate:  {cert_url}")

    # --- 9. Download certificate ---
    print("[8] POST /cert/<id>  (POST-as-GET)")
    body = jws_body({}, {"alg": "EdDSA", "kid": kid, "nonce": nonce,
                          "url": cert_url}, account_key)
    _, _, raw = http("POST", cert_url, body,
                     {"Content-Type": "application/jose+json"})
    pem = raw.decode()
    print()
    print("=== Certificate (first 400 chars) ===")
    print(pem[:400])

    open("acme_leaf.pem", "w").write(pem)
    print()
    print("Saved: acme_leaf.pem")


if __name__ == "__main__":
    main()
