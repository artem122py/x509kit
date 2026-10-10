# -*- coding: utf-8 -*-
"""
x509kit.acme — минимальный ACME-сервер (RFC 8555) поверх x509kit.

Поддерживает:
  directory, new-nonce, new-account (jwk), new-order, authz,
  http-01 challenge, finalize (CSR → cert), cert download.

Не поддерживает:
  DNS-01, TLS-ALPN-01, wildcard, external account binding,
  key rollover, revocation.

Состояние — в памяти. Перезапуск → всё потеряно.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.request
from datetime import datetime, timedelta, timezone

from .x509 import (
    ASN1, CertificateBuilder, CACert, CSR, der_int, der_seq,
    Ed25519Keys, ECDSAKeys, RSAKeys, X509Error,
)


# ======================================================================
#  Base64url (RFC 4648 §5)
# ======================================================================

def b64u(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("ascii")
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ======================================================================
#  JWK (RFC 7517) и thumbprint (RFC 7638)
# ======================================================================

def jwk_to_key(jwk: dict):
    """JWK dict → публичный ключ x509kit."""
    kty = jwk.get("kty")
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519Keys(pub=b64u_decode(jwk["x"]))
    if kty == "EC":
        crv = jwk.get("crv")
        curve_oid = {"P-256": "1.2.840.10045.3.1.7",
                     "P-384": "1.3.132.0.34",
                     "P-521": "1.3.132.0.35"}.get(crv)
        if curve_oid is None:
            raise X509Error(f"unsupported EC curve: {crv}")
        x = int.from_bytes(b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(b64u_decode(jwk["y"]), "big")
        return ECDSAKeys(curve_oid, point=(x, y))
    if kty == "RSA":
        n = int.from_bytes(b64u_decode(jwk["n"]), "big")
        e = int.from_bytes(b64u_decode(jwk["e"]), "big")
        return RSAKeys(n=n, e=e)
    raise X509Error(f"unsupported JWK kty={kty}")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint (base64url SHA-256)."""
    kty = jwk["kty"]
    if kty == "OKP":
        canonical = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"]}
    elif kty == "EC":
        canonical = {"crv": jwk["crv"], "kty": kty,
                     "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        canonical = {"e": jwk["e"], "kty": kty, "n": jwk["n"]}
    else:
        raise X509Error(f"unsupported kty: {kty}")
    js = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(js.encode("utf-8")).digest())


# ======================================================================
#  JWS verification (RFC 7515)
# ======================================================================

def _ecdsa_raw_to_der(raw: bytes) -> bytes:
    """64 байта r||s → DER SEQUENCE."""
    if len(raw) % 2 != 0:
        raise X509Error(f"bad ECDSA sig length: {len(raw)}")
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    return der_seq(der_int(r), der_int(s))


class JWSResult:
    __slots__ = ("protected", "payload", "key", "jwk", "kid",
                 "url", "nonce", "alg")

    def __init__(self, protected, payload, key, jwk, kid, url, nonce, alg):
        self.protected = protected
        self.payload = payload
        self.key = key
        self.jwk = jwk
        self.kid = kid
        self.url = url
        self.nonce = nonce
        self.alg = alg


def verify_jws(jws: dict, *, expected_url: str,
               nonce_checker=None, key_resolver=None) -> JWSResult:
    """Проверить JWS. Все ошибки → X509Error.

    jws = {"protected": b64u, "payload": b64u, "signature": b64u}
    """
    try:
        protected_b64 = jws["protected"]
        payload_b64 = jws.get("payload", "")
        signature_b64 = jws["signature"]
    except KeyError as e:
        raise X509Error(f"JWS missing field: {e}")

    try:
        protected = json.loads(b64u_decode(protected_b64))
    except Exception as e:
        raise X509Error(f"JWS protected header is not valid JSON: {e}")

    try:
        payload = json.loads(b64u_decode(payload_b64)) if payload_b64 else {}
    except Exception as e:
        raise X509Error(f"JWS payload is not valid JSON: {e}")

    # --- URL ---
    url = protected.get("url")
    if url != expected_url:
        raise X509Error(f"JWS url mismatch: {url!r} != {expected_url!r}")

    # --- nonce ---
    nonce = protected.get("nonce")
    if not nonce:
        raise X509Error("JWS missing nonce")
    if nonce_checker is not None and not nonce_checker(nonce):
        raise X509Error(f"JWS bad or reused nonce: {nonce!r}")

    # --- key: jwk (для new-account) или kid (для остальных) ---
    has_jwk = "jwk" in protected
    has_kid = "kid" in protected
    if has_jwk and has_kid:
        raise X509Error("JWS must have jwk OR kid, not both")
    if not has_jwk and not has_kid:
        raise X509Error("JWS must have either jwk or kid")

    if has_jwk:
        jwk = protected["jwk"]
        key = jwk_to_key(jwk)
        kid = None
    else:
        kid = protected["kid"]
        if key_resolver is None:
            raise X509Error("JWS uses kid, but no key resolver provided")
        key = key_resolver(kid)
        jwk = None

    # --- signature ---
    alg = protected.get("alg")
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    try:
        signature = b64u_decode(signature_b64)
    except Exception as e:
        raise X509Error(f"JWS signature is not valid base64url: {e}")

    if alg == "EdDSA":
        if not isinstance(key, Ed25519Keys):
            raise X509Error("alg=EdDSA but key is not Ed25519")
        ok = key.verify(signing_input, signature)
    elif alg in ("ES256", "ES384", "ES512"):
        if not isinstance(key, ECDSAKeys):
            raise X509Error(f"alg={alg} but key is not ECDSA")
        hash_name = {"ES256": "sha256", "ES384": "sha384", "ES512": "sha512"}[alg]
        try:
            der_sig = _ecdsa_raw_to_der(signature)
        except X509Error:
            raise
        ok = key.verify(signing_input, der_sig, hash_name)
    elif alg == "RS256":
        if not isinstance(key, RSAKeys):
            raise X509Error("alg=RS256 but key is not RSA")
        ok = key.verify_pkcs1v15(signing_input, signature, "sha256")
    else:
        raise X509Error(f"unsupported JWS alg: {alg}")

    if not ok:
        raise X509Error("JWS signature invalid")

    return JWSResult(protected, payload, key, jwk, kid, url, nonce, alg)


# ======================================================================
#  ACME errors
# ======================================================================

class ACMEError(X509Error):
    """Ошибка ACME с типом (urn:ietf:params:acme:error:...) и HTTP-кодом."""

    def __init__(self, kind: str, detail: str, status: int = 400):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail
        self.status = status


def _acme_problem(err: ACMEError) -> dict:
    return {
        "type": f"urn:ietf:params:acme:error:{err.kind}",
        "detail": err.detail,
    }


# ======================================================================
#  ACME Server
# ======================================================================

class ACMEServer:
    """Минимальный ACME-сервер с http-01 challenge.

    ca       — CACert (CA:TRUE)
    ca_key   — приватный ключ CA (RSA/Ed25519/ECDSA)
    base_url — базовый URL, например "http://localhost:14000"
    chain    — список промежуточных сертификатов (опционально)
    """

    def __init__(self, ca: CACert, ca_key, base_url: str, *,
                 chain=None, cert_days: int = 90, auto_verify: bool = False):
        if not ca_key.is_private:
            raise X509Error("ca_key must be a private key")
        if ca.public_key.to_public_pem() != ca_key.to_public_pem():
            raise X509Error("ca_key does not match ca.public_key")

        self.ca = ca
        self.ca_key = ca_key
        self.base_url = base_url.rstrip("/")
        self.chain = list(chain or [])
        self.cert_days = cert_days
        self.auto_verify = auto_verify

        self.nonces: set[str] = set()
        self.accounts: dict[str, dict] = {}       # kid -> {jwk, key, ...}
        self.orders:   dict[str, dict] = {}       # order_id
        self.authzs:   dict[str, dict] = {}       # authz_id
        self.chals:    dict[str, dict] = {}       # chal_id
        self.certs:    dict[str, dict] = {}       # cert_id

    # ---- nonces ----------------------------------------------------
    def new_nonce(self) -> str:
        n = b64u(secrets.token_bytes(16))
        self.nonces.add(n)
        return n

    def consume_nonce(self, n: str) -> bool:
        if n in self.nonces:
            self.nonces.discard(n)
            return True
        return False

    # ---- directory -------------------------------------------------
    def directory(self) -> dict:
        return {
            "newNonce":   f"{self.base_url}/new-nonce",
            "newAccount": f"{self.base_url}/new-account",
            "newOrder":   f"{self.base_url}/new-order",
            "revokeCert": f"{self.base_url}/revoke-cert",
            "keyChange":  f"{self.base_url}/key-change",
            "meta": {
                "termsOfService": f"{self.base_url}/tos",
                "website":        self.base_url,
            },
        }

    # ---- accounts --------------------------------------------------
    def new_account(self, jwk: dict, payload: dict):
        thumbprint = jwk_thumbprint(jwk)
        kid = f"{self.base_url}/acct/{thumbprint}"

        if kid in self.accounts:
            return kid, False

        if not payload.get("termsOfServiceAgreed", False):
            raise ACMEError("malformed", "termsOfServiceAgreed must be true")

        self.accounts[kid] = {
            "jwk": jwk,
            "key": jwk_to_key(jwk),
            "contact": payload.get("contact", []),
            "created": time.time(),
        }
        return kid, True

    def account_key(self, kid: str):
        acc = self.accounts.get(kid)
        if acc is None:
            raise ACMEError("accountDoesNotExist", f"unknown kid: {kid}", 400)
        return acc["key"]

    def account_view(self, kid: str) -> dict:
        acc = self.accounts[kid]
        return {
            "status": "valid",
            "contact": acc["contact"],
            "createdAt": datetime.fromtimestamp(
                acc["created"], tz=timezone.utc,
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    # ---- orders ----------------------------------------------------
    def new_order(self, kid: str, payload: dict) -> dict:
        idents = payload.get("identifiers") or []
        if not idents:
            raise ACMEError("malformed", "no identifiers in order")
        for i in idents:
            if i.get("type") != "dns":
                raise ACMEError("unsupportedIdentifier",
                                f"only 'dns' supported, got {i.get('type')}")

        order_id = b64u(secrets.token_bytes(16))
        authz_ids = [self._new_authz(kid, ident) for ident in idents]

        expires = datetime.now(timezone.utc) + timedelta(days=7)
        self.orders[order_id] = {
            "id": order_id,
            "account": kid,
            "status": "pending",
            "identifiers": idents,
            "authz_ids": authz_ids,
            "expires": expires.isoformat(),
            "finalize_url": f"{self.base_url}/finalize/{order_id}",
            "cert_id": None,
        }
        return self._order_view(order_id)

    def _order_view(self, order_id: str) -> dict:
        order = self.orders[order_id]
        self._refresh_order(order)
        view = {
            "id": order_id,
            "status": order["status"],
            "expires": order["expires"],
            "identifiers": order["identifiers"],
            "authorizations": [
                f"{self.base_url}/authz/{a}" for a in order["authz_ids"]
            ],
            "finalize": f"{self.base_url}/finalize/{order_id}",
        }
        if order["cert_id"]:
            view["certificate"] = f"{self.base_url}/cert/{order['cert_id']}"
        return view

    def _refresh_order(self, order: dict) -> None:
        if order["status"] not in ("pending", "ready"):
            return
        all_valid = True
        any_invalid = False
        for a in order["authz_ids"]:
            st = self.authzs[a]["status"]
            if st == "invalid":
                any_invalid = True
                break
            if st != "valid":
                all_valid = False
        if any_invalid:
            order["status"] = "invalid"
        elif all_valid:
            order["status"] = "ready"

    def get_order(self, order_id: str) -> dict:
        if order_id not in self.orders:
            raise ACMEError("orderNotReady", f"unknown order: {order_id}", 404)
        return self._order_view(order_id)

    # ---- authz / challenge ----------------------------------------
    def _new_authz(self, kid: str, ident: dict) -> str:
        authz_id = b64u(secrets.token_bytes(16))
        chal_id = b64u(secrets.token_bytes(16))
        token = b64u(secrets.token_bytes(32))

        jwk = self.accounts[kid]["jwk"]
        key_auth = f"{token}.{jwk_thumbprint(jwk)}"

        self.authzs[authz_id] = {
            "id": authz_id, "account": kid,
            "identifier": ident,
            "status": "pending",
            "challenge_id": chal_id,
        }
        self.chals[chal_id] = {
            "id": chal_id, "authz": authz_id,
            "type": "http-01", "token": token,
            "key_auth": key_auth, "status": "pending",
            "error": None,
        }
        return authz_id

    def get_authz(self, authz_id: str) -> dict:
        a = self.authzs.get(authz_id)
        if a is None:
            raise ACMEError("malformed", f"unknown authz: {authz_id}", 404)
        c = self.chals[a["challenge_id"]]
        return {
            "status": a["status"],
            "expires": (datetime.now(timezone.utc)
                        + timedelta(days=7)).isoformat(),
            "identifier": a["identifier"],
            "challenges": [self._chal_view(c)],
        }

    def _chal_view(self, c: dict) -> dict:
        v = {
            "type": c["type"],
            "url": f"{self.base_url}/challenge/{c['id']}",
            "status": c["status"],
            "token": c["token"],
        }
        if c["error"]:
            v["error"] = {
                "type": "urn:ietf:params:acme:error:unauthorized",
                "detail": c["error"],
            }
        return v

    def trigger_challenge(self, chal_id: str, *, fetcher=None) -> dict:
        c = self.chals.get(chal_id)
        if c is None:
            raise ACMEError("malformed", f"unknown challenge: {chal_id}", 404)
        if c["status"] == "valid":
            return self._chal_view(c)

        authz = self.authzs[c["authz"]]
        domain = authz["identifier"]["value"]
        path = f"/.well-known/acme-challenge/{c['token']}"

        if self.auto_verify:
            c["status"] = "valid"
            authz["status"] = "valid"
            return self._chal_view(c)

        fetch = fetcher or self._default_fetcher
        try:
            body = fetch(f"http://{domain}{path}")
        except Exception as e:
            c["error"] = f"fetch failed: {e}"
            c["status"] = "invalid"
            authz["status"] = "invalid"
            return self._chal_view(c)

        if body.strip() != c["key_auth"]:
            c["error"] = "key authorization mismatch"
            c["status"] = "invalid"
            authz["status"] = "invalid"
            return self._chal_view(c)

        c["status"] = "valid"
        authz["status"] = "valid"
        return self._chal_view(c)

    @staticmethod
    def _default_fetcher(url: str) -> str:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read().decode("utf-8", "replace")

    # ---- finalize --------------------------------------------------
    def finalize(self, order_id: str, payload: dict) -> dict:
        if order_id not in self.orders:
            raise ACMEError("orderNotReady", f"unknown order: {order_id}", 404)
        order = self.orders[order_id]
        self._refresh_order(order)
        if order["status"] != "ready":
            raise ACMEError("orderNotReady",
                            f"order status is {order['status']}, expected ready",
                            403)

        csr_b64 = payload.get("csr")
        if not csr_b64:
            raise ACMEError("malformed", "finalize payload missing csr")
        csr_der = b64u_decode(csr_b64)

        try:
            csr = CSR(csr_der)
        except X509Error as e:
            raise ACMEError("badCSR", f"cannot parse CSR: {e}")
        if not csr.verify_signature():
            raise ACMEError("badCSR", "CSR self-signature invalid")

        csr_names = set(csr.dns_names)
        for ident in order["identifiers"]:
            if ident["value"] not in csr_names:
                raise ACMEError("badCSR",
                                f"CSR missing identifier {ident['value']!r}")

        leaf = (CertificateBuilder.from_csr(csr)
            .add_issuer(self.ca)
            .add_serial_random()
            .add_validity(days=self.cert_days)
            .sign(self.ca_key))

        cert_id = b64u(secrets.token_bytes(16))
        # RFC 8555 §7.4.2: сервер ОБЯЗАН отдать fullchain — leaf + issuer(s).
        # Certbot требует минимум 2 сертификата. Если промежуточных нет,
        # включаем сам CA как последний элемент chain.
        chain_der = [c.der for c in self.chain]
        if not chain_der:
            chain_der = [self.ca.der]
        self.certs[cert_id] = {
            "der": leaf.der,
            "chain_der": chain_der,
            "order": order_id,
        }
        order["status"] = "valid"
        order["cert_id"] = cert_id
        return self._order_view(order_id)

    def get_certificate(self, cert_id: str) -> str:
        c = self.certs.get(cert_id)
        if c is None:
            raise ACMEError("malformed", f"unknown cert: {cert_id}", 404)
        from .x509 import Cert as _C
        pem = _C(c["der"]).to_pem()
        for d in c["chain_der"]:
            pem += _C(d).to_pem()
        return pem

    # ---- persistence ------------------------------------------------

    def to_dict(self) -> dict:
        """Всё состояние сервера в JSON-совместимый dict."""
        return {
            "version": 1,
            "base_url": self.base_url,
            "cert_days": self.cert_days,
            "accounts": {
                kid: {
                    "jwk": acc["jwk"],
                    "contact": acc["contact"],
                    "created": acc["created"],
                } for kid, acc in self.accounts.items()
            },
            "orders": {oid: dict(o) for oid, o in self.orders.items()},
            "authzs": {aid: dict(a) for aid, a in self.authzs.items()},
            "chals": {cid: dict(c) for cid, c in self.chals.items()},
            "certs": {
                cid: {
                    "der": b64u(c["der"]),
                    "chain_der": [b64u(d) for d in c["chain_der"]],
                    "order": c["order"],
                } for cid, c in self.certs.items()
            },
        }

    def save(self, path: str) -> str:
        """Сохранить состояние сервера в JSON-файл. Возвращает путь."""
        path = os.path.expanduser(path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)
        return path

    @classmethod
    def from_dict(cls, ca, ca_key, data: dict, *,
                  chain=None, auto_verify=False) -> "ACMEServer":
        """Восстановить сервер из dict (см. to_dict)."""
        srv = cls(
            ca, ca_key,
            data["base_url"],
            chain=chain,
            cert_days=data.get("cert_days", 90),
            auto_verify=auto_verify,
        )
        for kid, acc in data.get("accounts", {}).items():
            srv.accounts[kid] = {
                "jwk": acc["jwk"],
                "key": jwk_to_key(acc["jwk"]),
                "contact": acc.get("contact", []),
                "created": acc.get("created", time.time()),
            }
        for oid, o in data.get("orders", {}).items():
            srv.orders[oid] = dict(o)
        for aid, a in data.get("authzs", {}).items():
            srv.authzs[aid] = dict(a)
        for cid, c in data.get("chals", {}).items():
            srv.chals[cid] = dict(c)
        for cid, c in data.get("certs", {}).items():
            srv.certs[cid] = {
                "der": b64u_decode(c["der"]),
                "chain_der": [b64u_decode(d) for d in c["chain_der"]],
                "order": c["order"],
            }
        return srv

    @classmethod
    def load(cls, ca, ca_key, path: str, *,
             chain=None, auto_verify=False) -> "ACMEServer":
        """Загрузить сервер из JSON-файла. Если файла нет — создать пустой."""
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            return cls(ca, ca_key,
                       data["base_url"] if "data" in dir() else "http://localhost",
                       chain=chain, auto_verify=auto_verify)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(ca, ca_key, data,
                             chain=chain, auto_verify=auto_verify)

