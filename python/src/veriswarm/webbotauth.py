"""Web Bot Auth request signing (Python SDK).

Signs outbound HTTP requests per the IETF Web Bot Auth profile of RFC 9421
(HTTP Message Signatures) using Ed25519, so a customer's agent is
cryptographically identifiable at the edge (Cloudflare, Google, and other
verifiers that support the directory). VeriSwarm issues the Ed25519 keypair
via ``POST /v1/suite/passport/webbotauth/keys``; the customer holds and
signs with the private key. VeriSwarm never stores it.

This module requires the optional ``cryptography`` package. The base
``veriswarm`` package has zero required dependencies, so ``cryptography``
is imported lazily inside the functions/constructor that need it — never
at module import time — and importing ``veriswarm`` or
``veriswarm.webbotauth`` never requires it to be installed. Install the
extra with::

    pip install veriswarm[webbotauth]

Usage:
    from veriswarm.webbotauth import WebBotAuthSigner

    signer = WebBotAuthSigner(private_key_pem=my_pem, key_id="key_abc123")
    headers = signer.sign_request("https://example.com/api/resource")
    # headers == {"Signature-Agent": ..., "Signature-Input": ..., "Signature": ...}
"""
from __future__ import annotations

import base64
import time
from typing import Any
from urllib.parse import urlparse

DEFAULT_SIGNATURE_AGENT = "https://api.veriswarm.ai"
DEFAULT_EXPIRES_SECONDS = 300
SIGNATURE_TAG = "web-bot-auth"

_DEFAULT_PORTS = {"https": 443, "http": 80}


class WebBotAuthError(ImportError):
    """Raised when signing is attempted without the `cryptography` extra installed.

    Install with: pip install veriswarm[webbotauth]
    """


def _require_cryptography() -> tuple[Any, Any]:
    """Lazily import `cryptography`, raising a clear error if it's missing.

    Returns the (`serialization` module, `Ed25519PrivateKey` class) pair
    callers need. Imported here — never at module top level — so that
    `import veriswarm` and `import veriswarm.webbotauth` work with zero
    dependencies installed.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:
        raise WebBotAuthError(
            "Web Bot Auth signing requires the optional 'cryptography' "
            "package. Install it with: pip install veriswarm[webbotauth]"
        ) from exc
    return serialization, Ed25519PrivateKey


def _quote_string(value: str) -> str:
    """Quote a value as an RFC 8941 String: backslash-escape `\\` and `"`,
    then wrap in double quotes.

    `keyid`, `nonce`, and `signature_agent` are all caller-supplied (nonce
    directly through the public `sign_request()` API) and MUST go through
    this before being interpolated into a quoted-string param. An
    unescaped `"` would otherwise break out of its param and let arbitrary
    extra params be smuggled into both the signed base and the
    Signature-Input header. Mirrors `quoteString` in the Node SDK's
    `webbotauth.mjs` byte-for-byte, so both SDKs produce identical bases
    for identical inputs.
    """
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _derive_authority(url: str) -> str:
    """Derive the RFC 9421 `@authority` component from a request URL.

    Lowercased host, with the port included only when it differs from the
    scheme's default (443 for https, 80 for http).
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"URL has no host to derive an authority from: {url!r}")

    host = parsed.hostname.lower()
    port = parsed.port
    default_port = _DEFAULT_PORTS.get(parsed.scheme)
    if port is not None and port != default_port:
        return f"{host}:{port}"
    return host


def _build_signature_params(
    *,
    created: int,
    expires: int,
    keyid: str,
    nonce: str | None,
    tag: str,
) -> str:
    """Build the params portion shared verbatim by `@signature-params` and
    `Signature-Input`: `("@authority" "signature-agent");created=...;...`.

    Param order is fixed: created, expires, [nonce], keyid, tag.
    """
    parts = [f"created={created}", f"expires={expires}"]
    if nonce is not None:
        parts.append(f"nonce={_quote_string(nonce)}")
    parts.append(f"keyid={_quote_string(keyid)}")
    parts.append(f"tag={_quote_string(tag)}")
    return '("@authority" "signature-agent");' + ";".join(parts)


def build_signature_base(
    *,
    authority: str,
    signature_agent: str,
    created: int,
    expires: int,
    keyid: str,
    nonce: str | None = None,
    tag: str = SIGNATURE_TAG,
) -> str:
    """Build the RFC 9421 signature base string for Web Bot Auth.

    `signature_agent` must already be in wire format — an RFC 8941 String,
    i.e. the directory origin wrapped in double quotes (e.g.
    `"https://api.veriswarm.ai"`) — since that exact value is emitted
    verbatim into the base and is also the `Signature-Agent` header value.

    The verifier reconstructs this same string from the `@authority`,
    `Signature-Agent`, and `Signature-Input` headers of the request it
    receives, so every byte here is load-bearing.
    """
    params = _build_signature_params(
        created=created, expires=expires, keyid=keyid, nonce=nonce, tag=tag
    )
    return (
        f'"@authority": {authority}\n'
        f'"signature-agent": {signature_agent}\n'
        f'"@signature-params": {params}'
    )


class WebBotAuthSigner:
    """Signs outbound HTTP requests per the IETF Web Bot Auth profile of
    RFC 9421 (HTTP Message Signatures, Ed25519).

    Usage:
        signer = WebBotAuthSigner(private_key_pem=my_pem, key_id="key_abc123")
        headers = signer.sign_request("https://example.com/api/resource")
    """

    def __init__(
        self,
        private_key_pem: str,
        key_id: str,
        signature_agent: str = DEFAULT_SIGNATURE_AGENT,
    ) -> None:
        if not private_key_pem or not private_key_pem.strip():
            raise ValueError("private_key_pem is required")
        if not key_id or not key_id.strip():
            raise ValueError("key_id is required")
        if not signature_agent or not signature_agent.strip():
            raise ValueError("signature_agent is required")

        serialization, ed25519_private_key_cls = _require_cryptography()

        try:
            key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"), password=None
            )
        except Exception as exc:
            raise ValueError(f"Could not parse private_key_pem: {exc}") from exc

        if not isinstance(key, ed25519_private_key_cls):
            raise ValueError(
                "private_key_pem must be an Ed25519 private key "
                f"(got {type(key).__name__})"
            )

        self._private_key = key
        self.key_id = key_id
        # RFC 8941 String — quoted (and escaped) once here, reused verbatim
        # as both the Signature-Agent header value and the base's
        # signature-agent line.
        self.signature_agent = _quote_string(signature_agent)

    def sign_request(
        self,
        url: str,
        *,
        created: int | None = None,
        expires_in_seconds: int = DEFAULT_EXPIRES_SECONDS,
        nonce: str | None = None,
    ) -> dict[str, str]:
        """Sign a request URL, returning the three Web Bot Auth headers to
        attach: `Signature-Agent`, `Signature-Input`, `Signature`.
        """
        if not url or not url.strip():
            raise ValueError("url is required")
        if expires_in_seconds <= 0:
            raise ValueError("expires_in_seconds must be positive")

        authority = _derive_authority(url)
        if created is None:
            created = int(time.time())
        expires = created + expires_in_seconds

        base = build_signature_base(
            authority=authority,
            signature_agent=self.signature_agent,
            created=created,
            expires=expires,
            keyid=self.key_id,
            nonce=nonce,
        )
        # Extract the params substring straight out of the base we just
        # signed (rather than recomputing it) so Signature-Input is
        # structurally guaranteed byte-identical to what's inside
        # `@signature-params`, not merely "should match by determinism".
        params = base.split('"@signature-params": ', 1)[1]

        signature_bytes = self._private_key.sign(base.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        return {
            "Signature-Agent": self.signature_agent,
            "Signature-Input": f"sig1={params}",
            "Signature": f"sig1=:{signature_b64}:",
        }
