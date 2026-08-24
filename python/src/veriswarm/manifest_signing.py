"""Passport agent manifest signing (Python SDK).

Signs the canonical content of a Passport agent manifest with Ed25519 so the
VeriSwarm API's ``create_manifest`` endpoint (``POST
/v1/suite/passport/manifests/{agent_id}``) can verify the manifest was
produced by the key holder. VeriSwarm issues the Ed25519 keypair via ``POST
/v1/suite/passport/webbotauth/keys``; the customer holds and signs with the
private key. VeriSwarm never stores it.

Canonicalization MUST match the server exactly — see
``apps/api/app/services/manifest_hashing.py::_manifest_content_dict`` in the
main VeriSwarm repo. The signed content is the 5-key dict
``{version, capabilities, required_tools, ai_disclosure, principal_ref}``,
with ``capabilities``/``required_tools`` sorted ascending and
``ai_disclosure``/``principal_ref`` always present (``None`` when unset),
serialized via ``json.dumps(content, sort_keys=True, separators=(",", ":"))``.
Because ``sort_keys=True`` sorts nested dict keys recursively, building the
same dict (with pre-sorted lists) and calling ``json.dumps`` the same way
reproduces the server's canonical string byte-for-byte, including for a
nested ``principal_ref`` supplied in any key order.

This module requires the optional ``cryptography`` package. The base
``veriswarm`` package has zero required dependencies, so ``cryptography``
is imported lazily inside the functions that need it — never at module
import time — and importing ``veriswarm`` or ``veriswarm.manifest_signing``
never requires it to be installed. Install the extra with::

    pip install veriswarm[webbotauth]

Usage:
    from veriswarm.manifest_signing import sign_manifest

    result = sign_manifest(
        version="1.0",
        capabilities=["calendar.read", "email.send"],
        required_tools=["calendar"],
        ai_disclosure="You are chatting with an AI assistant operated by Acme Corp.",
        principal_ref={
            "type": "organization",
            "name": "Acme Corp",
            "identifier": "acme-001",
            "source": "explicit",
        },
        private_key_pem=my_pem,
        kid="key_abc123",
    )
    # result == {"signature": "...", "signing_kid": "key_abc123"}
    # Submit `signature` + `signing_kid` as the manifest's `signature` /
    # `signing_kid` fields on create.
"""
from __future__ import annotations

import base64
import json
from typing import Any


class ManifestSigningError(ImportError):
    """Raised when signing is attempted without the `cryptography` extra installed.

    Install with: pip install veriswarm[webbotauth]
    """


def _require_cryptography() -> Any:
    """Lazily import the `cryptography` Ed25519 private key class, raising a
    clear error if it's missing.

    Imported here — never at module top level — so that `import veriswarm`
    and `import veriswarm.manifest_signing` work with zero dependencies
    installed.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:
        raise ManifestSigningError(
            "Manifest signing requires the optional 'cryptography' package. "
            "Install it with: pip install veriswarm[webbotauth]"
        ) from exc
    return serialization, Ed25519PrivateKey


def _manifest_content_dict(
    *,
    version: str,
    capabilities: list[str] | None,
    required_tools: list[str] | None,
    ai_disclosure: str | None,
    principal_ref: dict[str, Any] | None,
) -> dict[str, Any]:
    """Canonical hashed/signed manifest content — mirrors the server's
    ``_manifest_content_dict`` in ``apps/api/app/services/manifest_hashing.py``
    key-for-key. ``ai_disclosure`` and ``principal_ref`` are ALWAYS present
    as keys (with explicit ``None`` when unset) so manifests hash over the
    same key set deterministically regardless of which fields are supplied.
    """
    return {
        "version": version,
        "capabilities": sorted(capabilities or []),
        "required_tools": sorted(required_tools or []),
        "ai_disclosure": ai_disclosure,
        "principal_ref": principal_ref,
    }


def canonical_manifest_content(
    *,
    version: str,
    capabilities: list[str] | None = None,
    required_tools: list[str] | None = None,
    ai_disclosure: str | None = None,
    principal_ref: dict[str, Any] | None = None,
) -> str:
    """Build the canonical JSON string the server hashes/signs over.

    Equivalent to the server's
    ``json.dumps(_manifest_content_dict(...), sort_keys=True, separators=(",", ":"))``.
    ``json.dumps(sort_keys=True)`` sorts nested keys recursively, so a
    ``principal_ref`` dict supplied in any key order produces the same
    canonical string.
    """
    content = _manifest_content_dict(
        version=version,
        capabilities=capabilities,
        required_tools=required_tools,
        ai_disclosure=ai_disclosure,
        principal_ref=principal_ref,
    )
    return json.dumps(content, sort_keys=True, separators=(",", ":"))


def sign_manifest(
    *,
    version: str,
    capabilities: list[str] | None = None,
    required_tools: list[str] | None = None,
    ai_disclosure: str | None = None,
    principal_ref: dict[str, Any] | None = None,
    private_key_pem: str,
    kid: str,
) -> dict[str, str]:
    """Sign a Passport agent manifest's canonical content with Ed25519.

    Returns ``{"signature": <base64>, "signing_kid": kid}`` — submit both
    as the manifest's ``signature`` / ``signing_kid`` fields on
    ``POST /v1/suite/passport/manifests/{agent_id}``.
    """
    if not version or not str(version).strip():
        raise ValueError("version is required")
    if not private_key_pem or not private_key_pem.strip():
        raise ValueError("private_key_pem is required")
    if not kid or not kid.strip():
        raise ValueError("kid is required")

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

    canonical = canonical_manifest_content(
        version=version,
        capabilities=capabilities,
        required_tools=required_tools,
        ai_disclosure=ai_disclosure,
        principal_ref=principal_ref,
    )
    signature_bytes = key.sign(canonical.encode("utf-8"))
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    return {"signature": signature_b64, "signing_kid": kid}
