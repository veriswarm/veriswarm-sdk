"""Tests for Passport agent manifest Ed25519 signing."""
from __future__ import annotations

import base64
import inspect
import subprocess
import sys
import textwrap

import pytest

from veriswarm.manifest_signing import (
    ManifestSigningError,
    canonical_manifest_content,
    sign_manifest,
)

# ---------------------------------------------------------------------------
# Golden vector — computed from the server's own canonicalization
# (apps/api/app/services/manifest_hashing.py::_manifest_content_dict). Do
# NOT change these values; if a test fails against them, the bug is in this
# SDK's canonicalization, not the vector.
# ---------------------------------------------------------------------------

GOLDEN_SEED_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
GOLDEN_PUBLIC_KEY_B64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
GOLDEN_VERSION = "1.0"
GOLDEN_CAPABILITIES = ["calendar.read", "email.send"]
GOLDEN_REQUIRED_TOOLS = ["calendar"]
GOLDEN_AI_DISCLOSURE = "You are chatting with an AI assistant operated by Acme Corp."
GOLDEN_PRINCIPAL_REF = {
    "type": "organization",
    "name": "Acme Corp",
    "identifier": "acme-001",
    "source": "explicit",
}
GOLDEN_CANONICAL_CONTENT = (
    '{"ai_disclosure":"You are chatting with an AI assistant operated by Acme Corp.",'
    '"capabilities":["calendar.read","email.send"],'
    '"principal_ref":{"identifier":"acme-001","name":"Acme Corp","source":"explicit","type":"organization"},'
    '"required_tools":["calendar"],'
    '"version":"1.0"}'
)
GOLDEN_SIGNATURE_B64 = (
    "c305VIG0K4UqbtUfc5haTC2q2TyS95uPCHWOSM4WqOSmEDnRF/snBVWFc3YAyL2lz01DjK9HDMVspmxrdM/pCA=="
)
GOLDEN_KID = "kid_golden"


def _golden_private_key_pem() -> str:
    """Build the golden Ed25519 private key's PKCS8 PEM from its raw seed."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = base64.b64decode(GOLDEN_SEED_B64)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _fresh_keypair():
    """Generate a fresh Ed25519 keypair + PKCS8 PEM. Skips if cryptography is absent."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return private_key, pem


# ---------------------------------------------------------------------------
# 1. Canonicalization (no crypto required)
# ---------------------------------------------------------------------------


def test_canonical_manifest_content_matches_golden_string():
    canonical = canonical_manifest_content(
        version=GOLDEN_VERSION,
        capabilities=GOLDEN_CAPABILITIES,
        required_tools=GOLDEN_REQUIRED_TOOLS,
        ai_disclosure=GOLDEN_AI_DISCLOSURE,
        principal_ref=GOLDEN_PRINCIPAL_REF,
    )
    assert canonical == GOLDEN_CANONICAL_CONTENT


# ---------------------------------------------------------------------------
# 2. Golden signature match
# ---------------------------------------------------------------------------


def test_sign_manifest_matches_golden_signature():
    pem = _golden_private_key_pem()
    result = sign_manifest(
        version=GOLDEN_VERSION,
        capabilities=GOLDEN_CAPABILITIES,
        required_tools=GOLDEN_REQUIRED_TOOLS,
        ai_disclosure=GOLDEN_AI_DISCLOSURE,
        principal_ref=GOLDEN_PRINCIPAL_REF,
        private_key_pem=pem,
        kid=GOLDEN_KID,
    )
    assert result["signature"] == GOLDEN_SIGNATURE_B64
    assert result["signing_kid"] == GOLDEN_KID


def test_golden_public_key_verifies_golden_signature():
    """Independent cross-check: the published golden public key verifies the
    published golden signature over the published golden canonical content."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(GOLDEN_PUBLIC_KEY_B64)
    )
    public_key.verify(
        base64.b64decode(GOLDEN_SIGNATURE_B64),
        GOLDEN_CANONICAL_CONTENT.encode("utf-8"),
    )  # raises InvalidSignature on mismatch


# ---------------------------------------------------------------------------
# 3. Round-trip: fresh key -> sign -> verify; tampered content fails
# ---------------------------------------------------------------------------


def test_round_trip_fresh_key_sign_and_verify():
    from cryptography.exceptions import InvalidSignature

    private_key, pem = _fresh_keypair()
    public_key = private_key.public_key()

    result = sign_manifest(
        version="2.0",
        capabilities=["kb.read"],
        required_tools=[],
        ai_disclosure=None,
        principal_ref=None,
        private_key_pem=pem,
        kid="kid_fresh",
    )
    canonical = canonical_manifest_content(
        version="2.0",
        capabilities=["kb.read"],
        required_tools=[],
        ai_disclosure=None,
        principal_ref=None,
    )
    signature = base64.b64decode(result["signature"])

    # Verifies against the correct content.
    public_key.verify(signature, canonical.encode("utf-8"))

    # Tampered content must fail verification.
    tampered = canonical.replace("2.0", "3.0")
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, tampered.encode("utf-8"))


# ---------------------------------------------------------------------------
# 4. Nested-sort proof: reversed key order in principal_ref
# ---------------------------------------------------------------------------


def test_canonical_content_sorts_nested_principal_ref_keys():
    reversed_principal_ref = {
        "source": "explicit",
        "identifier": "acme-001",
        "name": "Acme Corp",
        "type": "organization",
    }
    canonical = canonical_manifest_content(
        version=GOLDEN_VERSION,
        capabilities=GOLDEN_CAPABILITIES,
        required_tools=GOLDEN_REQUIRED_TOOLS,
        ai_disclosure=GOLDEN_AI_DISCLOSURE,
        principal_ref=reversed_principal_ref,
    )
    assert canonical == GOLDEN_CANONICAL_CONTENT


# ---------------------------------------------------------------------------
# 5. Unset fields render as null; lists are sorted
# ---------------------------------------------------------------------------


def test_unset_fields_render_as_null_and_lists_are_sorted():
    canonical = canonical_manifest_content(version="1.0")
    assert canonical == (
        '{"ai_disclosure":null,"capabilities":[],"principal_ref":null,'
        '"required_tools":[],"version":"1.0"}'
    )


def test_capabilities_and_required_tools_are_sorted_ascending():
    canonical = canonical_manifest_content(
        version="1.0",
        capabilities=["email.send", "calendar.read"],
        required_tools=["slack", "calendar"],
    )
    assert '"capabilities":["calendar.read","email.send"]' in canonical
    assert '"required_tools":["calendar","slack"]' in canonical


# ---------------------------------------------------------------------------
# 6. Input validation
# ---------------------------------------------------------------------------


def test_sign_manifest_rejects_missing_version():
    pem = _golden_private_key_pem()
    with pytest.raises(ValueError):
        sign_manifest(version="", private_key_pem=pem, kid="k1")


def test_sign_manifest_rejects_missing_kid():
    pem = _golden_private_key_pem()
    with pytest.raises(ValueError):
        sign_manifest(version="1.0", private_key_pem=pem, kid="")


def test_sign_manifest_rejects_missing_private_key_pem():
    with pytest.raises(ValueError):
        sign_manifest(version="1.0", private_key_pem="", kid="k1")


def test_sign_manifest_rejects_unparseable_pem():
    pytest.importorskip("cryptography")
    with pytest.raises(ValueError):
        sign_manifest(version="1.0", private_key_pem="not a pem", kid="k1")


def test_sign_manifest_rejects_non_ed25519_key():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    with pytest.raises(ValueError):
        sign_manifest(version="1.0", private_key_pem=pem, kid="k1")


# ---------------------------------------------------------------------------
# 7. Zero-dependency guard
# ---------------------------------------------------------------------------


def test_no_top_level_cryptography_import_in_source():
    """The manifest_signing module and package __init__ must not import
    `cryptography` at module top level — only lazily, inside the functions
    that need it."""
    import veriswarm as veriswarm_pkg
    import veriswarm.manifest_signing as manifest_signing_module

    for module in (veriswarm_pkg, manifest_signing_module):
        source = inspect.getsource(module)
        for line in source.splitlines():
            if line.startswith("import cryptography") or line.startswith("from cryptography"):
                pytest.fail(
                    f"top-level `cryptography` import found in {module.__name__}: {line!r}"
                )


def test_import_veriswarm_succeeds_without_cryptography():
    """Simulates a zero-dep install: block `cryptography` at import time via
    a meta-path finder, then assert `import veriswarm` and
    `import veriswarm.manifest_signing` still succeed, and that calling
    `sign_manifest` raises a clear ImportError telling the user to install
    the extra. `canonical_manifest_content` needs no crypto at all."""
    script = textwrap.dedent(
        """
        import sys

        class _BlockCryptography:
            def find_spec(self, name, path, target=None):
                if name == "cryptography" or name.startswith("cryptography."):
                    raise ImportError(f"'{name}' is blocked for this test")
                return None

        sys.meta_path.insert(0, _BlockCryptography())

        import veriswarm  # noqa: F401
        from veriswarm.manifest_signing import canonical_manifest_content, sign_manifest  # noqa: F401

        canonical = canonical_manifest_content(version="1.0", capabilities=["a"])
        assert canonical == '{"ai_disclosure":null,"capabilities":["a"],"principal_ref":null,"required_tools":[],"version":"1.0"}'

        try:
            sign_manifest(version="1.0", private_key_pem="dummy", kid="k1")
        except ImportError as exc:
            assert "veriswarm[webbotauth]" in str(exc), str(exc)
        else:
            raise SystemExit("expected ImportError when cryptography is unavailable")

        print("OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "OK" in result.stdout


def test_manifest_signing_error_is_import_error_subclass():
    assert issubclass(ManifestSigningError, ImportError)
