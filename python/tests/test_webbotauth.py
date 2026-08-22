"""Tests for Web Bot Auth (RFC 9421 Ed25519 HTTP Message Signatures) signing."""
from __future__ import annotations

import inspect
import re
import subprocess
import sys
import textwrap

import pytest

from veriswarm.webbotauth import (
    DEFAULT_SIGNATURE_AGENT,
    WebBotAuthError,
    WebBotAuthSigner,
    _derive_authority,
    build_signature_base,
)

QUOTED_DEFAULT_AGENT = f'"{DEFAULT_SIGNATURE_AGENT}"'


def _keypair():
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
# 1. Known-answer round trip
# ---------------------------------------------------------------------------


def test_signature_verifies_against_reconstructed_base():
    private_key, pem = _keypair()
    public_key = private_key.public_key()

    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    headers = signer.sign_request("https://example.com/a/b?q=1", created=1_700_000_000)

    sig_input = headers["Signature-Input"]
    assert sig_input.startswith("sig1=")
    params = sig_input[len("sig1="):]

    base = build_signature_base(
        authority="example.com",
        signature_agent=QUOTED_DEFAULT_AGENT,
        created=1_700_000_000,
        expires=1_700_000_300,
        keyid="key-1",
    )
    assert base.endswith(params)

    sig_match = re.match(r"^sig1=:([A-Za-z0-9+/=]+):$", headers["Signature"])
    assert sig_match is not None
    import base64
    signature_bytes = base64.b64decode(sig_match.group(1))

    # Verifies cleanly against the true base.
    public_key.verify(signature_bytes, base.encode("utf-8"))


def test_tampered_base_fails_verification():
    from cryptography.exceptions import InvalidSignature

    private_key, pem = _keypair()
    public_key = private_key.public_key()

    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    headers = signer.sign_request("https://example.com/a/b?q=1", created=1_700_000_000)

    base = build_signature_base(
        authority="example.com",
        signature_agent=QUOTED_DEFAULT_AGENT,
        created=1_700_000_000,
        expires=1_700_000_300,
        keyid="key-1",
    )
    import base64
    sig_match = re.match(r"^sig1=:([A-Za-z0-9+/=]+):$", headers["Signature"])
    signature_bytes = base64.b64decode(sig_match.group(1))

    tampered = base + "\ntampered"
    with pytest.raises(InvalidSignature):
        public_key.verify(signature_bytes, tampered.encode("utf-8"))


# ---------------------------------------------------------------------------
# 2. Signature-Input round-trips byte-identical against the actual signed base
# ---------------------------------------------------------------------------


def test_signature_input_params_are_byte_identical_to_signed_base(monkeypatch):
    import veriswarm.webbotauth as webbotauth_module

    captured: dict[str, str] = {}
    original = webbotauth_module.build_signature_base

    def spy(**kwargs):
        result = original(**kwargs)
        captured["base"] = result
        return result

    monkeypatch.setattr(webbotauth_module, "build_signature_base", spy)

    private_key, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    headers = signer.sign_request(
        "https://example.com/x", created=1_700_000_000, nonce="n-123"
    )

    assert "base" in captured
    base = captured["base"]
    header_params = headers["Signature-Input"][len("sig1="):]
    base_params = base.split('"@signature-params": ', 1)[1]
    assert base_params == header_params


# ---------------------------------------------------------------------------
# 3. Header shape
# ---------------------------------------------------------------------------


def test_signature_header_matches_expected_shape():
    private_key, pem = _keypair()
    signer = WebBotAuthSigner(
        private_key_pem=pem, key_id="key-1", signature_agent="https://api.veriswarm.ai"
    )
    headers = signer.sign_request("https://example.com/")

    assert re.match(r"^sig1=:[A-Za-z0-9+/=]+:$", headers["Signature"])
    assert headers["Signature-Agent"] == '"https://api.veriswarm.ai"'
    assert set(headers.keys()) == {"Signature-Agent", "Signature-Input", "Signature"}


# ---------------------------------------------------------------------------
# 4. Authority derivation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://example.com/a/b?q=1", "example.com"),
        ("https://example.com:8443/path", "example.com:8443"),
        ("https://example.com:443/path", "example.com"),
        ("http://example.com:80/path", "example.com"),
        ("http://example.com:8080/path", "example.com:8080"),
        ("https://EXAMPLE.com/PATH", "example.com"),
    ],
)
def test_derive_authority(url, expected):
    assert _derive_authority(url) == expected


def test_derive_authority_rejects_hostless_url():
    with pytest.raises(ValueError):
        _derive_authority("not-a-url")


# ---------------------------------------------------------------------------
# 5. created / expires / nonce behavior
# ---------------------------------------------------------------------------


def test_expires_defaults_to_created_plus_300():
    private_key, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    headers = signer.sign_request("https://example.com/", created=1000)
    assert "created=1000" in headers["Signature-Input"]
    assert "expires=1300" in headers["Signature-Input"]


def test_expires_in_seconds_is_honored():
    private_key, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    headers = signer.sign_request("https://example.com/", created=1000, expires_in_seconds=60)
    assert "expires=1060" in headers["Signature-Input"]


def test_nonce_present_in_header_when_provided():
    private_key, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    headers = signer.sign_request("https://example.com/", created=1000, nonce="abc-123")
    assert 'nonce="abc-123"' in headers["Signature-Input"]


def test_nonce_absent_from_header_when_not_provided():
    private_key, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    headers = signer.sign_request("https://example.com/", created=1000)
    assert "nonce=" not in headers["Signature-Input"]


def test_created_defaults_to_current_time_when_omitted():
    import time

    private_key, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    before = int(time.time())
    headers = signer.sign_request("https://example.com/")
    after = int(time.time())

    match = re.search(r"created=(\d+)", headers["Signature-Input"])
    assert match is not None
    created = int(match.group(1))
    assert before <= created <= after


# ---------------------------------------------------------------------------
# 6. Constructor / input validation errors
# ---------------------------------------------------------------------------


def test_missing_private_key_pem_raises_value_error():
    with pytest.raises(ValueError):
        WebBotAuthSigner(private_key_pem="", key_id="key-1")


def test_missing_key_id_raises_value_error():
    _, pem = _keypair()
    with pytest.raises(ValueError):
        WebBotAuthSigner(private_key_pem=pem, key_id="")


def test_missing_signature_agent_raises_value_error():
    _, pem = _keypair()
    with pytest.raises(ValueError):
        WebBotAuthSigner(private_key_pem=pem, key_id="key-1", signature_agent="")


def test_unparseable_pem_raises_value_error():
    pytest.importorskip("cryptography")
    with pytest.raises(ValueError):
        WebBotAuthSigner(private_key_pem="not a real pem", key_id="key-1")


def test_non_ed25519_key_raises_value_error():
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
        WebBotAuthSigner(private_key_pem=pem, key_id="key-1")


def test_sign_request_rejects_empty_url():
    _, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    with pytest.raises(ValueError):
        signer.sign_request("")


def test_sign_request_rejects_non_positive_expires_in_seconds():
    _, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    with pytest.raises(ValueError):
        signer.sign_request("https://example.com/", expires_in_seconds=0)


# ---------------------------------------------------------------------------
# 7. Zero-dependency guard
# ---------------------------------------------------------------------------


def test_no_top_level_cryptography_import_in_source():
    """The webbotauth module and package __init__ must not import
    `cryptography` at module top level — only lazily, inside the
    functions/constructor that need it."""
    import veriswarm as veriswarm_pkg
    import veriswarm.webbotauth as webbotauth_module

    for module in (veriswarm_pkg, webbotauth_module):
        source = inspect.getsource(module)
        for line in source.splitlines():
            if line.startswith("import cryptography") or line.startswith("from cryptography"):
                pytest.fail(
                    f"top-level `cryptography` import found in {module.__name__}: {line!r}"
                )


def test_import_veriswarm_succeeds_without_cryptography():
    """Simulates a zero-dep install: block `cryptography` at import time via
    a meta-path finder, then assert `import veriswarm` and
    `import veriswarm.webbotauth` still succeed, and that constructing a
    WebBotAuthSigner raises a clear ImportError telling the user to install
    the extra."""
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
        from veriswarm.webbotauth import WebBotAuthSigner, build_signature_base  # noqa: F401

        # Pure string-building helper needs no crypto at all.
        base = build_signature_base(
            authority="example.com",
            signature_agent='"https://api.veriswarm.ai"',
            created=1000,
            expires=1300,
            keyid="key-1",
        )
        assert '"@authority": example.com' in base

        try:
            WebBotAuthSigner(private_key_pem="dummy", key_id="k1")
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


def test_web_bot_auth_error_is_import_error_subclass():
    assert issubclass(WebBotAuthError, ImportError)
