"""Tests for Web Bot Auth (RFC 9421 Ed25519 HTTP Message Signatures) signing."""
from __future__ import annotations

import inspect
import re
import subprocess
import sys
import textwrap

import pytest

import base64

from veriswarm.webbotauth import (
    DEFAULT_SIGNATURE_AGENT,
    WebBotAuthError,
    WebBotAuthSigner,
    _derive_authority,
    _quote_string,
    build_signature_base,
)

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
        signature_agent=DEFAULT_SIGNATURE_AGENT,
        created=1_700_000_000,
        expires=1_700_000_300,
        keyid="key-1",
    )
    assert base.endswith(params)

    sig_match = re.match(r"^sig1=:([A-Za-z0-9+/=]+):$", headers["Signature"])
    assert sig_match is not None
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
        signature_agent=DEFAULT_SIGNATURE_AGENT,
        created=1_700_000_000,
        expires=1_700_000_300,
        keyid="key-1",
    )
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
        ("https://[2001:db8::1]/path", "[2001:db8::1]"),
        ("https://[2001:db8::1]:8443/path", "[2001:db8::1]:8443"),
        ("https://例え.jp/path", "xn--r8jz45g.jp"),
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
# 5b. Structured-field injection: keyid / nonce / signature_agent must be
#     escaped, not just quote-wrapped, since all three are (directly or
#     indirectly) caller-controlled and interpolated into RFC 8941 quoted
#     Strings inside the signature base and Signature-Input header.
# ---------------------------------------------------------------------------


def test_quote_string_escapes_backslash_and_quote():
    # Mirrors Node's quoteString exactly: backslash first, then quote.
    assert _quote_string('a"b') == '"a\\"b"'
    assert _quote_string("a\\b") == '"a\\\\b"'
    assert _quote_string('a\\b"c') == '"a\\\\b\\"c"'
    assert _quote_string("plain") == '"plain"'


def test_nonce_containing_quote_is_escaped_not_injected():
    private_key, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    malicious_nonce = 'n";evil="injected'

    headers = signer.sign_request(
        "https://example.com/", created=1000, nonce=malicious_nonce
    )
    sig_input = headers["Signature-Input"]

    # The raw injected param must never appear unescaped.
    assert ';evil="injected"' not in sig_input
    # The nonce value is present, but its embedded quote is backslash-escaped.
    assert _quote_string(malicious_nonce) in sig_input
    # Exactly one nonce param, one keyid param, one tag param — no smuggled
    # extras from the unescaped quote breaking out of its field.
    assert sig_input.count("nonce=") == 1
    assert sig_input.count("keyid=") == 1
    assert sig_input.count("tag=") == 1


def test_keyid_containing_quote_is_escaped_not_injected():
    private_key, pem = _keypair()
    malicious_keyid = 'key";evil="injected'
    signer = WebBotAuthSigner(private_key_pem=pem, key_id=malicious_keyid)

    headers = signer.sign_request("https://example.com/", created=1000)
    sig_input = headers["Signature-Input"]

    assert ';evil="injected"' not in sig_input
    assert _quote_string(malicious_keyid) in sig_input
    assert sig_input.count("keyid=") == 1
    assert sig_input.count("tag=") == 1


def test_signature_agent_containing_quote_is_escaped_not_injected():
    private_key, pem = _keypair()
    malicious_agent = 'https://example.com";evil="injected'
    signer = WebBotAuthSigner(
        private_key_pem=pem, key_id="key-1", signature_agent=malicious_agent
    )

    headers = signer.sign_request("https://example.com/", created=1000)

    # The header value is exactly the escaped quoted string — the embedded
    # `"` is backslash-escaped, not left to terminate the RFC 8941 String
    # early and smuggle an `evil` field into the header.
    assert headers["Signature-Agent"] == _quote_string(malicious_agent)
    assert headers["Signature-Agent"] == '"https://example.com\\";evil=\\"injected"'


@pytest.mark.parametrize(
    "keyid,nonce,signature_agent",
    [
        ("key-1", "nonce-1", "https://api.veriswarm.ai"),
        ('key"1', 'nonce"1', 'https://api.veriswarm.ai"evil'),
        ("key\\1", "nonce\\1", "https://api.veriswarm.ai\\evil"),
        ('key\\"1', 'nonce\\"1', 'https://api.veriswarm.ai\\"evil'),
    ],
)
def test_escaped_fields_stay_byte_identical_between_base_and_header_and_verify(
    monkeypatch, keyid, nonce, signature_agent
):
    """Regression for the injection defect: for values containing `"`
    and/or `\\` in keyid, nonce, and signature_agent, the emitted
    Signature-Input params must remain byte-identical to the params
    actually signed inside the base, AND the signature must still verify
    cryptographically against the reconstructed base.
    """
    import veriswarm.webbotauth as webbotauth_module

    captured: dict[str, str] = {}
    original = webbotauth_module.build_signature_base

    def spy(**kwargs):
        result = original(**kwargs)
        captured["base"] = result
        return result

    monkeypatch.setattr(webbotauth_module, "build_signature_base", spy)

    private_key, pem = _keypair()
    public_key = private_key.public_key()
    signer = WebBotAuthSigner(
        private_key_pem=pem, key_id=keyid, signature_agent=signature_agent
    )
    headers = signer.sign_request("https://example.com/", created=1000, nonce=nonce)

    # Byte-identity between the signed base and the emitted header.
    base = captured["base"]
    header_params = headers["Signature-Input"][len("sig1="):]
    base_params = base.split('"@signature-params": ', 1)[1]
    assert base_params == header_params

    # The signature still verifies against the true (escaped) base.
    sig_match = re.match(r"^sig1=:([A-Za-z0-9+/=]+):$", headers["Signature"])
    assert sig_match is not None
    signature_bytes = base64.b64decode(sig_match.group(1))
    public_key.verify(signature_bytes, base.encode("utf-8"))


# ---------------------------------------------------------------------------
# 5c. Cross-SDK parity: golden vector shared with the Node SDK.
# ---------------------------------------------------------------------------


def test_matches_cross_sdk_golden_vector():
    """Fixed, hand-verified vector captured from a live run of both SDKs
    against the same Ed25519 key. This MUST stay in lockstep with the
    equivalent assertion in `node/test/webbotauth.test.mjs` — if the
    expected strings below ever change, the Node SDK and the VeriSwarm API
    server's verifier must change identically, in the same PR/release.

    Exercises `build_signature_base` directly with a RAW (unquoted)
    `signature_agent`, per the shared cross-SDK contract: the helper
    quotes+escapes `signature_agent` internally, exactly like it already
    does for `keyid`/`nonce`/`tag`. `keyid` and `nonce` both contain an
    embedded `"` to also pin the escaping behavior in the same vector.
    """
    base = build_signature_base(
        authority="example.com",
        signature_agent="https://api.veriswarm.ai",  # raw, not pre-quoted
        created=1000,
        expires=1300,
        keyid='k"1',
        nonce='n"2',
    )

    expected_base = (
        '"@authority": example.com\n'
        '"signature-agent": "https://api.veriswarm.ai"\n'
        '"@signature-params": ("@authority" "signature-agent");created=1000;'
        'expires=1300;nonce="n\\"2";keyid="k\\"1";tag="web-bot-auth"'
    )
    assert base == expected_base

    expected_signature_input = (
        'sig1=("@authority" "signature-agent");created=1000;expires=1300;'
        'nonce="n\\"2";keyid="k\\"1";tag="web-bot-auth"'
    )
    params = base.split('"@signature-params": ', 1)[1]
    assert f"sig1={params}" == expected_signature_input

    quoted_signature_agent = base.split('"signature-agent": ', 1)[1].split(
        '\n"@signature-params": ', 1
    )[0]
    assert quoted_signature_agent == '"https://api.veriswarm.ai"'


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


def test_sign_request_rejects_non_integer_created():
    _, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    with pytest.raises(ValueError, match="created"):
        signer.sign_request("https://example.com/", created=1000.5)


def test_sign_request_rejects_non_integer_expires_in_seconds():
    _, pem = _keypair()
    signer = WebBotAuthSigner(private_key_pem=pem, key_id="key-1")
    with pytest.raises(ValueError, match="expires_in_seconds"):
        signer.sign_request("https://example.com/", expires_in_seconds=300.0)


def test_build_signature_base_rejects_non_integer_timestamps():
    with pytest.raises(ValueError, match="created"):
        build_signature_base(
            authority="example.com",
            signature_agent=DEFAULT_SIGNATURE_AGENT,
            created=1000.5,
            expires=1300,
            keyid="key-1",
        )
    with pytest.raises(ValueError, match="expires"):
        build_signature_base(
            authority="example.com",
            signature_agent=DEFAULT_SIGNATURE_AGENT,
            created=1000,
            expires=1300.5,
            keyid="key-1",
        )


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

        # Pure string-building helper needs no crypto at all. signature_agent
        # is RAW (unquoted) — build_signature_base quotes it internally.
        base = build_signature_base(
            authority="example.com",
            signature_agent="https://api.veriswarm.ai",
            created=1000,
            expires=1300,
            keyid="key-1",
        )
        assert '"@authority": example.com' in base
        assert '"signature-agent": "https://api.veriswarm.ai"' in base

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
