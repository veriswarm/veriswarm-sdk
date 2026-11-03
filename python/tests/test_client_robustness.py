"""Transport failures surface as VeriSwarmClientError; the UA reports the real version."""
from __future__ import annotations

import io
import socket
from email.message import Message
from urllib.error import HTTPError

import pytest

import veriswarm
from veriswarm import VeriSwarmClient, VeriSwarmClientError
from veriswarm import client as client_module

from .conftest import FakeResponse

BASE = "https://api.test"


@pytest.fixture
def client() -> VeriSwarmClient:
    return VeriSwarmClient(base_url=BASE, api_key="vsk_x")


class TimeoutOnRead(FakeResponse):
    def read(self, *args, **kwargs):  # type: ignore[override]
        raise socket.timeout("The read operation timed out")


@pytest.mark.parametrize("exc", [socket.timeout("timed out"), TimeoutError("timed out")])
def test_connect_timeout_is_wrapped(client, recorder, exc):
    recorder.raise_exc = exc
    with pytest.raises(VeriSwarmClientError, match="timed out") as info:
        client.get_platform_status()
    assert info.value.status is None


def test_read_timeout_is_wrapped(client, monkeypatch):
    class Opener:
        def open(self, request, timeout=None):
            return TimeoutOnRead(b"")

    monkeypatch.setattr(client_module, "_OPENER", Opener())
    with pytest.raises(VeriSwarmClientError, match="timed out"):
        client.get_platform_status()


def test_connection_reset_is_wrapped(client, recorder):
    recorder.raise_exc = ConnectionResetError("reset by peer")
    with pytest.raises(VeriSwarmClientError, match="request failed"):
        client.get_platform_status()


@pytest.mark.parametrize("body", [b"<html>maintenance</html>", b"{not json", b"\xff\xfe\x00"])
def test_non_json_success_body_is_wrapped(client, recorder, body):
    recorder.body = body
    with pytest.raises(VeriSwarmClientError, match="invalid JSON") as info:
        client.get_platform_status()
    assert info.value.status == 200


def test_http_error_carries_status(client, recorder):
    recorder.raise_exc = HTTPError(
        f"{BASE}/v1/public/status", 422, "Unprocessable", Message(), io.BytesIO(b'{"detail":"bad"}')
    )
    with pytest.raises(VeriSwarmClientError) as info:
        client.get_platform_status()
    assert info.value.status == 422
    assert "422" in str(info.value)


def test_user_agent_reports_package_version(client, recorder):
    client.get_platform_status()
    assert recorder.header("User-Agent") == f"veriswarm-python-sdk/{veriswarm.__version__}"
    assert veriswarm.__version__ != "0.4.0"


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), "15", True])
def test_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError, match="timeout_seconds"):
        VeriSwarmClient(base_url=BASE, api_key="k", timeout_seconds=timeout)  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [1, 0.5, 15, 300])
def test_accepts_valid_timeout(timeout):
    assert VeriSwarmClient(base_url=BASE, api_key="k", timeout_seconds=timeout).timeout_seconds == timeout


@pytest.mark.parametrize("url", ["http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"])
def test_accepts_local_http(url):
    VeriSwarmClient(base_url=url, api_key="k")


@pytest.mark.parametrize("url", ["http://[::2]:8000", "http://localhost.evil.test", "http://10.0.0.1"])
def test_rejects_non_local_http(url):
    with pytest.raises(ValueError, match="https"):
        VeriSwarmClient(base_url=url, api_key="k")
