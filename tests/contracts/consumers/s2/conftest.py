"""Consumer runtime controls; original publisher's detached harness also guards imports."""

import builtins
import socket

import pytest


@pytest.fixture(autouse=True)
def deny_original_owner_provider_and_network(monkeypatch):
    original = builtins.__import__
    banned = {"rfr", "openai", "typesafe", "PIL", "pytesseract", "fastapi"}

    def importing(name, *args, **kwargs):
        if name.split(".")[0] in banned:
            raise AssertionError("original owner/domain/provider import forbidden in S6 evalkit")
        return original(name, *args, **kwargs)

    def denied(*args, **kwargs):
        raise RuntimeError("S6 evalkit consumer network forbidden")

    monkeypatch.setattr(builtins, "__import__", importing)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket.socket, "sendto", denied)
    with pytest.raises(AssertionError, match="import forbidden"):
        __import__("rfr.pipeline")
    with pytest.raises(RuntimeError, match="network forbidden"):
        socket.create_connection(("example.invalid", 443))
