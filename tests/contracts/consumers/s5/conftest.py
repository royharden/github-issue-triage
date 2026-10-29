"""Explicit offline consumer guards; canonical source cannot rely on its owner app."""

import builtins
import socket

import pytest


@pytest.fixture(autouse=True)
def deny_owner_and_network(monkeypatch):
    original = builtins.__import__

    def importing(name, *args, **kwargs):
        if name.split(".")[0] in {"changelog_advisor", "openai", "typesafe", "requests", "httpx"}:
            raise AssertionError("S5 owner/provider import forbidden")
        return original(name, *args, **kwargs)

    def denied(*args, **kwargs):
        raise AssertionError("S5 offline consumer network forbidden")

    monkeypatch.setattr(builtins, "__import__", importing)
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    with pytest.raises(AssertionError, match="owner/provider"):
        __import__("changelog_advisor")
    with pytest.raises(AssertionError, match="network"):
        socket.socket()
