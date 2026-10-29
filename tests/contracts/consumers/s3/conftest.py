"""Consumer controls: canonical source must run without owner namespace or network."""

import builtins
import socket

import pytest


@pytest.fixture(autouse=True)
def forbid_owner_and_network(monkeypatch):
    original = builtins.__import__

    def importing(name, *args, **kwargs):
        if name == "llm_router_eval" or name.startswith("llm_router_eval."):
            raise AssertionError("S3 owner namespace forbidden in S6")
        return original(name, *args, **kwargs)

    def blocked(*args, **kwargs):
        raise RuntimeError("S6 offline consumer network blocked")

    monkeypatch.setattr(builtins, "__import__", importing)
    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    with pytest.raises(AssertionError, match="owner namespace"):
        __import__("llm_router_eval")
    with pytest.raises(RuntimeError, match="network blocked"):
        socket.socket()
