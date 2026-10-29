"""Original keyless controls and GitHub's published HMAC interoperability vector."""

import base64
import hashlib
import hmac
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from issue_triage.shared.ghapp import (
    AuthError,
    WebhookError,
    app_jwt,
    installation_token_request,
    parse_delivery,
    verify_signature,
)

SECRET = b"synthetic-webhook-control-secret"


def payload(
    *, body="An original local control.", updated="2026-10-14T10:00:00Z", action="opened", sender=12
):
    return {
        "action": action,
        "installation": {"id": 1},
        "repository": {"id": 2, "owner": {"login": "synthetic"}, "name": "demo"},
        "issue": {
            "number": 3,
            "title": "Synthetic title",
            "body": body,
            "updated_at": updated,
            "user": {"id": 12, "login": "synthetic-author"},
        },
        "sender": {"id": sender},
    }


def sign(raw):
    return "sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest()


def verified(value=None, *, delivery_id="delivery-1", event="issues", **options):
    raw = json.dumps(payload() if value is None else value, ensure_ascii=False).encode()
    return parse_delivery(
        raw,
        signature_header=sign(raw),
        secret=SECRET,
        delivery_id=delivery_id,
        event=event,
        received_at="2026-10-14T10:00:01Z",
        installation_id=1,
        repository_id=2,
        **options,
    )


def test_official_github_hmac_vector():
    # Public interoperability data from GitHub validating-webhook-deliveries docs, not a real key.
    verify_signature(
        b"Hello, World!",
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        b"It's a Secret to Everybody",
    )


@pytest.mark.parametrize(
    "signature", [None, "", "sha1=" + "a" * 40, "sha256=" + "a" * 64, "sha256=" + "A" * 64]
)
def test_authentication_precedes_json_decode(monkeypatch, signature):
    def forbidden(*args, **kwargs):
        raise AssertionError("JSON decoding before signature authentication")

    monkeypatch.setattr("issue_triage.shared.ghapp.webhook.json.loads", forbidden)
    with pytest.raises(WebhookError, match="bad_signature"):
        parse_delivery(
            b"not json",
            signature_header=signature,
            secret=SECRET,
            delivery_id="d",
            event="issues",
            received_at="2026-10-14T10:00:01Z",
            installation_id=1,
            repository_id=2,
        )


def test_signature_binds_original_bytes_and_oversize_never_parses(monkeypatch):
    raw = b'{"x":1}'
    with pytest.raises(WebhookError, match="bad_signature"):
        verify_signature(raw + b" ", sign(raw), SECRET)
    with pytest.raises(WebhookError, match="body_too_large_or_invalid"):
        verify_signature(b"a" * 1048577, sign(b"a" * 1048577), SECRET)
    with pytest.raises(WebhookError, match="webhook_secret_unavailable"):
        verify_signature(raw, sign(raw), b"short")


@pytest.mark.parametrize(
    "raw", [b'{"action":"opened","action":"edited"}', b'{"x":NaN}', b"[]", b"not json"]
)
def test_authenticated_bad_json_remains_closed(raw):
    with pytest.raises(WebhookError, match="invalid_payload"):
        parse_delivery(
            raw,
            signature_header=sign(raw),
            secret=SECRET,
            delivery_id="d",
            event="issues",
            received_at="2026-10-14T10:00:01Z",
            installation_id=1,
            repository_id=2,
        )


def test_unsupported_self_app_and_other_bot_rules():
    assert verified(event="issue_comment").reason == "unsupported_event"
    assert verified(payload(action="labeled")).reason == "unsupported_action"
    assert verified(app_actor_id=12).reason == "app_self_event"
    assert verified(payload(sender=90), app_actor_id=12).disposition == "supported"
    value = payload()
    value["issue"]["pull_request"] = {}
    assert verified(value).reason == "pull_request_not_supported"


def test_repository_allowlist_and_complete_unicode_body():
    value = payload(body="é" * 20000 + "tail")
    result = verified(value)
    assert result.envelope.issue.body == value["issue"]["body"]
    assert "tail" not in repr(result)
    value["repository"]["id"] = 999
    with pytest.raises(WebhookError, match="repository_not_allowed"):
        verified(value)
    value["repository"]["id"] = True
    with pytest.raises(WebhookError, match="invalid_issue_payload"):
        verified(value)


def test_null_body_is_explicit_no_description_projection():
    assert verified(payload(body=None)).envelope.issue.body == ""


class Signer:
    def __init__(self):
        self.calls = []

    def sign(self, value, *, algorithm):
        self.calls.append((value, algorithm))
        return b"synthetic-signature-not-RSA-proof"


def test_jwt_rs256_port_and_bounded_time_without_real_key():
    signer = Signer()
    jwt = app_jwt("synthetic-app", now_seconds=1000, signer=signer)
    header, claims, _ = jwt.token.split(".")

    def decode(item):
        return json.loads(base64.urlsafe_b64decode(item + "=" * (-len(item) % 4)))

    assert decode(header) == {"alg": "RS256", "typ": "JWT"}
    assert decode(claims) == {"iat": 940, "exp": 1540, "iss": "synthetic-app"}
    assert signer.calls[0][1] == "RS256" and len(signer.calls) == 1
    assert jwt.expires_at_seconds == 1540 and jwt.token not in repr(jwt)
    with pytest.raises(AuthError, match="signer_unavailable"):
        app_jwt("synthetic-app", now_seconds=1000, signer=None)


@pytest.mark.parametrize("clock", [True, 0, 59, -1])
def test_bad_jwt_clock_rejected(clock):
    with pytest.raises(AuthError, match="invalid_clock"):
        app_jwt("synthetic-app", now_seconds=clock, signer=Signer())


def test_reader_and_apply_requests_are_one_repo_minimal_subsets():
    registered = {"contents": "read", "issues": "write", "metadata": "read", "actions": "write"}
    reader = installation_token_request(1, 2, role="reader", registered_permissions=registered)
    assert reader.path == "/app/installations/1/access_tokens"
    assert reader.payload() == {
        "repository_ids": [2],
        "permissions": {"contents": "read", "issues": "read", "metadata": "read"},
    }
    writer = installation_token_request(1, 2, role="apply", registered_permissions=registered)
    assert writer.payload() == {
        "repository_ids": [2],
        "permissions": {"issues": "write", "metadata": "read"},
    }
    copy = reader.payload()
    copy["permissions"]["issues"] = "write"
    assert reader.payload()["permissions"]["issues"] == "read"
    with pytest.raises(AuthError, match="permission_not_registered"):
        installation_token_request(
            1, 2, role="apply", registered_permissions={"issues": "read", "metadata": "read"}
        )
    with pytest.raises(AuthError, match="invalid_github_id"):
        installation_token_request(1, True, role="reader", registered_permissions=registered)


def test_detached_stdlib_auth_and_signature_import_without_app(tmp_path):
    module = Path(__file__).parents[2] / "src/issue_triage/shared/ghapp"
    shutil.copytree(module, tmp_path / "ghapp", ignore=shutil.ignore_patterns("__pycache__"))
    code = (
        "import sys; sys.path.insert(0,sys.argv[1]); import ghapp; "
        "assert 'ghapp.webhook' not in sys.modules; "
        "r=ghapp.installation_token_request(1,2,role='reader',"
        "registered_permissions={'contents':'read','issues':'read','metadata':'read'}); "
        "assert r.payload()['repository_ids']==[2]; "
        "assert not any(x.startswith(('issue_triage','pydantic','openai')) for x in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
