"""Synthetic mapping only: no actual environment or credential file reads."""

import pytest

from issue_triage.runtime import child_environment

VALUES = {
    "SYSTEMROOT": "synthetic-system",
    "PATH": "UNTRUSTED_TOOL_PATH",
    "PYTHONPATH": "UNTRUSTED_IMPORT",
    "GITHUB_APP_PRIVATE_KEY_FILE": "GITHUB_SIGNING_CANARY",
    "GITHUB_WEBHOOK_SECRET": "WEBHOOK_CANARY",
    "GITHUB_INSTALLATION_WRITE_TOKEN": "WRITER_CANARY",
    "TRIAGE_OPERATOR_TOKEN": "OPERATOR_CANARY",
    "OPENAI_API_KEY_FILE": "PROVIDER_CANARY",
    "TYPESAFE_API_KEY_FILE": "TYPED_CANARY",
    "UNRELATED_SECRET": "UNRELATED_CANARY",
}


@pytest.mark.parametrize("role", ["serve", "broker", "judge", "apply"])
def test_no_secret_inheritance_by_default(role):
    actual = child_environment(role, VALUES)
    assert actual["SYSTEMROOT"] == "synthetic-system"
    assert set(actual) == {
        "SYSTEMROOT",
        "PYTHONUTF8",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
    }
    assert not any("CANARY" in value or "UNTRUSTED" in value for value in actual.values())


def test_judge_selected_provider_only_and_parent_map_unmodified():
    before = VALUES.copy()
    actual = child_environment("judge", VALUES, selected=("OPENAI_API_KEY_FILE",))
    assert actual["OPENAI_API_KEY_FILE"] == "PROVIDER_CANARY"
    assert all("GITHUB" not in name for name in actual)
    assert "TYPESAFE_API_KEY_FILE" not in actual and "UNRELATED_SECRET" not in actual
    assert VALUES == before


@pytest.mark.parametrize(
    "role,name",
    [
        ("judge", "GITHUB_APP_PRIVATE_KEY_FILE"),
        ("apply", "OPENAI_API_KEY_FILE"),
        ("serve", "GITHUB_INSTALLATION_WRITE_TOKEN"),
        ("broker", "GITHUB_WEBHOOK_SECRET"),
        ("judge", "PATH"),
        ("judge", "*"),
    ],
)
def test_cross_role_or_wildcard_secret_rejected(role, name):
    with pytest.raises(ValueError, match="secret_not_allowed_for_role"):
        child_environment(role, VALUES, selected=(name,))


def test_bad_role_or_environment_rejected():
    with pytest.raises(ValueError, match="unknown_process_role"):
        child_environment("unknown", VALUES)
    with pytest.raises(ValueError, match="invalid_environment"):
        child_environment(
            "judge", {"OPENAI_API_KEY_FILE": "bad\x00path"}, selected=("OPENAI_API_KEY_FILE",)
        )
