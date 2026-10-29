"""Project a supplied map; never read the real environment or a credential file."""

from collections.abc import Mapping

COMMON = frozenset({"SYSTEMROOT", "WINDIR", "TEMP", "TMP"})
ROLE_SECRETS = {
    "serve": frozenset({"GITHUB_WEBHOOK_SECRET", "TRIAGE_OPERATOR_TOKEN"}),
    "broker": frozenset({"GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_FILE"}),
    "judge": frozenset(
        {"OPENAI_API_KEY", "OPENAI_API_KEY_FILE", "TYPESAFE_API_KEY", "TYPESAFE_API_KEY_FILE"}
    ),
    "apply": frozenset({"GITHUB_INSTALLATION_WRITE_TOKEN"}),
}


def child_environment(
    role: str, supplied: Mapping[str, str], *, selected: tuple[str, ...] = ()
) -> dict[str, str]:
    """Explicit secret names only; no wildcard, PATH/PYTHONPATH, implicit inheritance or IO.

    This is environment scrubbing, not OS isolation or authority to read/use any passed secret.
    Launch code must use an absolute interpreter and isolated mode separately.
    """
    if type(role) is not str or role not in ROLE_SECRETS:
        raise ValueError("unknown_process_role")
    if not isinstance(supplied, Mapping) or type(selected) is not tuple:
        raise ValueError("invalid_environment")
    if any(type(name) is not str for name in selected) or not set(selected) <= ROLE_SECRETS[role]:
        raise ValueError("secret_not_allowed_for_role")
    output = {"PYTHONUTF8": "1", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    for name in COMMON | set(selected):
        if name in supplied:
            value = supplied[name]
            if type(value) is not str or "\x00" in value or "=" in name:
                raise ValueError("invalid_environment")
            output[name] = value
    return output
