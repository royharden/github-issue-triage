"""Deterministic baseline: neutral holds, with diagnostics that cannot clear a hold."""

import re
import unicodedata

from .models import HeldInput, PreparedText, ScreenPolicy, ScreenResult, UntrustedText
from .prepare import prepare_text

RULES = (
    (
        "addresses_automated_agent",
        re.compile(
            r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|above|criteria|instructions)|(?:system|assistant)\s*:|\[INST\]|<system>|\b(?:bot|agent|assistant)\s*[,!:].*\b(?:ignore|execute|obey)",
            re.I | re.S,
        ),
    ),
    (
        "asks_to_run_fetch_or_install",
        re.compile(
            r"(?:^|[.!?\n]\s*|\bplease\s+|\b(?:could|can|would)\s+you\s+)(?:run|execute|install|fetch|download|paste)\s+\S|\bcurl\b.*\|\s*(?:ba)?sh\b|\bpip\s+install\b|\bnpm\s+install\b",
            re.I | re.M,
        ),
    ),
    (
        "asks_for_credentials",
        re.compile(
            r"\b(?:send|share|reveal|provide|give|print|paste|upload)\b.{0,80}"
            r"(?:\b(?:password|credentials?|api[ _-]?keys?|tokens?|ssh[ _-]?keys?)\b|\.env\b)",
            re.I | re.S,
        ),
    ),
)


def safety_flags(prepared: PreparedText) -> tuple[str, ...]:
    texts = (prepared.source.text, prepared.normalized_text)
    flags = {name for name, rule in RULES if any(rule.search(text) for text in texts)}
    for word in re.findall(r"\w+", prepared.source.text):
        scripts = {
            s for c in word for s in ("LATIN", "CYRILLIC", "GREEK") if s in unicodedata.name(c, "")
        }
        if "LATIN" in scripts and len(scripts) > 1:
            flags.add("mixed_script_review")
    if any(
        unicodedata.bidirectional(c)
        in ("RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI")
        for c in prepared.source.text
    ):
        flags.add("bidi_control_review")
    return tuple(sorted(flags))


def result_for(prepared: PreparedText | HeldInput, policy: ScreenPolicy, **changes) -> ScreenResult:
    held = isinstance(prepared, HeldInput)
    values = {
        "input_sha256": prepared.original_sha256,
        "normalized_sha256": prepared.normalized_sha256,
        "transform_version": policy.normalization_version,
        "source_generation": prepared.source.source_generation,
        "policy_sha256": policy.sha256,
        "method": "rules",
        "coverage": "partial" if held else "complete",
        "decision": "needs_human" if held else "pass",
        "reason_codes": (prepared.reason,) if held else (),
        "diagnostic_notices": prepared.notices,
        "offset_segments": () if held else prepared.offset_segments,
    }
    values.update(changes)
    return ScreenResult(**values)


def screen_rules(source: UntrustedText, policy: ScreenPolicy) -> ScreenResult:
    prepared = prepare_text(source, policy)
    if isinstance(prepared, HeldInput):
        return result_for(prepared, policy)
    flags = safety_flags(prepared)
    if flags:
        return result_for(
            prepared, policy, decision="needs_human", reason_codes=flags, deterministic_flags=flags
        )
    notices = prepared.notices
    if re.search(r"\brun\b", prepared.normalized_text, re.I):
        notices += ("descriptive_or_quoted_run",)
    if policy.required_method != "rules":
        return result_for(
            prepared,
            policy,
            decision="needs_human",
            reason_codes=("required_method_unavailable",),
            diagnostic_notices=notices,
        )
    return result_for(prepared, policy, diagnostic_notices=notices)
