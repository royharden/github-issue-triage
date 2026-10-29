"""Transparent uncalibrated deterministic baseline; every proposal still needs human disposition."""

import re

from .context import admit_context, common_record
from .contracts import DEFAULT_JUDGMENT_POLICY, JudgmentRecord


def judge_rules(context, policy=DEFAULT_JUDGMENT_POLICY):
    facts = admit_context(context, policy)
    title, body = context.issue.title.lower(), context.issue.body.lower()
    text = title + "\n" + body
    if re.search(r"\b(feature|enhancement|support for|would like)\b", title):
        kind = "feature"
    elif "?" in title or re.search(r"\b(how to|how do|question|where can)\b", title):
        kind = "question"
    elif re.search(r"\b(bug|crash|error|broken|fails?|incorrect|wrong)\b", text):
        if facts.reference_count and facts.not_found == facts.reference_count:
            kind = "likely_invalid"
        elif not all(word in body for word in ("steps", "expected", "actual")):
            kind = "needs_repro"
        else:
            kind = "bug"
    else:
        kind = "unclear"
    if kind == "unclear":
        return JudgmentRecord(
            status="needs_human",
            method="rules",
            type_decision=None,
            priority=None,
            reason_codes=("rules_unclear",),
            current_external_cost_usd="0",
            **common_record(context, policy),
        )
    priority = (
        0
        if re.search(r"\b(data loss|security breach|service down)\b", text)
        else (
            1
            if re.search(r"\b(crash|unusable|blocked)\b", text)
            else (3 if kind in {"feature", "question", "likely_invalid"} else 2)
        )
    )
    return JudgmentRecord(
        status="proposal",
        method="rules",
        type_decision=kind,
        priority=priority,
        reason_codes=("deterministic_rules_baseline", "human_disposition_required"),
        current_external_cost_usd="0",
        **common_record(context, policy),
    )
