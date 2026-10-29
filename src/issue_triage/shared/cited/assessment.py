"""Mandatory evidence accounting only; no semantic judge or application pipeline."""

from collections import Counter
from dataclasses import dataclass

from .models import Finding, Resolution, ResolutionContext
from .registry import Registry


@dataclass(frozen=True, slots=True)
class EvidenceAssessment:
    finding: Finding
    resolutions: tuple[Resolution, ...]
    reason_counts: tuple[tuple[str, int], ...]

    @property
    def required_count(self) -> int:
        return len(self.finding.evidence)

    @property
    def resolved_count(self) -> int:
        return sum(result.status == "resolved" for result in self.resolutions)

    @property
    def unresolved_count(self) -> int:
        return self.required_count - self.resolved_count

    @property
    def status_counts(self) -> tuple[tuple[str, int], ...]:
        return tuple(sorted(Counter(result.status for result in self.resolutions).items()))


def assess_required_evidence(
    finding: Finding,
    registry: Registry,
    context: ResolutionContext,
) -> EvidenceAssessment:
    """All evidence is mandatory in Finding/1. Failure cannot disappear or upgrade."""
    finding = Finding.model_validate(finding)
    context = ResolutionContext.model_validate(context)
    resolutions = tuple(registry.resolve(pointer, context) for pointer in finding.evidence)
    reasons = Counter(result.reason for result in resolutions if result.status != "resolved")
    if not resolutions:
        reasons["no_required_evidence"] += 1
    if reasons:
        data = finding.model_dump()
        data["verdict"] = "unsupported"
        finding = Finding.model_validate(data)
    return EvidenceAssessment(finding, resolutions, tuple(sorted(reasons.items())))
