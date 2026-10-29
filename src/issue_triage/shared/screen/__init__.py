"""Portable, no-network rules core with a lazy explicitly injected typed seam."""

from .models import (
    HAZARDS,
    HeldInput,
    OffsetSegment,
    PreparedText,
    ScreenPolicy,
    ScreenResult,
    ScreenValidationError,
    UntrustedText,
    WrappedData,
)
from .prepare import prepare_text, wrap_untrusted
from .rules import screen_rules

__all__ = [
    "HAZARDS",
    "HeldInput",
    "OffsetSegment",
    "PreparedText",
    "ScreenPolicy",
    "ScreenResult",
    "ScreenValidationError",
    "UntrustedText",
    "WrappedData",
    "prepare_text",
    "screen_rules",
    "screen_typed",
    "wrap_untrusted",
]


def __getattr__(name):
    if name == "screen_typed":
        from .typed import screen_typed

        return screen_typed
    raise AttributeError(name)
