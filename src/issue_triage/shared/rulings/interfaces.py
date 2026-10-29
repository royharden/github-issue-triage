"""Injected source validation and future durable-store/reducer ports, no implementation."""

from collections.abc import Mapping
from typing import Protocol

from .models import AppendReceipt, Generation, RulingEvent, RulingIntent, Subject


class GenerationValidator(Protocol):
    def validate(self, subject: Subject, generation: Generation) -> None: ...


class PairProducerProfile(GenerationValidator, Protocol):
    """S4 product-raw-fields-v1 supplies its exact producer preimage; never guessed here."""

    def raw_fingerprint(self, raw_fields: Mapping[str, str]) -> str: ...


class RulingStore(Protocol):
    def append(self, intent: RulingIntent, validator: GenerationValidator) -> AppendReceipt: ...

    def stable_head(self, namespace: str, subject: Subject) -> RulingEvent | None: ...


class PairReducer(Protocol):
    def reduce(self, events: tuple[RulingEvent, ...], current_generation: str) -> object: ...
