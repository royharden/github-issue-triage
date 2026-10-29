"""Owner-private bounded JSONL journal. No domain graph, source discovery or repair."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .identity import canonical_bytes, intent_bytes
from .interfaces import GenerationValidator
from .models import (
    AppendReceipt,
    PairDecision,
    PairRetraction,
    RulingEvent,
    RulingIntent,
    ScalarSubject,
    Subject,
)

MAX_EVENT_BYTES = 64 * 1024
_HELD = threading.local()
_DEVICES = {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)}


class JournalError(RuntimeError):
    """Closed reason code only; never include private paths/payload/underlying exceptions."""


class PathRefused(JournalError):
    pass


class LockTimeout(JournalError):
    pass


class JournalReadOnly(JournalError):
    pass


class IntentConflict(JournalError):
    pass


class PriorConflict(JournalError):
    pass


class GenerationConflict(JournalError):
    pass


class AppendUncertain(JournalError):
    """Write/sync failed; complete bytes may exist. Retry same intent, never assume no effect."""


def subject_key(namespace: str, subject: Subject) -> str:
    if isinstance(subject, ScalarSubject):
        stable = [namespace, "field", subject.item_id, subject.field_id, subject.row_key]
    else:
        stable = [namespace, "pair", subject.pair_key]
    return canonical_bytes(stable).decode("utf-8")


@dataclass(frozen=True)
class JournalSnapshot:
    status: Literal["clean", "repair_required", "limit_exceeded"]
    events: tuple[RulingEvent, ...]
    valid_prefix_bytes: int
    issue_code: str | None
    damaged_tail_sha256: str | None
    damaged_tail_bytes: int

    @property
    def can_append(self) -> bool:
        return self.status == "clean"

    def stable_head(self, namespace: str, subject: Subject) -> RulingEvent | None:
        key = subject_key(namespace, subject)
        return next(
            (
                event
                for event in reversed(self.events)
                if subject_key(event.namespace, event.subject) == key
            ),
            None,
        )


def _not_reparse(path: Path, *, directory: bool) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise PathRefused("path_unavailable") from None
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise PathRefused("reparse_or_symlink_refused")
    wanted = stat.S_ISDIR if directory else stat.S_ISREG
    if not wanted(info.st_mode):
        raise PathRefused("wrong_path_type")
    if not directory and info.st_nlink != 1:
        raise PathRefused("hard_link_refused")


def _drive_type(root: Path) -> int:
    import ctypes

    function = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    function.argtypes = [ctypes.c_wchar_p]
    function.restype = ctypes.c_uint
    return function(str(root.anchor))


def _check_local_root(root: Path) -> None:
    if os.name == "nt":
        if root.drive.startswith("\\\\"):
            raise PathRefused("unc_or_device_root_refused")
        if _drive_type(root) == 4:
            raise PathRefused("remote_drive_refused")


class JournalStore:
    """A trusted owner-private directory and one leaf filename, never an imported source path.

    The directory/ancestors must be owner-controlled. Static links/reparse points/hard links reject;
    this is not a multi-user hostile-filesystem service. No automatic tail repair is exposed.
    """

    def __init__(
        self,
        root: Path,
        name: str = "rulings.jsonl",
        *,
        lock_deadline_s: float = 5.0,
        max_journal_bytes: int = 64 * 1024 * 1024,
        max_events: int = 10000,
    ):
        if type(name) is not str or not re.fullmatch(
            r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,126}\.jsonl", name
        ):
            raise PathRefused("invalid_journal_leaf")
        if name.split(".")[0].upper() in _DEVICES:
            raise PathRefused("reserved_journal_leaf")
        if (
            type(lock_deadline_s) not in (int, float)
            or not math.isfinite(lock_deadline_s)
            or lock_deadline_s <= 0
        ):
            raise ValueError("finite positive lock deadline required")
        if any(type(n) is not int or n <= 0 for n in (max_journal_bytes, max_events)):
            raise ValueError("positive integer journal bounds required")
        raw_root = Path(root).absolute()
        _check_local_root(raw_root)
        for component in (*reversed(raw_root.parents), raw_root):
            _not_reparse(component, directory=True)
        self.root = raw_root.resolve(strict=True)
        self.path = self.root / name
        self.lock_path = self.root / (name + ".lock")
        self.lock_deadline_s = lock_deadline_s
        self.max_journal_bytes = max_journal_bytes
        self.max_events = max_events
        self._check_paths()

    def _check_paths(self) -> None:
        _not_reparse(self.root, directory=True)
        for path in (self.path, self.lock_path):
            # lexists catches broken links without following them.
            if os.path.lexists(path):
                _not_reparse(path, directory=False)
            if path.parent.resolve(strict=True) != self.root:
                raise PathRefused("journal_containment_refused")

    @contextmanager
    def _critical(self):
        self._check_paths()
        key = os.path.normcase(str(self.lock_path))
        held = getattr(_HELD, "keys", set())
        if key in held:
            raise JournalError("reentrant_journal_access")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        acquired = False
        try:
            self._check_paths()
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            end = time.monotonic() + self.lock_deadline_s
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    _HELD.keys = held | {key}
                    break
                except OSError:
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise LockTimeout("journal_lock_deadline") from None
                    time.sleep(min(0.01, remaining))
            self._check_paths()
            yield
        finally:
            if acquired:
                _HELD.keys = held
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _scan(self) -> JournalSnapshot:
        if not self.path.exists():
            return JournalSnapshot("clean", (), 0, None, None, 0)
        if self.path.stat().st_size > self.max_journal_bytes:
            return JournalSnapshot("limit_exceeded", (), 0, "journal_byte_limit", None, 0)
        events: list[RulingEvent] = []
        seen: set[str] = set()
        heads: dict[str, str] = {}
        by_id: dict[str, RulingEvent] = {}
        offset = 0
        issue = None
        with self.path.open("rb") as reader:
            while line := reader.readline(MAX_EVENT_BYTES + 1):
                if len(events) >= self.max_events:
                    return JournalSnapshot(
                        "limit_exceeded", tuple(events), offset, "journal_event_limit", None, 0
                    )
                try:
                    if not line.endswith(b"\n") or len(line) > MAX_EVENT_BYTES:
                        raise ValueError("incomplete_or_oversized_event")
                    event = RulingEvent.model_validate_json(line[:-1])
                    if canonical_bytes(event.model_dump(mode="json")) + b"\n" != line:
                        raise ValueError("noncanonical_event")
                    if event.sequence != len(events) + 1 or event.event_id in seen:
                        raise ValueError("invalid_sequence_or_duplicate_id")
                    key = subject_key(event.namespace, event.subject)
                    if event.expected_prior_event_id != heads.get(key):
                        raise ValueError("invalid_historical_predecessor")
                    if isinstance(event.payload, PairRetraction):
                        self._check_retraction(event, by_id.get(event.payload.target_event_id))
                except ValueError:
                    issue = "damaged_event_or_tail"
                    digest = hashlib.sha256(line)
                    size = len(line)
                    while chunk := reader.read(65536):
                        digest.update(chunk)
                        size += len(chunk)
                    return JournalSnapshot(
                        "repair_required", tuple(events), offset, issue, digest.hexdigest(), size
                    )
                events.append(event)
                seen.add(event.event_id)
                by_id[event.event_id] = event
                heads[key] = event.event_id
                offset += len(line)
        return JournalSnapshot("clean", tuple(events), offset, None, None, 0)

    def _sync(self, fd: int) -> None:
        os.fsync(fd)

    def _sync_existing(self) -> None:
        if self.path.exists():
            fd = os.open(
                self.path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            )
            try:
                self._sync(fd)
            except OSError:
                raise AppendUncertain("journal_sync_uncertain") from None
            finally:
                os.close(fd)

    def replay(self) -> JournalSnapshot:
        with self._critical():
            snapshot = self._scan()
            if snapshot.can_append:
                self._sync_existing()
            return snapshot

    def stable_head(self, namespace: str, subject: Subject) -> RulingEvent | None:
        return self.replay().stable_head(namespace, subject)

    def append(self, intent: RulingIntent, validator: GenerationValidator) -> AppendReceipt:
        if type(intent) is not RulingIntent:
            raise ValueError("client RulingIntent required, never an imported assigned sequence")
        # Revalidate mutable JSON payloads and the complete intent before touching journal bytes.
        try:
            checked = RulingIntent.model_validate_json(intent_bytes(intent))
        except ValueError:
            raise JournalError("invalid_client_intent") from None
        complete_intent = intent_bytes(checked)
        if len(complete_intent) + 1 > MAX_EVENT_BYTES:
            raise ValueError("event_byte_limit")
        with self._critical():
            snapshot = self._scan()
            if not snapshot.can_append:
                raise JournalReadOnly(snapshot.issue_code or "journal_read_only")
            existing = next((e for e in snapshot.events if e.event_id == checked.event_id), None)
            if existing is not None:
                if intent_bytes(existing) != complete_intent:
                    raise IntentConflict("event_id_intent_conflict")
                self._sync_existing()
                return self._receipt(existing, "exact_retry", historical=True)
            head = snapshot.stable_head(checked.namespace, checked.subject)
            if checked.expected_prior_event_id != (head.event_id if head else None):
                raise PriorConflict("stable_head_conflict")
            try:
                if validator.validate(checked.subject, checked.generation_identity) is not None:
                    raise GenerationConflict("generation_validator_contract")
            except JournalError:
                raise
            except Exception:
                raise GenerationConflict("current_generation_conflict") from None
            if isinstance(checked.payload, PairRetraction):
                target = next(
                    (e for e in snapshot.events if e.event_id == checked.payload.target_event_id),
                    None,
                )
                try:
                    self._check_retraction(checked, target)
                except ValueError:
                    raise IntentConflict("invalid_retraction_target") from None
            event = RulingEvent.model_validate_json(
                canonical_bytes(
                    checked.model_dump(mode="json") | {"sequence": len(snapshot.events) + 1}
                )
            )
            line = canonical_bytes(event.model_dump(mode="json")) + b"\n"
            if len(line) > MAX_EVENT_BYTES:
                raise ValueError("event_byte_limit")
            if (
                len(snapshot.events) >= self.max_events
                or snapshot.valid_prefix_bytes + len(line) > self.max_journal_bytes
            ):
                raise JournalReadOnly("journal_limit")
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_APPEND
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0)
            )
            fd = os.open(self.path, flags, 0o600)
            try:
                self._check_paths()
                remaining = memoryview(line)
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise OSError("no write progress")
                    remaining = remaining[written:]
                self._sync(fd)
            except OSError:
                raise AppendUncertain("journal_append_uncertain") from None
            finally:
                os.close(fd)
            # No new-event receipt/projection is published before successful journal fsync.
            return self._receipt(event, "appended", historical=False)

    @staticmethod
    def _check_retraction(intent: RulingIntent, target: RulingEvent | None) -> None:
        if (
            target is None
            or not isinstance(target.payload, PairDecision)
            or subject_key(target.namespace, target.subject)
            != subject_key(intent.namespace, intent.subject)
            or target.generation_identity != intent.generation_identity
        ):
            # ValueError allows replay to report a corrupt historical line; append wraps the code.
            raise ValueError("invalid_retraction_target")

    @staticmethod
    def _receipt(
        event: RulingEvent, outcome: Literal["appended", "exact_retry"], *, historical: bool
    ) -> AppendReceipt:
        return AppendReceipt(
            event_id=event.event_id,
            sequence=event.sequence,
            intent_sha256=hashlib.sha256(intent_bytes(event)).hexdigest(),
            outcome=outcome,
            historical=historical,
        )
