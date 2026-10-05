"""Append-only, hash-chained JSONL audit log.

Each line holds prev_hash (the previous line's hash) and hash, the SHA-256 of
the line's canonical JSON without the hash field. Editing, deleting, inserting,
or reordering any line breaks the chain, which `verify` detects.

Writes take a cross-process file lock, because one server process runs per role
and they all share one log. Any failure raises AuditWriteError so the caller can
fail the tool call (fail closed).

Residual risk: someone who can rewrite the whole file can recompute every hash.
Production would ship records to WORM storage or a SIEM.

CLI: uv run python -m consent_gate.audit verify [--path logs/audit.jsonl]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from pydantic import BaseModel, ValidationError

from consent_gate.config import PROJECT_ROOT
from consent_gate.models import AuditEvent, AuditRecord
from consent_gate.redact import scrub_text

DEFAULT_AUDIT_PATH = PROJECT_ROOT / "logs" / "audit.jsonl"
GENESIS_HASH = "0" * 64
MAX_ARG_CHARS = 256

_HEX64 = re.compile(r"[0-9a-f]{64}")


class AuditWriteError(RuntimeError):
    """The audit record could not be written. The tool call must fail."""


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def compute_hash(record: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the record without its hash field."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _sanitize(value: Any) -> Any:
    """Scrub and cap caller-supplied args so the log cannot become a leak or a flood."""
    if isinstance(value, str):
        text = scrub_text(value).text
        return text if len(text) <= MAX_ARG_CHARS else text[:MAX_ARG_CHARS] + "...[truncated]"
    if isinstance(value, dict):
        return {str(k)[:MAX_ARG_CHARS]: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_sanitize(v) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return _sanitize(str(value))


# Serializes writers inside one process; the file lock serializes across processes.
_THREAD_LOCK = threading.Lock()
LOCK_TIMEOUT_SECONDS = 5.0


@contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    """Cross-process exclusive lock on a sidecar file. Raises OSError on timeout."""
    with _THREAD_LOCK, open(lock_path, "a+b") as fh:
        fh.seek(0)
        if os.name == "nt":
            import msvcrt

            # LK_LOCK sleeps a full second between retries, so poll non-blocking instead.
            deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.01)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _last_line(fh: IO[bytes]) -> bytes | None:
    """Return the last complete line, or None for an empty file."""
    fh.seek(0, os.SEEK_END)
    pos = fh.tell()
    if pos == 0:
        return None
    buf = b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        fh.seek(pos)
        buf = fh.read(step) + buf
        if buf.rfind(b"\n", 0, len(buf) - 1) != -1:
            break
    if not buf.endswith(b"\n"):
        raise AuditWriteError("audit log ends with an incomplete line; run verify")
    return buf[:-1].rsplit(b"\n", 1)[-1]


def _tail_hash(fh: IO[bytes]) -> str:
    """Hash of the last record, after checking that record is intact."""
    line = _last_line(fh)
    if line is None:
        return GENESIS_HASH
    try:
        last = json.loads(line)
    except json.JSONDecodeError as e:
        raise AuditWriteError("audit log tail is not valid JSON; run verify") from e
    if not isinstance(last, dict) or last.get("hash") != compute_hash(last):
        raise AuditWriteError("audit log tail hash does not match; run verify")
    return last["hash"]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditLog:
    def __init__(
        self, path: Path = DEFAULT_AUDIT_PATH, clock: Callable[[], datetime] = _utc_now
    ) -> None:
        self.path = Path(path)
        self._clock = clock

    def append(self, event: AuditEvent) -> AuditRecord:
        """Write one record. Raises AuditWriteError on any failure."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with _exclusive_lock(self.path.with_name(self.path.name + ".lock")):
                with open(self.path, "a+b") as fh:
                    data: dict[str, Any] = {
                        "ts": self._clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        **event.model_dump(mode="json"),
                    }
                    data["args"] = _sanitize(data["args"])
                    data["prev_hash"] = _tail_hash(fh)
                    data["hash"] = compute_hash(data)
                    record = AuditRecord.model_validate(data)
                    fh.write(json.dumps(data, ensure_ascii=False).encode() + b"\n")
                    fh.flush()
                    os.fsync(fh.fileno())
        except AuditWriteError:
            raise
        except (OSError, ValueError, ValidationError) as e:
            raise AuditWriteError(f"audit write failed: {type(e).__name__}") from e
        return record


class VerifyResult(BaseModel):
    ok: bool
    records: int
    failed_line: int | None = None
    message: str


def verify(path: Path = DEFAULT_AUDIT_PATH) -> VerifyResult:
    """Walk the whole log and check every line's schema, hash, and link."""
    path = Path(path)
    if not path.exists():
        return VerifyResult(ok=True, records=0, message="no audit log yet")

    def fail(n: int, msg: str) -> VerifyResult:
        return VerifyResult(ok=False, records=n - 1, failed_line=n, message=msg)

    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        n = raw.count(b"\n") + 1
        return fail(n, "incomplete final line")

    prev = GENESIS_HASH
    lines = raw.split(b"\n")[:-1] if raw else []
    for n, line in enumerate(lines, start=1):
        try:
            data = json.loads(line)
            record = AuditRecord.model_validate(data)
        except (json.JSONDecodeError, ValidationError):
            return fail(n, "line is not a valid audit record")
        if not _HEX64.fullmatch(record.hash) or record.hash != compute_hash(data):
            return fail(n, "hash does not match record contents")
        if record.prev_hash != prev:
            return fail(
                n, "prev_hash does not match previous record (deleted, inserted, or reordered)"
            )
        prev = record.hash
    return VerifyResult(ok=True, records=len(lines), message="chain intact")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="consent_gate.audit")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="check the audit log hash chain")
    v.add_argument("--path", type=Path, default=DEFAULT_AUDIT_PATH)
    args = parser.parse_args(argv)

    result = verify(args.path)
    if result.ok:
        print(f"OK: {result.records} records, {result.message} ({args.path})")
        return 0
    print(f"FAILED at line {result.failed_line}: {result.message} ({args.path})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
