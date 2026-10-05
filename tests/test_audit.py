import json
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from consent_gate import audit
from consent_gate.audit import GENESIS_HASH, AuditLog, AuditWriteError, compute_hash, verify
from consent_gate.models import AuditEvent

FIXED_TIME = datetime(2026, 10, 5, 14, 3, 22, tzinfo=UTC)


def event(n: int = 0, **overrides) -> AuditEvent:
    base = {
        "request_id": f"req-{n}",
        "role": "marketing_analyst",
        "tool": "get_marketing_audience",
        "purpose": "marketing",
        "args": {"segment": "affluent", "state": "PA"},
        "decision": "partial",
        "reason": "41 excluded",
        "record_ids_returned": ["C00012"],
        "excluded_count": 41,
    }
    return AuditEvent(**(base | overrides))


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "logs" / "audit.jsonl"


def write_n(path: Path, n: int) -> list[dict]:
    log = AuditLog(path, clock=lambda: FIXED_TIME)
    for i in range(n):
        log.append(event(i))
    return read_lines(path)


def read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def write_lines(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


# ------------------------------------------------------------------ writing


def test_first_record_links_to_genesis(log_path):
    rec = AuditLog(log_path, clock=lambda: FIXED_TIME).append(event())
    assert rec.prev_hash == GENESIS_HASH
    assert rec.ts == "2026-10-05T14:03:22Z"
    [line] = read_lines(log_path)
    assert line["hash"] == rec.hash == compute_hash(line)


def test_records_chain_together(log_path):
    rows = write_n(log_path, 5)
    for prev, cur in zip(rows, rows[1:], strict=False):
        assert cur["prev_hash"] == prev["hash"]
    assert verify(log_path).ok


def test_log_contains_spec_fields(log_path):
    [row] = write_n(log_path, 1)
    assert set(row) == {
        "ts", "request_id", "role", "tool", "purpose", "args", "decision", "reason",
        "record_ids_returned", "excluded_count", "fields_masked", "scrub_replacements",
        "prev_hash", "hash",
    }  # fmt: skip


def test_new_log_instance_continues_existing_chain(log_path):
    write_n(log_path, 2)
    AuditLog(log_path).append(event(99))
    assert verify(log_path).records == 3
    assert verify(log_path).ok


def test_args_are_scrubbed_and_capped(log_path):
    AuditLog(log_path).append(
        event(
            args={
                "name_contains": "900-12-3456",
                "note": "x" * 1000,
                "nested": ["4111111111111111"],
            }
        )
    )
    [row] = read_lines(log_path)
    assert row["args"]["name_contains"] == "[REDACTED-SSN]"
    assert row["args"]["nested"] == ["[REDACTED-CARD]"]
    assert len(row["args"]["note"]) < 300
    assert verify(log_path).ok


# ---------------------------------------------------------------- verifying


def test_verify_missing_file_is_ok(log_path):
    result = verify(log_path)
    assert result.ok and result.records == 0


def test_tampered_field_fails_verify(log_path):
    rows = write_n(log_path, 5)
    rows[2]["decision"] = "allow"
    write_lines(log_path, rows)
    result = verify(log_path)
    assert not result.ok
    assert result.failed_line == 3
    assert "hash" in result.message


def test_tampered_record_with_reforged_hash_breaks_next_link(log_path):
    rows = write_n(log_path, 5)
    rows[2]["record_ids_returned"] = []
    rows[2]["hash"] = compute_hash(rows[2])
    write_lines(log_path, rows)
    result = verify(log_path)
    assert not result.ok
    assert result.failed_line == 4
    assert "prev_hash" in result.message


def test_deleted_line_fails_verify(log_path):
    rows = write_n(log_path, 5)
    write_lines(log_path, rows[:2] + rows[3:])
    assert verify(log_path).failed_line == 3


def test_reordered_lines_fail_verify(log_path):
    rows = write_n(log_path, 5)
    rows[1], rows[2] = rows[2], rows[1]
    write_lines(log_path, rows)
    assert not verify(log_path).ok


def test_injected_extra_field_fails_verify(log_path):
    rows = write_n(log_path, 3)
    rows[1]["approved_by"] = "ciso"
    rows[1]["hash"] = compute_hash(rows[1])
    write_lines(log_path, rows)
    assert verify(log_path).failed_line == 2


def test_truncated_final_line_fails_verify(log_path):
    write_n(log_path, 3)
    raw = log_path.read_bytes()
    log_path.write_bytes(raw[:-20])
    result = verify(log_path)
    assert not result.ok and result.failed_line == 3


# ----------------------------------------------------------------- fail closed


def test_append_refuses_when_tail_is_corrupt(log_path):
    write_n(log_path, 2)
    log_path.write_bytes(log_path.read_bytes()[:-20])
    with pytest.raises(AuditWriteError):
        AuditLog(log_path).append(event())


def test_append_refuses_when_tail_hash_was_edited(log_path):
    rows = write_n(log_path, 2)
    rows[-1]["reason"] = "nothing to see"
    write_lines(log_path, rows)
    with pytest.raises(AuditWriteError):
        AuditLog(log_path).append(event())


def test_append_to_unwritable_path_raises(tmp_path):
    blocker = tmp_path / "audit.jsonl"
    blocker.mkdir()  # a directory where the log file should be
    with pytest.raises(AuditWriteError):
        AuditLog(blocker).append(event())


# --------------------------------------------------------------------- CLI


def test_cli_verify_exit_codes(log_path, capsys):
    rows = write_n(log_path, 3)
    assert audit.main(["verify", "--path", str(log_path)]) == 0
    assert "OK: 3 records" in capsys.readouterr().out
    rows[0]["purpose"] = "servicing"
    write_lines(log_path, rows)
    assert audit.main(["verify", "--path", str(log_path)]) == 1
    assert "FAILED at line 1" in capsys.readouterr().err


# ------------------------------------------------------------- concurrency


def test_concurrent_threads_keep_chain_intact(log_path):
    log = AuditLog(log_path)

    def worker(t: int) -> None:
        for i in range(25):
            log.append(event(t * 1000 + i))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    result = verify(log_path)
    assert result.ok, result.message
    assert result.records == 100


def test_concurrent_processes_keep_chain_intact(log_path):
    """One server process runs per role, all sharing one log."""
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from consent_gate.audit import AuditLog\n"
        "from consent_gate.models import AuditEvent\n"
        "log = AuditLog(Path(sys.argv[1]))\n"
        "for i in range(20):\n"
        "    log.append(AuditEvent(request_id=f'{sys.argv[2]}-{i}', role='r', tool='t',\n"
        "        purpose=None, args={}, decision='allow', reason='ok'))\n"
    )
    procs = [
        subprocess.Popen([sys.executable, "-c", script, str(log_path), str(p)])  # noqa: S603
        for p in range(3)
    ]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    result = verify(log_path)
    assert result.ok, result.message
    assert result.records == 60
