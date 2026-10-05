"""Tool tests, through the handler layer (Gate) and through a real MCP client."""

import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import anyio
import pytest
from mcp import Client, StdioServerParameters

from consent_gate import server as server_mod
from consent_gate.audit import AuditLog, verify
from consent_gate.config import CONFIG_DIR, load_policy_config
from consent_gate.db import CustomerStore
from consent_gate.seed import build_database
from consent_gate.server import build_server
from consent_gate.tools import NOT_AVAILABLE, Gate, GateError

ROLE_TOOLS = {
    "support_agent": ["whoami", "lookup_customer"],
    "marketing_analyst": ["whoami", "search_customers", "get_marketing_audience"],
    "fraud_investigator": ["whoami", "lookup_customer", "search_customers"],
}
ROLE_KEYS = {
    "support_agent": {
        "customer_id", "full_name", "email", "phone", "state", "ssn_last4", "untrusted_notes",
    },
    "marketing_analyst": {"customer_id", "full_name", "email", "state", "segment"},
    "fraud_investigator": {
        "customer_id", "full_name", "email", "phone", "ssn_last4", "card_last4", "state",
        "segment", "do_not_sell_or_share", "untrusted_notes", "created_at",
    },
}  # fmt: skip


@pytest.fixture(scope="module")
def cfg():
    return load_policy_config(CONFIG_DIR)


@pytest.fixture(scope="module")
def db_path(tmp_path_factory) -> Path:
    return build_database(tmp_path_factory.mktemp("db") / "larkspur.db")


@pytest.fixture
def audit_path(tmp_path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def gate(cfg, db_path, audit_path):
    def make(role: str) -> Gate:
        return Gate(role, cfg, CustomerStore(db_path), AuditLog(audit_path))

    return make


def audit_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def query(db_path: Path, sql: str, *params) -> list[tuple]:
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(sql, params).fetchall()


# ===================================================================== whoami


@pytest.mark.parametrize("role", sorted(ROLE_TOOLS))
def test_whoami_describes_role(gate, cfg, audit_path, role):
    resp = gate(role).whoami()
    assert resp.role == role
    assert resp.visible_tools == ROLE_TOOLS[role]
    assert [p.name for p in resp.allowed_purposes] == list(cfg.roles[role].purposes)
    assert set(resp.fields_returned) == ROLE_KEYS[role]
    [row] = audit_rows(audit_path)
    assert row["tool"] == "whoami" and row["decision"] == "allow"
    assert row["request_id"] == resp.request_id


# ============================================================ lookup_customer


def test_support_lookup_servicing(gate, db_path, audit_path):
    resp = gate("support_agent").lookup_customer("C00042", "servicing")
    assert resp.decision == "allow"
    [rec] = resp.records
    assert set(rec) == ROLE_KEYS["support_agent"]
    [(ssn,)] = query(db_path, "SELECT ssn FROM customers WHERE customer_id = 'C00042'")
    assert rec["ssn_last4"] == f"***-**-{ssn[-4:]}"
    [row] = audit_rows(audit_path)
    assert row["record_ids_returned"] == ["C00042"]
    assert row["fields_masked"] == ["ssn"]
    assert row["purpose"] == "servicing"


def test_fraud_lookup_has_card_last4(gate, db_path):
    resp = gate("fraud_investigator").lookup_customer("C00042", "fraud_prevention")
    [rec] = resp.records
    [(card,)] = query(db_path, "SELECT card_number FROM customers WHERE customer_id = 'C00042'")
    assert rec["card_last4"] == f"**** **** **** {card[-4:]}"
    assert set(rec) == ROLE_KEYS["fraud_investigator"]


def test_lookup_with_disallowed_purpose_denied(gate, audit_path):
    resp = gate("support_agent").lookup_customer("C00042", "marketing")
    assert resp.decision == "deny"
    assert resp.reason == "Denied: purpose 'marketing' is not permitted for role 'support_agent'"
    assert resp.records == []
    assert audit_rows(audit_path)[0]["decision"] == "deny"


def test_handler_guards_tools_not_permitted_for_role(gate):
    # Not registered for marketing_analyst; the handler refuses anyway (defense in depth).
    resp = gate("marketing_analyst").lookup_customer("C00042", "marketing")
    assert resp.decision == "deny"
    assert "not permitted for role 'marketing_analyst'" in resp.reason


@pytest.mark.parametrize("cid", ["42", "C42", "C00042; DROP TABLE customers", "c00042"])
def test_lookup_rejects_malformed_ids(gate, cid):
    resp = gate("support_agent").lookup_customer(cid, "servicing")
    assert resp.decision == "deny"
    assert "customer_id" in resp.reason


def test_lookup_unknown_customer_does_not_reveal_existence(gate, audit_path):
    resp = gate("support_agent").lookup_customer("C99999", "servicing")
    assert resp.decision == "deny"
    assert resp.reason == NOT_AVAILABLE
    assert audit_rows(audit_path)[0]["reason"] == "Denied: no such customer"


def test_injected_notes_returned_as_labeled_untrusted_data(gate):
    resp = gate("support_agent").lookup_customer("C00007", "servicing")
    notes = resp.records[0]["untrusted_notes"]
    assert notes["warning"].startswith("Customer-supplied or staff-entered text")
    assert "ignore previous instructions" in notes["text"]


# =========================================================== search_customers


def test_search_analytics_returns_only_granted(gate, db_path):
    resp = gate("marketing_analyst").search_customers("analytics", state="CA", limit=25)
    granted = {
        cid
        for (cid,) in query(
            db_path,
            "SELECT c.customer_id FROM customers c JOIN consents k USING (customer_id) "
            "WHERE c.state = 'CA' AND k.purpose = 'analytics' AND k.status = 'granted'",
        )
    }
    [(total,)] = query(db_path, "SELECT COUNT(*) FROM customers WHERE state = 'CA'")
    returned = {r["customer_id"] for r in resp.records}
    assert returned <= granted
    assert resp.excluded_by_consent == total - len(granted)
    assert all(set(r) == ROLE_KEYS["marketing_analyst"] for r in resp.records)
    assert resp.excluded_by_reason is None  # breakdown only on the audience tool


def test_search_lowercase_state_accepted(gate):
    assert gate("fraud_investigator").search_customers("fraud_prevention", state="pa").returned > 0


def test_search_limit_above_cap_is_clamped(gate, audit_path):
    resp = gate("fraud_investigator").search_customers("fraud_prevention", limit=10_000)
    assert resp.returned == 25
    assert resp.truncated is True
    assert resp.decision == "partial"
    row = audit_rows(audit_path)[0]
    assert len(row["record_ids_returned"]) == 25
    assert row["args"]["limit"] == 10_000
    assert "server cap 25" in row["reason"]


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"limit": 0}, "limit"),
        ({"segment": "vip"}, "segment"),
        ({"state": "Pennsylvania"}, "state"),
        ({"name_contains": "x" * 65}, "name_contains"),
        ({"name_contains": ""}, "name_contains"),
    ],
)
def test_search_rejects_bad_filters(gate, audit_path, kwargs, fragment):
    resp = gate("fraud_investigator").search_customers("fraud_prevention", **kwargs)
    assert resp.decision == "deny"
    assert fragment in resp.reason
    assert audit_rows(audit_path)[0]["decision"] == "deny"


def test_search_name_filter_treats_wildcards_literally(gate):
    resp = gate("fraud_investigator").search_customers("fraud_prevention", name_contains="%")
    assert resp.returned == 0


def _unique_name_with_marketing(db_path: Path, status: str) -> str:
    return query(
        db_path,
        "SELECT c.full_name FROM customers c JOIN consents k USING (customer_id) "
        "WHERE k.purpose = 'marketing' AND k.status = ? AND c.full_name IN "
        "(SELECT full_name FROM customers GROUP BY full_name HAVING COUNT(*) = 1) "
        "ORDER BY c.customer_id LIMIT 1",
        status,
    )[0][0]


def test_name_search_does_not_reveal_one_persons_consent(gate, db_path, audit_path):
    m = gate("marketing_analyst")
    opted_out = m.search_customers(
        "marketing", name_contains=_unique_name_with_marketing(db_path, "denied")
    )
    opted_in = m.search_customers(
        "marketing", name_contains=_unique_name_with_marketing(db_path, "granted")
    )
    assert (opted_out.returned, opted_in.returned) == (0, 1)
    for resp in (opted_out, opted_in):
        assert resp.decision == "allow"
        assert resp.excluded_by_consent is None
        assert "not reported for name searches" in resp.reason
        assert "excluded" not in resp.reason
    # The audit log keeps the truth.
    rows = audit_rows(audit_path)
    assert [r["excluded_count"] for r in rows] == [1, 0]
    assert [r["decision"] for r in rows] == ["partial", "allow"]


def test_search_without_name_filter_still_reports_exclusions(gate):
    resp = gate("marketing_analyst").search_customers("marketing", state="PA")
    assert resp.excluded_by_consent is not None and resp.excluded_by_consent > 0


def test_search_unknown_purpose_denied(gate):
    resp = gate("marketing_analyst").search_customers("research", segment="affluent")
    assert resp.decision == "deny"
    assert resp.reason == "Denied: unknown purpose 'research'"


# ===================================================== get_marketing_audience


def test_audience_matches_consent_and_opt_out(gate, db_path, audit_path):
    resp = gate("marketing_analyst").get_marketing_audience("affluent", "marketing")
    eligible = [
        cid
        for (cid,) in query(
            db_path,
            "SELECT c.customer_id FROM customers c JOIN consents k USING (customer_id) "
            "WHERE c.segment = 'affluent' AND k.purpose = 'marketing' AND k.status = 'granted' "
            "AND c.do_not_sell_or_share = 0 ORDER BY c.customer_id",
        )
    ]
    [(total,)] = query(db_path, "SELECT COUNT(*) FROM customers WHERE segment = 'affluent'")
    assert [r["customer_id"] for r in resp.records] == eligible[:50]
    assert resp.truncated == (len(eligible) > 50)
    assert resp.excluded_by_consent == total - len(eligible)
    assert sum(resp.excluded_by_reason.values()) == resp.excluded_by_consent
    assert set(resp.excluded_by_reason) <= {"consent_not_granted", "do_not_sell_or_share"}
    assert resp.excluded_by_reason["do_not_sell_or_share"] > 0
    row = audit_rows(audit_path)[0]
    assert row["decision"] == "partial"
    assert "do-not-sell/share" in row["reason"]


def test_audience_requires_marketing_purpose(gate):
    resp = gate("marketing_analyst").get_marketing_audience("affluent", "analytics")
    assert resp.decision == "deny"
    assert "requires purpose 'marketing'" in resp.reason


def test_audience_denied_for_support_agent(gate):
    resp = gate("support_agent").get_marketing_audience("affluent", "marketing")
    assert resp.decision == "deny"


# ============================================================ audit coupling


def test_every_handler_call_writes_one_linked_audit_record(gate, audit_path):
    m, s, f = gate("marketing_analyst"), gate("support_agent"), gate("fraud_investigator")
    responses = [
        m.whoami(),
        m.search_customers("marketing", segment="mass"),
        m.get_marketing_audience("small_business", "marketing", state="TX"),
        m.lookup_customer("C00001", "marketing"),
        s.lookup_customer("C00007", "servicing"),
        s.lookup_customer("C00001", "research"),
        f.search_customers("fraud_prevention", limit=500),
    ]
    rows = audit_rows(audit_path)
    assert [r["request_id"] for r in rows] == [r.request_id for r in responses]
    assert verify(audit_path).ok


def test_audit_failure_returns_no_data(cfg, db_path, tmp_path):
    blocked = tmp_path / "audit.jsonl"
    blocked.mkdir()  # a directory where the log file should be
    g = Gate("support_agent", cfg, CustomerStore(db_path), AuditLog(blocked))
    with pytest.raises(GateError, match="audit log could not be written"):
        g.lookup_customer("C00042", "servicing")


def test_missing_database_is_an_audited_error(cfg, tmp_path, audit_path):
    g = Gate("support_agent", cfg, CustomerStore(tmp_path / "nope.db"), AuditLog(audit_path))
    with pytest.raises(GateError, match="not set up"):
        g.lookup_customer("C00042", "servicing")
    [row] = audit_rows(audit_path)
    assert row["decision"] == "deny"
    assert row["reason"] == "Error: FileNotFoundError"


# =============================================== invariants 10 and 11, tool level


def test_no_full_ssn_or_card_and_only_allowed_keys_in_any_tool_output(gate, db_path):
    secrets = {v for row in query(db_path, "SELECT ssn, card_number FROM customers") for v in row}
    secrets |= {s.replace("-", "") for s in secrets}
    outputs = []
    f = gate("fraud_investigator")
    s = gate("support_agent")
    m = gate("marketing_analyst")
    for state in ("PA", "CA", "TX", "NY", "FL", "OH"):
        outputs.append(
            ("fraud_investigator", f.search_customers("fraud_prevention", state=state, limit=25))
        )
    for n in range(1, 501, 7):
        outputs.append(("support_agent", s.lookup_customer(f"C{n:05d}", "servicing")))
    for seg in ("mass", "affluent", "small_business"):
        outputs.append(("marketing_analyst", m.get_marketing_audience(seg, "marketing")))
    for role, resp in outputs:
        text = resp.model_dump_json()
        assert not any(sec in text for sec in secrets), role
        for rec in resp.records:
            assert set(rec) <= ROLE_KEYS[role]


# ======================================================== MCP server layer


def call(server, name: str, args: dict):
    async def go():
        async with Client(server) as client:
            return await client.call_tool(name, args)

    return anyio.run(go)


def list_tool_names(server) -> list[str]:
    async def go():
        async with Client(server) as client:
            return sorted(t.name for t in (await client.list_tools()).tools)

    return anyio.run(go)


@pytest.fixture
def make_server(cfg, db_path, audit_path):
    def make(role: str):
        return build_server(role, cfg=cfg, db_path=db_path, audit_path=audit_path)

    return make


@pytest.mark.parametrize("role", sorted(ROLE_TOOLS))
def test_only_role_tools_are_registered(make_server, role):
    assert list_tool_names(make_server(role)) == sorted(ROLE_TOOLS[role])


def test_unknown_role_refuses_to_build(cfg):
    with pytest.raises(ValueError, match="unknown role"):
        build_server("admin", cfg=cfg)


def test_client_lookup_returns_structured_envelope(make_server, audit_path):
    result = call(make_server("support_agent"), "lookup_customer",
                  {"customer_id": "C00042", "purpose": "servicing"})  # fmt: skip
    assert not result.is_error
    body = result.structured_content
    assert body["decision"] == "allow"
    assert body["records"][0]["customer_id"] == "C00042"
    assert [r["request_id"] for r in audit_rows(audit_path)] == [body["request_id"]]


def test_client_unknown_tool_is_audited(make_server, audit_path):
    result = call(make_server("fraud_investigator"), "export_all_customers", {"format": "csv"})
    assert result.is_error
    [row] = audit_rows(audit_path)
    assert row["tool"] == "export_all_customers"
    assert row["decision"] == "deny"
    assert row["reason"] == "Denied: unknown tool 'export_all_customers'"


def test_client_unregistered_tool_is_audited_with_policy_reason(make_server, audit_path):
    result = call(make_server("marketing_analyst"), "lookup_customer",
                  {"customer_id": "C00042", "purpose": "marketing"})  # fmt: skip
    assert result.is_error
    [row] = audit_rows(audit_path)
    assert row["reason"] == (
        "Denied: tool 'lookup_customer' is not permitted for role 'marketing_analyst'"
    )
    assert row["purpose"] == "marketing"


def test_client_schema_rejection_is_audited(make_server, audit_path):
    result = call(make_server("fraud_investigator"), "search_customers",
                  {"purpose": "fraud_prevention", "limit": "lots"})  # fmt: skip
    assert result.is_error
    [row] = audit_rows(audit_path)
    assert row["reason"] == "Denied: invalid arguments for tool 'search_customers'"


def test_client_role_argument_is_ignored(make_server):
    result = call(make_server("support_agent"), "lookup_customer",
                  {"customer_id": "C00042", "purpose": "servicing",
                   "role": "fraud_investigator"})  # fmt: skip
    rec = result.structured_content["records"][0]
    assert "card_last4" not in rec
    assert set(rec) == ROLE_KEYS["support_agent"]


def test_client_audit_failure_is_an_error_with_no_data(cfg, db_path, tmp_path):
    blocked = tmp_path / "audit.jsonl"
    blocked.mkdir()
    srv = build_server("support_agent", cfg=cfg, db_path=db_path, audit_path=blocked)
    result = call(srv, "lookup_customer", {"customer_id": "C00042", "purpose": "servicing"})
    assert result.is_error
    assert result.structured_content is None
    assert "C00042" not in json.dumps([c.model_dump() for c in result.content])


@pytest.mark.parametrize("role", [None, "", "admin"])
def test_main_refuses_to_start_without_valid_role(monkeypatch, role):
    if role is None:
        monkeypatch.delenv(server_mod.ROLE_ENV, raising=False)
    else:
        monkeypatch.setenv(server_mod.ROLE_ENV, role)
    assert server_mod.main() == 2


def test_stdio_end_to_end(db_path, audit_path):
    """Launch the real server process and talk to it over stdio."""
    env = dict(os.environ)
    env.update(
        {
            "CONSENT_GATE_ROLE": "marketing_analyst",
            "CONSENT_GATE_DB": str(db_path),
            "CONSENT_GATE_AUDIT_LOG": str(audit_path),
        }
    )
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "consent_gate.server"], env=env
    )

    async def go():
        async with Client(params) as client:
            names = sorted(t.name for t in (await client.list_tools()).tools)
            who = await client.call_tool("whoami", {})
            return names, who

    names, who = anyio.run(go)
    assert names == sorted(ROLE_TOOLS["marketing_analyst"])
    assert who.structured_content["role"] == "marketing_analyst"
    assert [r["tool"] for r in audit_rows(audit_path)] == ["whoami"]
