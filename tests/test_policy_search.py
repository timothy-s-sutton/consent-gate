import json
from pathlib import Path

import anyio
import pytest
from mcp import Client

from consent_gate.audit import AuditLog
from consent_gate.config import CONFIG_DIR, load_policy_config
from consent_gate.db import CustomerStore
from consent_gate.policy_search import POLICIES_DIR, PolicyIndex, chunk_markdown
from consent_gate.server import build_server
from consent_gate.tools import Gate

# (question, expected source, expected heading suffix) for the top-ranked result.
SAMPLE_QUESTIONS = [
    (
        "Can I use customer email addresses for a marketing campaign?",
        "privacy_notice.md",
        "Purposes of processing and legal basis > Marketing",
    ),
    (
        "How must Social Security numbers be classified and displayed?",
        "data_classification.md",
        "Classification levels > Restricted",
    ),
    (
        "Does a person need to review AI recommendations before acting on a customer?",
        "ai_acceptable_use.md",
        "Human review",
    ),
    (
        "What happens if a customer opts out of the sale or sharing of their personal information?",
        "privacy_notice.md",
        "Do not sell or share my personal information",
    ),
    (
        "Are AI agent tool calls logged, and who reviews the logs?",
        "ai_acceptable_use.md",
        "Logging and monitoring",
    ),
]


@pytest.fixture(scope="module")
def index() -> PolicyIndex:
    return PolicyIndex.from_directory(POLICIES_DIR)


@pytest.fixture
def audit_path(tmp_path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def gate(index, audit_path, tmp_path):
    def make(role: str = "marketing_analyst") -> Gate:
        return Gate(
            role,
            load_policy_config(CONFIG_DIR),
            CustomerStore(tmp_path / "unused.db"),  # policy search never touches it
            AuditLog(audit_path),
            policy_index=lambda: index,
        )

    return make


def audit_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------------ documents


@pytest.mark.parametrize(
    "name", ["privacy_notice.md", "data_classification.md", "ai_acceptable_use.md"]
)
def test_policy_documents_exist_and_are_marked_fictional(name):
    text = (POLICIES_DIR / name).read_text(encoding="utf-8")
    assert "FICTIONAL DOCUMENT" in text
    assert 400 <= len(text.split()) <= 800
    assert "—" not in text  # no em dashes (CLAUDE.md writing style)


# ------------------------------------------------------------------ chunking


def test_chunking_follows_headings():
    md = "# Title\n\nintro\n\n## A\n\nalpha\n\n### A1\n\nalpha one\n\n## B\n\nbeta\n"
    chunks = chunk_markdown("doc.md", md)
    assert [(c.heading, c.text) for c in chunks] == [
        ("Title", "intro"),
        ("Title > A", "alpha"),
        ("Title > A > A1", "alpha one"),
        ("Title > B", "beta"),
    ]
    assert {c.source for c in chunks} == {"doc.md"}


def test_headings_without_body_are_skipped():
    chunks = chunk_markdown("doc.md", "# Title\n\n## Empty\n\n## Full\n\ntext\n")
    assert [c.heading for c in chunks] == ["Title > Full"]


def test_index_covers_all_three_documents(index):
    assert {c.source for c in index.chunks} == {
        "privacy_notice.md",
        "data_classification.md",
        "ai_acceptable_use.md",
    }


# ------------------------------------------------------------------ retrieval


@pytest.mark.parametrize(("question", "source", "heading"), SAMPLE_QUESTIONS)
def test_sample_questions_return_expected_cited_section_first(index, question, source, heading):
    hits = index.search(question, 3)
    assert hits, question
    assert hits[0].source == source
    assert hits[0].heading.endswith(heading)
    assert hits[0].score > hits[1].score


def test_scores_are_descending(index):
    hits = index.search("consent for marketing and analytics", 5)
    assert [h.score for h in hits] == sorted((h.score for h in hits), reverse=True)


def test_unrelated_question_returns_nothing(index):
    assert index.search("What is the capital of Mongolia?", 5) == []


# ------------------------------------------------------------------ tool handler


def test_search_policy_handler_returns_citations_and_audits(gate, audit_path):
    resp = gate().search_policy(SAMPLE_QUESTIONS[0][0])
    assert resp.decision == "allow"
    assert resp.returned == len(resp.results) == 3
    assert resp.results[0].source == "privacy_notice.md"
    [row] = audit_rows(audit_path)
    assert row["tool"] == "search_policy"
    assert row["purpose"] is None
    assert row["record_ids_returned"] == []
    assert row["request_id"] == resp.request_id


def test_k_above_cap_is_clamped(gate, audit_path):
    resp = gate().search_policy("consent", k=50)
    assert resp.returned <= 5
    assert resp.truncated is True
    assert resp.decision == "partial"
    assert audit_rows(audit_path)[0]["args"]["k"] == 50


@pytest.mark.parametrize(
    ("question", "k", "fragment"),
    [("", 3, "question"), ("   ", 3, "question"), ("x" * 501, 3, "question"), ("consent", 0, "k")],
)
def test_bad_inputs_are_denied_and_audited(gate, audit_path, question, k, fragment):
    resp = gate().search_policy(question, k=k)
    assert resp.decision == "deny"
    assert fragment in resp.reason
    assert resp.results == []
    assert audit_rows(audit_path)[0]["decision"] == "deny"


def test_no_match_is_allowed_with_empty_results(gate):
    resp = gate().search_policy("What is the capital of Mongolia?")
    assert resp.decision == "allow"
    assert resp.results == []
    assert "no policy text matched" in resp.reason


# ------------------------------------------------------------------ MCP layer


@pytest.mark.parametrize("role", ["support_agent", "marketing_analyst", "fraud_investigator"])
def test_every_role_can_search_policy_over_mcp(role, tmp_path, audit_path):
    srv = build_server(role, db_path=tmp_path / "unused.db", audit_path=audit_path)

    async def go():
        async with Client(srv) as client:
            return await client.call_tool("search_policy", {"question": SAMPLE_QUESTIONS[1][0]})

    result = anyio.run(go)
    assert not result.is_error
    top = result.structured_content["results"][0]
    assert top["source"] == "data_classification.md"
    assert "Restricted" in top["heading"]
