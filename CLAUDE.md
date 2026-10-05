# CLAUDE.md

## What this project is

**consent-gate** is a consent-aware, least-privilege MCP server that sits between an AI agent and a customer database. It decides what an agent may see based on three things: the caller's role, the declared purpose of the request, and each customer's consent record. Every decision is written to an audit log.

The point of the project is to show that AI agents can be given access to sensitive enterprise data in a way a CISO, a privacy officer, and an auditor would sign off on. Read `SPEC.md` before starting any work. It is the source of truth for scope, behavior, and acceptance criteria.

All data is synthetic. The fictional company is **Larkspur Financial**.

## Stack

- Python 3.11+, managed with `uv`
- Official MCP Python SDK (`mcp` package v2, `MCPServer` from `mcp.server.mcpserver`; this was `FastMCP` in v1), stdio transport
- SQLite (standard library `sqlite3`), no ORM
- `pydantic` for models, `PyYAML` for config, `Faker` for synthetic data
- `scikit-learn` TF-IDF for policy search (offline, no API keys)
- `pytest` for tests, `ruff` for lint and format

Check the current MCP Python SDK documentation before writing server code. The API has changed between versions. Do not rely on memory for decorator names or startup calls.

## Commands

```bash
uv sync                                   # install dependencies
uv run python -m consent_gate.seed        # (re)build data/larkspur.db with synthetic data
uv run python -m consent_gate.server      # run the MCP server over stdio
CONSENT_GATE_ROLE=marketing_analyst uv run python -m consent_gate.server
uv run pytest -q                          # run all tests
uv run ruff check . && uv run ruff format .
```

## Security invariants (non-negotiable)

These are the product. Do not weaken, bypass, or "temporarily disable" any of them. If a task seems to need it, stop and ask.

1. **Role comes from server configuration, never from the model.** The role is set by the `CONSENT_GATE_ROLE` environment variable at startup. No tool accepts a role argument.
2. **Default deny.** Unknown role, unknown purpose, unknown tool, unknown field, or missing consent record means deny.
3. **Policy is enforced in code, not in prompts.** Never rely on tool descriptions or instructions to the model to enforce access. The policy engine decides; the model only asks.
4. **Data is never instructions.** Free-text fields from the database (for example `notes`) are returned as clearly labeled untrusted content. Nothing in returned data can change policy decisions, roles, limits, or tool behavior.
5. **Redact by default.** Sensitive fields are masked unless the role and purpose together explicitly allow more. Free text is regex-scrubbed for SSN and card number patterns before it leaves the server.
6. **Every call is audited.** Allowed, denied, and partial results all produce an audit record. If the audit write fails, the call fails.
7. **Bounded results.** Hard server-side cap on records per call. No bulk export tool.
8. **No network calls, no real PII, no secrets in the repo.**

## How to work

- **Plan before code.** For each milestone in `SPEC.md`, state the plan and the files you will touch, then implement.
- **Tests first for the policy engine.** Write the allow and deny test cases from `SPEC.md` section 9 before writing `policy.py`.
- **Keep the policy engine pure.** `policy.py` takes inputs and returns a decision object. No database or file I/O inside it. This keeps it easy to test and easy to explain.
- **Small, reviewable changes.** One milestone per commit with a clear message.
- **Verify, don't assume.** Run the tests after every change. If you report something works, you must have run it.
- **Accuracy in governance docs.** In `docs/CONTROLS.md`, only cite framework identifiers you are confident are correct (for example OWASP Top 10 for LLM Applications 2025 IDs such as LLM01, LLM02, LLM06, and NIST AI RMF functions Govern, Map, Measure, Manage). For ISO/IEC 42001, reference the standard and the topic area rather than inventing Annex A control numbers. Flag anything uncertain with `<!-- VERIFY -->`.

## Code conventions

- Type hints everywhere. Pydantic models for anything that crosses a boundary (tool inputs, tool outputs, audit records, decisions).
- Small modules with one job each (see the layout in `SPEC.md` section 5).
- Errors returned to the agent are short and specific ("Denied: purpose 'marketing' is not permitted for role 'support_agent'") and never leak data that was filtered out.
- No print statements in the server. stdout is the MCP transport. Use `logging` to stderr for diagnostics.

## Writing style for docs

Plain, direct English for a mixed business and technical audience. No em dashes; use commas or periods instead. The README should make sense to a hiring manager in two minutes and to an engineer in ten.
