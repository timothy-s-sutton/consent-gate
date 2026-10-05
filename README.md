# consent-gate

**Governed access to customer data for AI agents.** consent-gate is an [MCP](https://modelcontextprotocol.io) server that sits between an AI agent (such as Claude) and a customer database. On every request it decides what the agent may see based on three things: the agent's role, the purpose it declares, and each customer's consent record. Every decision is written to a tamper-evident audit log.

All data is synthetic. The company, Larkspur Financial, is fictional.

## Why this exists

Companies want AI agents to help with customer service, marketing, and fraud work. Security, privacy, and compliance teams usually block these projects, for good reasons:

- A general-purpose agent with database access has no idea of purpose or consent.
- It gets more access than any single job needs.
- Text hidden in the data it reads can steer it (prompt injection).
- Nobody can prove afterwards what it saw and why.

consent-gate shows a pattern those teams can sign off on. The agent never touches the database. It asks a gateway, and the gateway enforces the rules in code.

## What it does, in one table

| Role | May use data for | Gets these fields |
|---|---|---|
| Support agent | servicing | name, email, phone, state, SSN last 4, notes (scrubbed, labeled untrusted) |
| Marketing analyst | marketing, analytics | name, email, state, segment, and only for customers who consented |
| Fraud investigator | fraud prevention | all fields, SSN and card shown as last 4 only, notes (scrubbed, labeled untrusted) |

- **The role is set by whoever runs the server, never by the agent.** Asking nicely, claiming to be someone else, or planting instructions in the data changes nothing.
- **Purpose and consent are checked on every record.** Marketing and analytics need the customer's consent. Marketing also honors the CCPA/CPRA "do not sell or share" opt-out. Servicing and fraud prevention rely on other legal bases, so they do not need consent. That distinction is how privacy law actually works.
- **Default deny.** An unknown role, purpose, tool, or field is refused. So is a missing consent record.
- **No one ever sees a full SSN or card number.** Free text is scanned and SSN or card numbers are redacted before it leaves the server.
- **Every call is audited**, whether it was allowed, partly allowed, or denied. The log is hash-chained, so editing, deleting, or reordering any line is detectable. If the audit write fails, the call fails and no data is returned.
- **Results are capped** (25 per search, 50 per marketing audience) and there is no export tool.

## Proof

253 automated tests, including:

- Every allow and deny case in [SPEC.md](SPEC.md) section 9, written before the policy engine.
- **Prompt injection, end to end.** A sweep of 300+ calls runs against a clean database and one where every customer record carries an attack. Examples include "ignore previous instructions", fake JSON to break out of the response, fake system tags, fake tool calls, and hidden SSNs. Every decision, result set, and audit record is identical.
- A sweep of all 500 customers across every role confirms no SSN or card number ever appears in output.
- Audit tampering (edited, deleted, reordered, or forged lines) is detected.
- The real server process is launched and driven over stdio by an MCP client.

**Live red team** ([docs/RED_TEAM.md](docs/RED_TEAM.md)): eight adversarial prompts against Claude Code. Seven passed. In the eighth, asked to export the whole customer table, the agent did not attack the gateway; it tried to go around it by reading the database file directly with its own tools. Claude Code's safety check blocked that, not consent-gate. The lesson is the most important one in the project: a gateway only governs traffic that goes through it, so the agent must have no other route to the data. Re-run with Claude Code's own file and shell tools turned off, so the gateway was the only route, the agent refused the export.

See [docs/CONTROLS.md](docs/CONTROLS.md) for how each control maps to the NIST AI RMF, the OWASP Top 10 for LLM Applications (2025), ISO/IEC 42001, and privacy principles.

---

## For engineers

### Quick start

Requires [uv](https://docs.astral.sh/uv/). uv installs the pinned Python version (3.12) automatically.

```bash
uv sync                                   # install dependencies
uv run python -m consent_gate.seed        # build data/larkspur.db (500 synthetic customers)
uv run pytest -q                          # run the test suite
uv run python -m consent_gate.audit verify  # check the audit log hash chain
```

Run the server over stdio, choosing the role with an environment variable:

```bash
CONSENT_GATE_ROLE=marketing_analyst uv run python -m consent_gate.server
```

| Environment variable | Required | Meaning |
|---|---|---|
| `CONSENT_GATE_ROLE` | yes | `support_agent`, `marketing_analyst`, or `fraud_investigator`. Anything else and the server refuses to start. |
| `CONSENT_GATE_DB` | no | Database path. Default `data/larkspur.db`. |
| `CONSENT_GATE_AUDIT_LOG` | no | Audit log path. Default `logs/audit.jsonl`. |

### Connect to Claude Code

Register one server per role. Replace the path with your checkout.

```bash
claude mcp add consent-gate-support   -e CONSENT_GATE_ROLE=support_agent      -- uv --directory /path/to/consent-gate run python -m consent_gate.server
claude mcp add consent-gate-marketing -e CONSENT_GATE_ROLE=marketing_analyst  -- uv --directory /path/to/consent-gate run python -m consent_gate.server
claude mcp add consent-gate-fraud     -e CONSENT_GATE_ROLE=fraud_investigator -- uv --directory /path/to/consent-gate run python -m consent_gate.server
```

To run a session that sees only one role, without registering anything, use the config files in `redteam/`:

```bash
claude --strict-mcp-config --mcp-config redteam/support.json
```

This is how the red team exercise in [docs/RED_TEAM.md](docs/RED_TEAM.md) is run.

### Connect to Claude Desktop

Add entries under `mcpServers` in `claude_desktop_config.json`. On macOS it is at `~/Library/Application Support/Claude/claude_desktop_config.json`. On Windows it is at `%APPDATA%\Claude\claude_desktop_config.json`.

```json
{
  "mcpServers": {
    "consent-gate-support": {
      "command": "uv",
      "args": ["--directory", "/path/to/consent-gate", "run", "python", "-m", "consent_gate.server"],
      "env": { "CONSENT_GATE_ROLE": "support_agent" }
    }
  }
}
```

Add `consent-gate-marketing` and `consent-gate-fraud` the same way, then fully quit and restart Claude Desktop.

### Tools

| Tool | Roles | Inputs | Returns |
|---|---|---|---|
| `whoami` | all | none | Role, allowed purposes and legal bases, visible tools, fields returned, record caps |
| `lookup_customer` | support, fraud | `customer_id`, `purpose` | One record, filtered and masked, or a denial |
| `search_customers` | marketing, fraud | `purpose`, `state?`, `segment?`, `name_contains?`, `limit` (cap 25) | Consented matches, an excluded-by-consent count (withheld for name searches and groups under 5), and a `truncated` flag |
| `get_marketing_audience` | marketing | `segment`, `state?`, `purpose` (must be `marketing`) | Up to 50 customers with consent granted and no sale/share opt-out, plus exclusion counts by reason (withheld for groups under 5) |
| `search_policy` | all | `question`, `k` (cap 5) | Cited sections of Larkspur's privacy, data classification, and AI use policies |

Customer-data tools return one envelope: `decision` (`allow`, `partial`, or `deny`), `reason`, `purpose`, `records`, `excluded_by_consent`, `truncated`, and `request_id`. The `request_id` matches the audit log line.

### Layout

```
config/          roles.yaml, purposes.yaml (policy as data, validated strictly at load)
policies/        fictional Larkspur policy documents for search_policy
src/consent_gate/
  policy.py      pure decision engine (no I/O, enforced by a test)
  redact.py      field masks and free-text scrubbing
  audit.py       hash-chained JSONL audit log and verify command
  tools.py       tool handlers: policy, data, redaction, audit (MCP-independent)
  server.py      MCP server: role-scoped registration, audit middleware
  db.py          read-only SQLite access
  policy_search.py  offline TF-IDF retrieval
  seed.py        reproducible synthetic data, including planted injection notes
  models.py, config.py
tests/           253 tests
docs/            ARCHITECTURE, THREAT_MODEL, CONTROLS, RED_TEAM
```

Start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the request flow and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what this does and does not protect against.

### Development

```bash
uv run ruff check . && uv run ruff format .
uv run pytest -q
```

The non-negotiable security invariants are listed in [CLAUDE.md](CLAUDE.md). Scope and acceptance criteria are in [SPEC.md](SPEC.md).
