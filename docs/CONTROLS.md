# Control Mapping

This maps each consent-gate control to recognized frameworks, and points to the test that shows it works. It is written so an engineer, a privacy officer, and an auditor can each find what they need.

## Frameworks referenced

- **NIST AI Risk Management Framework (AI RMF 1.0)**: the four core functions, Govern, Map, Measure, and Manage. This document cites functions only, not subcategory identifiers.
- **OWASP Top 10 for LLM Applications (2025)**: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency, LLM10 Unbounded Consumption.
- **ISO/IEC 42001:2023** (AI management systems): cited by topic area only. Annex A control numbers are deliberately not cited. <!-- VERIFY: topic names below are paraphrases of the standard's areas; confirm wording against the published text before external use. -->
- **Privacy principles**: purpose limitation, lawful basis, data minimization, integrity and confidentiality, and accountability, as commonly stated in privacy law. The do-not-sell/share opt-out refers to the CCPA as amended by the CPRA.

## Controls

| Control | How it works here | NIST AI RMF | OWASP LLM (2025) | ISO/IEC 42001 topic | Privacy principle | Evidence |
|---|---|---|---|---|---|---|
| Purpose validation | Every customer-data call must declare a purpose the role allows. Unknown purposes are denied. | Govern, Manage | LLM02, LLM06 | Use of AI systems; AI policy | Purpose limitation | `test_policy.py` cases 4, 6 |
| Consent check per record | Consent-based purposes need a single `granted` record for that customer and purpose. Missing or conflicting records mean deny. | Govern, Manage | LLM02 | Data for AI systems | Lawful basis, purpose limitation | `test_policy.py` cases 2, 7; `test_tools.py::test_search_analytics_returns_only_granted` |
| Sale/share opt-out | Marketing excludes customers who opted out, even if marketing consent is granted. | Manage | LLM02 | Data for AI systems | Lawful basis (CCPA/CPRA opt-out) | `test_policy.py` case 8; `test_tools.py::test_audience_matches_consent_and_opt_out` |
| Legal basis made visible | `purposes.yaml` records the basis for each purpose. `whoami` and allow decisions report it. | Govern, Map | n/a | AI system impact assessment <!-- VERIFY --> | Lawful basis, transparency | `test_policy.py` case 1 |
| Role fixed by configuration | The role comes from an environment variable at startup. No tool accepts a role. Extra arguments are discarded. | Govern | LLM06 | Roles and responsibilities; AI system operation <!-- VERIFY --> | Accountability | `test_tools.py::test_client_role_argument_is_ignored`, `test_main_refuses_to_start_without_valid_role` |
| Role-scoped tools | Only the role's tools are registered, and each handler re-checks policy. | Manage | LLM06 | Use of AI systems | Data minimization | `test_tools.py::test_only_role_tools_are_registered`, `test_handler_guards_tools_not_permitted_for_role` |
| Field allowlists | Each role receives an explicit list of fields. There is no wildcard, and unknown fields are rejected at config load. | Manage | LLM02 | Data for AI systems | Data minimization | `test_policy.py` case 11; `test_redact.py` record shape tests |
| Default deny | Unknown role, tool, purpose, or field, or a missing consent record, means deny. | Govern | LLM06 | AI risk treatment <!-- VERIFY --> | Privacy by design | `test_policy.py` default-deny tests |
| Masking of Restricted fields | SSN and card are shown as last 4 only. Config cannot be set to show them in full. | Manage | LLM02 | Data for AI systems | Integrity and confidentiality | `test_policy.py` case 10; `test_redact.py` mask tests |
| Free-text scrubbing | Every outgoing string is scanned for SSN patterns and Luhn-valid card numbers, which are replaced with labels. | Manage | LLM02 | Data for AI systems | Integrity and confidentiality | `test_redact.py`; `test_injection.py::test_no_ssn_or_card_from_notes_survives` |
| Untrusted content labeling | Notes are returned only inside `untrusted_notes` with a warning. | Manage | LLM01 | Use of AI systems | Integrity | `test_injection.py::test_poisoned_notes_only_appear_inside_untrusted_wrapper` |
| Decisions independent of content | The policy engine never reads free text. Tested by comparing a clean and a poisoned database. | Measure | LLM01 | AI system verification and validation <!-- VERIFY --> | Integrity | `test_injection.py::test_invariant_12_*`; `test_policy.py` case 12 |
| Pure policy engine | `policy.py` has no I/O, enforced by a test, so every decision is reproducible. | Measure | LLM06 | AI system verification and validation <!-- VERIFY --> | Accountability | `test_policy.py::test_policy_module_is_pure` |
| Record caps, no export tool | Hard caps in code: 25 per search, 50 per audience, 5 per policy search. No export or write tool. | Manage | LLM06, LLM10 | Use of AI systems | Data minimization | `test_policy.py` case 9; `test_tools.py::test_search_limit_above_cap_is_clamped` |
| Non-disclosure of exclusions | Searches count exclusions but never list them. Name searches and groups of fewer than 5 withhold the count. Missing and excluded customers get the same message. | Manage | LLM02 | Data for AI systems | Data minimization | `test_tools.py::test_name_search_does_not_reveal_one_persons_consent`, `test_small_groups_do_not_reveal_consent`, `test_lookup_unknown_customer_does_not_reveal_existence` |
| Read-only data access | SQLite opened with `mode=ro` and `query_only`. Parameterized queries only. | Manage | LLM06 | AI system operation <!-- VERIFY --> | Integrity | `test_injection.py::test_injected_name_filters_match_nothing` |
| Complete audit trail | One record per call: allowed, partial, or denied. Calls rejected before a handler runs are audited by middleware. | Govern, Measure | LLM06 | Event logging; monitoring <!-- VERIFY --> | Accountability | `test_tools.py::test_every_handler_call_writes_one_linked_audit_record`, `test_client_unknown_tool_is_audited` |
| Tamper-evident audit | Hash chain with a `verify` command. Appends check the previous hash. | Govern, Measure | n/a | Event logging <!-- VERIFY --> | Accountability | `test_audit.py` tamper tests |
| Fail closed on audit failure | If the audit write fails, the call fails and returns no data. | Govern, Manage | n/a | Event logging <!-- VERIFY --> | Accountability | `test_tools.py::test_audit_failure_returns_no_data`, `test_client_audit_failure_is_an_error_with_no_data` |
| Audit hygiene | Arguments are scrubbed and capped before logging. Note text never enters the log. | Manage | LLM02 | Event logging <!-- VERIFY --> | Data minimization | `test_audit.py::test_args_are_scrubbed_and_capped`; `test_injection.py::test_note_text_never_reaches_the_audit_log` |
| Policy search with citations | Agents can look up Larkspur policy and cite the source section before acting. | Govern | n/a | Information for interested parties <!-- VERIFY --> | Transparency | `test_policy_search.py` sample questions |
| Red team exercise | Adversarial prompts run against a live agent, with results tied to audit request IDs. | Measure | LLM01, LLM02, LLM06 | AI system verification and validation <!-- VERIFY --> | Accountability | `docs/RED_TEAM.md` |

## Known gaps

These are tracked as residual risks in [THREAT_MODEL.md](THREAT_MODEL.md):

- No rate limits or per-session quotas, so enumeration through many small calls is visible in the audit log but not prevented (T7).
- Exclusion counts are withheld for name searches and small groups, but comparing two large overlapping queries could still isolate one person (T8).
- The role comes from an environment variable, not authenticated identity (T9).
- A whole-file rewrite of the audit log can recompute every hash (T10).
