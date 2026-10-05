"""The policy decision engine.

Pure functions only: inputs in, Decision out. No database, file, network, or
clock access, so every decision is reproducible and easy to test.

Checks run in a fixed order and the first failure wins (default deny):
  role known -> tool known -> tool permitted for role -> purpose present
  -> purpose known -> purpose permitted for role -> purpose valid for tool
  -> (per customer) consent granted -> not opted out of sale/share

Only customer_id and do_not_sell_or_share are read from a customer record.
Free-text fields such as notes are never consulted.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence

from consent_gate.models import (
    TOOL_RULES,
    ConsentRecord,
    Customer,
    Decision,
    DenyCode,
    FilterResult,
    LimitDecision,
    PolicyConfig,
)

__all__ = ["LimitDecision", "authorize_request", "clamp_limit", "decide", "filter_customers"]

_MAX_ECHO = 32


def _q(value: str) -> str:
    """Quote a caller-supplied value for a reason string, truncated so it cannot flood it."""
    if len(value) > _MAX_ECHO:
        value = value[:_MAX_ECHO] + "..."
    return f"'{value}'"


def authorize_request(cfg: PolicyConfig, role: str, tool: str, purpose: str | None) -> Decision:
    """Request-level check: may this role call this tool for this purpose?"""

    def deny(code: DenyCode, reason: str) -> Decision:
        return Decision(
            allowed=False, code=code, reason=reason, role=role, tool=tool, purpose=purpose
        )

    role_policy = cfg.roles.get(role)
    if role_policy is None:
        return deny(DenyCode.UNKNOWN_ROLE, f"Denied: unknown role {_q(role)}")

    rule = TOOL_RULES.get(tool)
    if rule is None:
        return deny(DenyCode.UNKNOWN_TOOL, f"Denied: unknown tool {_q(tool)}")
    if tool not in role_policy.tools:
        return deny(
            DenyCode.TOOL_NOT_PERMITTED,
            f"Denied: tool {_q(tool)} is not permitted for role {_q(role)}",
        )

    if not rule.customer_data:
        return Decision(
            allowed=True,
            reason=f"Allowed: tool {_q(tool)} does not access customer records",
            role=role,
            tool=tool,
            purpose=purpose,
        )

    if purpose is None:
        return deny(DenyCode.PURPOSE_REQUIRED, f"Denied: tool {_q(tool)} requires a purpose")
    purpose_policy = cfg.purposes.get(purpose)
    if purpose_policy is None:
        return deny(DenyCode.UNKNOWN_PURPOSE, f"Denied: unknown purpose {_q(purpose)}")
    if purpose not in role_policy.purposes:
        return deny(
            DenyCode.PURPOSE_NOT_PERMITTED,
            f"Denied: purpose {_q(purpose)} is not permitted for role {_q(role)}",
        )
    if rule.required_purpose is not None and purpose != rule.required_purpose:
        return deny(
            DenyCode.PURPOSE_NOT_VALID_FOR_TOOL,
            f"Denied: tool {_q(tool)} requires purpose {_q(rule.required_purpose)}",
        )

    return Decision(
        allowed=True,
        reason=f"Allowed: purpose {_q(purpose)} under legal basis {_q(purpose_policy.legal_basis)}",
        role=role,
        tool=tool,
        purpose=purpose,
        legal_basis=purpose_policy.legal_basis,
        fields=dict(role_policy.fields),
    )


def decide(
    cfg: PolicyConfig,
    role: str,
    tool: str,
    purpose: str | None,
    customer: Customer,
    consent_records: Sequence[ConsentRecord],
) -> Decision:
    """May this role, for this purpose, see this customer, and which fields?"""
    request = authorize_request(cfg, role, tool, purpose)
    cid = customer.customer_id
    if not request.allowed:
        return request.model_copy(update={"customer_id": cid})

    def deny(code: DenyCode, reason: str) -> Decision:
        return Decision(
            allowed=False,
            code=code,
            reason=reason,
            role=role,
            tool=tool,
            purpose=purpose,
            customer_id=cid,
        )

    if not TOOL_RULES[tool].customer_data or purpose is None:
        return deny(
            DenyCode.NOT_A_CUSTOMER_DATA_TOOL,
            f"Denied: tool {_q(tool)} does not access customer records",
        )

    purpose_policy = cfg.purposes[purpose]
    if purpose_policy.requires_consent:
        # Only records for this customer and this purpose count.
        statuses = {
            r.status for r in consent_records if r.customer_id == cid and r.purpose == purpose
        }
        if not statuses:
            return deny(DenyCode.CONSENT_MISSING, f"Excluded: no {purpose} consent record")
        if len(statuses) > 1:
            return deny(
                DenyCode.CONSENT_AMBIGUOUS, f"Excluded: conflicting {purpose} consent records"
            )
        (status,) = statuses
        if status != "granted":
            return deny(DenyCode.CONSENT_NOT_GRANTED, f"Excluded: {purpose} consent is '{status}'")

    if purpose_policy.honor_do_not_sell_or_share and customer.do_not_sell_or_share:
        return deny(DenyCode.DO_NOT_SELL_OR_SHARE, "Excluded: customer opted out of sale/share")

    return request.model_copy(update={"customer_id": cid})


def filter_customers(
    cfg: PolicyConfig,
    role: str,
    tool: str,
    purpose: str | None,
    candidates: Iterable[tuple[Customer, Sequence[ConsentRecord]]],
) -> FilterResult:
    """Apply decide() to many customers. Excluded customers are counted by reason, never listed."""
    request = authorize_request(cfg, role, tool, purpose)
    if not request.allowed:
        return FilterResult(request=request)

    allowed: list[Customer] = []
    excluded: Counter[DenyCode] = Counter()
    for customer, records in candidates:
        d = decide(cfg, role, tool, purpose, customer, records)
        if d.allowed:
            allowed.append(customer)
        elif d.code is not None:  # always set on a deny; enforced by Decision
            excluded[d.code] += 1
    return FilterResult(request=request, allowed=allowed, excluded_by_reason=dict(excluded))


def clamp_limit(tool: str, requested: int) -> LimitDecision:
    """Clamp a requested record count to the tool's hard cap."""
    rule = TOOL_RULES.get(tool)
    if rule is None or rule.max_limit is None:
        raise ValueError(f"tool {_q(tool)} does not take a limit")
    if requested < 1:
        raise ValueError("limit must be at least 1")
    return LimitDecision(
        effective=min(requested, rule.max_limit), clamped=requested > rule.max_limit
    )
