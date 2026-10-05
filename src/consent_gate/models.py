"""Pydantic models and fixed schema facts shared across consent-gate."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, computed_field, model_validator


class FieldTreatment(StrEnum):
    PLAIN = "plain"
    LAST4 = "last4"
    UNTRUSTED_TEXT = "untrusted_text"


class DenyCode(StrEnum):
    UNKNOWN_ROLE = "unknown_role"
    UNKNOWN_TOOL = "unknown_tool"
    TOOL_NOT_PERMITTED = "tool_not_permitted"
    NOT_A_CUSTOMER_DATA_TOOL = "not_a_customer_data_tool"
    PURPOSE_REQUIRED = "purpose_required"
    UNKNOWN_PURPOSE = "unknown_purpose"
    PURPOSE_NOT_PERMITTED = "purpose_not_permitted"
    PURPOSE_NOT_VALID_FOR_TOOL = "purpose_not_valid_for_tool"
    CONSENT_MISSING = "consent_missing"
    CONSENT_AMBIGUOUS = "consent_ambiguous"
    CONSENT_NOT_GRANTED = "consent_not_granted"
    DO_NOT_SELL_OR_SHARE = "do_not_sell_or_share"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ------------------------------------------------------------------ schema facts

# Every customer column, and the only treatments each may be configured with.
# ssn and card_number can never be configured as plain (SPEC section 9, case 10).
ALLOWED_TREATMENTS: MappingProxyType[str, frozenset[FieldTreatment]] = MappingProxyType(
    {
        "customer_id": frozenset({FieldTreatment.PLAIN}),
        "full_name": frozenset({FieldTreatment.PLAIN}),
        "email": frozenset({FieldTreatment.PLAIN}),
        "phone": frozenset({FieldTreatment.PLAIN}),
        "ssn": frozenset({FieldTreatment.LAST4}),
        "card_number": frozenset({FieldTreatment.LAST4}),
        "state": frozenset({FieldTreatment.PLAIN}),
        "segment": frozenset({FieldTreatment.PLAIN}),
        "do_not_sell_or_share": frozenset({FieldTreatment.PLAIN}),
        "notes": frozenset({FieldTreatment.UNTRUSTED_TEXT}),
        "created_at": frozenset({FieldTreatment.PLAIN}),
    }
)


class ToolRule(_Frozen):
    customer_data: bool
    max_limit: int | None = None
    required_purpose: str | None = None


# Hard server-side caps live in code, not config, so they cannot be loosened by
# editing YAML. A tool not listed here does not exist.
TOOL_RULES: MappingProxyType[str, ToolRule] = MappingProxyType(
    {
        "whoami": ToolRule(customer_data=False),
        "lookup_customer": ToolRule(customer_data=True),
        "search_customers": ToolRule(customer_data=True, max_limit=25),
        "get_marketing_audience": ToolRule(
            customer_data=True, max_limit=50, required_purpose="marketing"
        ),
        "search_policy": ToolRule(customer_data=False, max_limit=5),
    }
)


# ------------------------------------------------------------------ policy config


class PurposePolicy(_Frozen):
    legal_basis: str
    requires_consent: bool
    honor_do_not_sell_or_share: bool = False
    description: str = ""


class RolePolicy(_Frozen):
    purposes: tuple[str, ...]
    tools: tuple[str, ...]
    fields: dict[str, FieldTreatment]


class PolicyConfig(_Frozen):
    purposes: dict[str, PurposePolicy]
    roles: dict[str, RolePolicy]

    @model_validator(mode="after")
    def _check_references(self) -> PolicyConfig:
        for name, role in self.roles.items():
            for purpose in role.purposes:
                if purpose not in self.purposes:
                    raise ValueError(f"role '{name}': unknown purpose '{purpose}'")
            for tool in role.tools:
                if tool not in TOOL_RULES:
                    raise ValueError(f"role '{name}': unknown tool '{tool}'")
            for field, treatment in role.fields.items():
                allowed = ALLOWED_TREATMENTS.get(field)
                if allowed is None:
                    raise ValueError(f"role '{name}': unknown field '{field}'")
                if treatment not in allowed:
                    raise ValueError(
                        f"role '{name}': field '{field}' cannot be '{treatment}', "
                        f"allowed: {sorted(allowed)}"
                    )
        return self


# ------------------------------------------------------------------ data records


class Customer(_Frozen):
    customer_id: str
    full_name: str
    email: str
    phone: str
    ssn: str
    card_number: str
    state: str
    segment: str
    do_not_sell_or_share: bool
    notes: str | None
    created_at: str


class ConsentRecord(_Frozen):
    customer_id: str
    purpose: str
    status: Literal["granted", "denied", "not_collected"]
    source: str | None
    updated_at: str


# ------------------------------------------------------------------ decisions


class Decision(_Frozen):
    allowed: bool
    code: DenyCode | None = None
    reason: str
    role: str
    tool: str
    purpose: str | None
    customer_id: str | None = None
    legal_basis: str | None = None
    fields: dict[str, FieldTreatment] = {}

    @model_validator(mode="after")
    def _consistent(self) -> Decision:
        if self.allowed and self.code is not None:
            raise ValueError("an allow decision cannot carry a deny code")
        if not self.allowed and (self.code is None or self.fields):
            raise ValueError("a deny decision needs a code and must grant no fields")
        return self


# ------------------------------------------------------------------ audit


class AuditEvent(_Frozen):
    """What a tool call reports to the audit log."""

    request_id: str
    role: str
    tool: str
    purpose: str | None
    args: dict[str, Any]
    decision: Literal["allow", "partial", "deny"]
    reason: str
    record_ids_returned: list[str] = []
    excluded_count: int = 0
    fields_masked: list[str] = []
    scrub_replacements: int = 0


class AuditRecord(AuditEvent):
    """One line of logs/audit.jsonl."""

    ts: str
    prev_hash: str
    hash: str


# ------------------------------------------------------------------ tool responses


class CustomerResponse(BaseModel):
    """Envelope for every customer-data tool (SPEC.md section 8)."""

    decision: Literal["allow", "partial", "deny"]
    reason: str
    purpose: str | None
    records: list[dict[str, Any]] = []
    returned: int = 0
    # None means withheld (name searches), so the count cannot single out one person.
    excluded_by_consent: int | None = 0
    excluded_by_reason: dict[str, int] | None = None
    truncated: bool = False
    request_id: str


class PurposeInfo(BaseModel):
    name: str
    legal_basis: str
    requires_consent: bool
    description: str


class WhoAmIResponse(BaseModel):
    role: str
    allowed_purposes: list[PurposeInfo]
    visible_tools: list[str]
    fields_returned: dict[str, str]
    record_limits: dict[str, int]
    note: str
    request_id: str


class LimitDecision(_Frozen):
    effective: int
    clamped: bool


class FilterResult(_Frozen):
    request: Decision
    allowed: list[Customer] = []
    excluded_by_reason: dict[DenyCode, int] = {}

    @computed_field
    @property
    def excluded_count(self) -> int:
        return sum(self.excluded_by_reason.values())
