"""NL Protocol shared domain types.

This module defines every value type, enum, and Pydantic model that is shared
across the NL Protocol implementation.  All public symbols are re-exported
from ``nl_protocol.core``.

Key design decisions:
* ``SecretValue`` is a plain Python class (not Pydantic) that prevents
  accidental serialisation of secret material via ``str()`` or ``repr()``.
* ``AgentURI`` and ``SecretRef`` are ``NewType`` wrappers around ``str`` for
  static type-safety while remaining JSON-serialisable.
* All Pydantic models use **v2** ``model_config`` and ``from __future__
  import annotations`` for forward-reference support.
* Enums use *string* values so they serialise cleanly to JSON.
"""
from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Any, Literal, NewType

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Value types (NewType wrappers)
# ---------------------------------------------------------------------------

AgentURI = NewType("AgentURI", str)
"""Agent identifier in the form ``nl://vendor/agent-type/version``."""

SecretRef = NewType("SecretRef", str)
"""Secret reference in the form ``category/name`` or just ``name``."""


# ---------------------------------------------------------------------------
# SecretValue -- opaque wrapper that prevents accidental exposure
# ---------------------------------------------------------------------------

class SecretValue:
    """A secret value that prevents accidental exposure.

    The underlying plaintext is *only* accessible via the explicit
    :meth:`expose` method.  ``str()``, ``repr()``, ``format()`` and
    ``logging`` all return a redacted placeholder.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def expose(self) -> str:
        """Explicitly reveal the secret value.  Use with caution."""
        return self._value

    def __str__(self) -> str:
        return "[NL-REDACTED]"

    def __repr__(self) -> str:
        return "SecretValue([NL-REDACTED])"

    def __format__(self, format_spec: str) -> str:
        return "[NL-REDACTED]"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretValue):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TrustLevel(enum.StrEnum):
    """Trust-level tiers for agent identity assurance.

    * **L0** -- self-attested (no external verification)
    * **L1** -- organisation-verified
    * **L2** -- vendor-attested (signed JWT from platform provider)
    * **L3** -- third-party-certified
    """

    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"

    @property
    def numeric(self) -> int:
        """Return the integer trust level (0-3)."""
        return int(self.value[1])

    def __ge__(self, other: object) -> bool:
        if isinstance(other, TrustLevel):
            return self.numeric >= other.numeric
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, TrustLevel):
            return self.numeric > other.numeric
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, TrustLevel):
            return self.numeric <= other.numeric
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, TrustLevel):
            return self.numeric < other.numeric
        return NotImplemented


class LifecycleState(enum.StrEnum):
    """Agent lifecycle states.

    Transitions: PENDING -> ACTIVE <-> SUSPENDED -> REVOKED (terminal).
    """

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class ActionType(enum.StrEnum):
    """Supported action types for action-based access.

    Each type defines a different execution semantic as specified in
    Chapter 02 of the NL Protocol specification.
    """

    EXEC = "exec"
    TEMPLATE = "template"
    READ = "read"
    HTTP = "http"
    INJECT_STDIN = "inject_stdin"
    INJECT_TEMPFILE = "inject_tempfile"
    SDK_PROXY = "sdk_proxy"
    DELEGATE = "delegate"


class ThreatLevel(enum.StrEnum):
    """Threat-level classification for attack-detection (Chapter 06).

    Each level corresponds to a range of cumulative threat scores.
    """

    GREEN = "green"
    YELLOW = "yellow"
    ORANGE = "orange"
    RED = "red"

    @classmethod
    def from_score(cls, score: float) -> ThreatLevel:
        """Determine the threat level from a cumulative threat score.

        Score ranges (per Chapter 06):
        * GREEN:  0 -- 29
        * YELLOW: 30 -- 59
        * ORANGE: 60 -- 89
        * RED:    90+
        """
        if score < 30:
            return cls.GREEN
        if score < 60:
            return cls.YELLOW
        if score < 90:
            return cls.ORANGE
        return cls.RED

    @property
    def min_score(self) -> int:
        """Return the minimum cumulative score for this threat level."""
        return {
            ThreatLevel.GREEN: 0,
            ThreatLevel.YELLOW: 30,
            ThreatLevel.ORANGE: 60,
            ThreatLevel.RED: 90,
        }[self]

    @property
    def max_score(self) -> int | None:
        """Return the exclusive upper bound, or ``None`` for RED (unbounded)."""
        return {
            ThreatLevel.GREEN: 30,
            ThreatLevel.YELLOW: 60,
            ThreatLevel.ORANGE: 90,
            ThreatLevel.RED: None,
        }[self]


# ---------------------------------------------------------------------------
# Pydantic helper -- UTC-aware datetime default
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return the current UTC datetime with timezone information."""
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ScopeConditions(BaseModel):
    """Conditions attached to a :class:`ScopeGrant`.

    All condition fields are optional; omitting them means the condition
    is not enforced.
    """

    model_config = ConfigDict(strict=True)

    valid_from: datetime | None = None
    valid_until: datetime | None = None
    max_uses: int | None = None
    current_uses: int = 0
    ip_whitelist: list[str] = Field(default_factory=list)


class AID(BaseModel):
    """Agent Identity Document (AID).

    The AID is the canonical representation of an agent's identity, as
    defined in Chapter 01 of the NL Protocol specification.
    """

    model_config = ConfigDict(strict=True)

    agent_uri: AgentURI
    display_name: str
    vendor: str
    version: str
    scope: list[str] = Field(
        default_factory=list,
        description="Glob patterns of secrets this agent MAY access.",
    )
    trust_level: TrustLevel = TrustLevel.L0
    capabilities: list[ActionType] = Field(default_factory=list)
    public_key: str | None = Field(
        default=None,
        description="PEM-encoded public key for signature verification.",
    )
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScopeGrant(BaseModel):
    """A discrete authorisation granting an agent access to secrets.

    Scope grants are the Level 2 mechanism for binding agent identities
    to permitted actions and secret patterns.
    """

    model_config = ConfigDict(strict=True)

    grant_id: str = Field(description="UUID v4 identifying this grant.")
    agent_uri: AgentURI
    secret: str = Field(description="Secret pattern (supports glob syntax).")
    actions: list[ActionType]
    conditions: ScopeConditions = Field(default_factory=ScopeConditions)
    created_at: datetime = Field(default_factory=_utcnow)
    revoked: bool = False


class ActionPayload(BaseModel):
    """The payload portion of an :class:`ActionRequest`.

    Contains the action type, template with ``{{nl:...}}`` placeholders,
    and execution parameters.
    """

    model_config = ConfigDict(strict=True)

    type: ActionType
    template: str = Field(
        description="Command template with {{nl:...}} opaque-handle placeholders.",
    )
    purpose: str = Field(
        description="Human-readable purpose recorded in the audit trail.",
    )
    timeout: int = Field(
        default=30,
        ge=1,
        le=600,
        description="Maximum execution time in seconds.",
    )


class ActionRequest(BaseModel):
    """An action request submitted by an agent.

    The agent sends this message to the NL-compliant system, which
    resolves opaque handles, executes the action in isolation, and
    returns an :class:`ActionResponse`.
    """

    model_config = ConfigDict(strict=True, populate_by_name=True)

    version: str = "1.0"
    type: Literal["action_request"] = "action_request"
    agent_id: AgentURI = Field(alias="agent_uri")
    action: ActionPayload
    scope: dict[str, str] = Field(
        default_factory=dict,
        description="Contextual metadata (project, environment, etc.).",
    )
    delegation_token_id: str | None = None


class ActionResult(BaseModel):
    """The result of a successfully executed action."""

    model_config = ConfigDict(strict=True)

    exit_code: int
    stdout: str = ""
    stderr: str = ""


class ActionError(BaseModel):
    """Structured error returned inside an :class:`ActionResponse`."""

    model_config = ConfigDict(strict=True)

    code: str = Field(description="NL Protocol error code (NL-EXXX).")
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ActionResponse(BaseModel):
    """Response to an :class:`ActionRequest`.

    Exactly one of ``result`` or ``error`` will be populated, depending
    on the ``status``.
    """

    model_config = ConfigDict(strict=True)

    version: str = "1.0"
    type: Literal["action_response"] = "action_response"
    status: Literal["success", "error", "denied"]
    result: ActionResult | None = None
    error: ActionError | None = None
    audit_ref: str | None = None


class DelegationScope(BaseModel):
    """Scope constraints for a :class:`DelegationToken`."""

    model_config = ConfigDict(strict=True)

    secrets: list[str] = Field(
        default_factory=list,
        description="Secret patterns the delegate may access.",
    )
    actions: list[ActionType] = Field(default_factory=list)
    conditions: ScopeConditions | None = None


class DelegationToken(BaseModel):
    """A scoped, time-limited token for agent-to-agent delegation.

    Delegation tokens allow an orchestrator agent to grant a narrow
    subset of its own permissions to a sub-agent without exposing
    secrets (Chapter 07).
    """

    model_config = ConfigDict(strict=True)

    token_id: str = Field(description="UUID v4 identifying this token.")
    issuer: AgentURI
    subject: AgentURI
    scope: DelegationScope
    issued_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime
    max_delegation_depth: int = Field(
        default=3,
        ge=0,
        description="Maximum allowed re-delegation depth.",
    )
    current_depth: int = Field(
        default=0,
        ge=0,
        description="Current position in the delegation chain.",
    )
    signature: str | None = None


class AuditRecord(BaseModel):
    """An immutable, hash-chained audit record (Chapter 05).

    Audit records form a tamper-evident chain: each record includes the
    hash of the previous record, and optionally an HMAC signature for
    provider-level integrity.

    **CRITICAL:** ``secrets_used`` contains secret *names*, NEVER values.
    """

    model_config = ConfigDict(strict=True)

    record_id: str = Field(description="UUID v4 identifying this record.")
    timestamp: datetime = Field(default_factory=_utcnow)
    agent_uri: AgentURI
    action_type: ActionType | str
    secrets_used: list[str] = Field(
        default_factory=list,
        description="Secret names (NEVER values) used in this action.",
    )
    result_summary: str = ""
    hash_algorithm: str = "sha256"
    previous_hash: str = Field(
        description="Hash of the preceding record in the chain.",
    )
    record_hash: str = Field(
        description="Hash of *this* record for chain integrity.",
    )
    hmac_signature: str | None = None
    hmac_key_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None
