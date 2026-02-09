"""NL Protocol provider configuration.

Defines the validated configuration model consumed by all NL Protocol
subsystems.  Values align with the defaults and limits specified across
Chapters 01-08 of the specification.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class NLProviderConfig(BaseModel):
    """Configuration for an NL Protocol provider.

    Every subsystem (identity, access, isolation, defense, audit,
    detection, federation, wire) reads from a shared instance of this
    model.  All fields carry sensible defaults drawn from the
    specification so that a minimal configuration (just ``provider_id``)
    is sufficient for development.
    """

    model_config = ConfigDict(strict=True)

    provider_id: str = Field(
        description="Unique identifier for this NL Provider instance.",
    )
    supported_levels: list[int] = Field(
        default=[1, 2, 3, 4, 5, 6, 7],
        description=(
            "NL Protocol levels (1-7) implemented by this provider."
        ),
    )
    max_delegation_depth: int = Field(
        default=3,
        ge=0,
        description="Maximum allowed re-delegation depth (Chapter 07).",
    )
    default_action_timeout: int = Field(
        default=30,
        ge=1,
        le=600,
        description="Default action timeout in seconds.",
    )
    max_output_size: int = Field(
        default=10 * 1024 * 1024,  # 10 MiB
        ge=0,
        description="Maximum allowed output size in bytes.",
    )
    sanitization_timeout_ms: int = Field(
        default=500,
        ge=0,
        description=(
            "Maximum time in milliseconds for output sanitisation "
            "before the result is withheld."
        ),
    )
    threat_score_decay_per_hour: float = Field(
        default=1.0,
        ge=0.0,
        description=(
            "Points per hour subtracted from an agent's cumulative "
            "threat score (Chapter 06)."
        ),
    )
    hmac_key_id: str = Field(
        default="default",
        description="Identifier for the HMAC key used in audit records.",
    )
    clock_drift_tolerance_seconds: int = Field(
        default=30,
        ge=0,
        description=(
            "Allowable clock drift in seconds for timestamp validation."
        ),
    )
    audit_fail_closed: bool = Field(
        default=True,
        description=(
            "When True, actions are blocked if the audit subsystem "
            "is unavailable (fail-closed behaviour)."
        ),
    )
    max_message_size_bytes: int = Field(
        default=1_048_576,  # 1 MiB
        ge=0,
        description="Maximum accepted wire-protocol message size in bytes.",
    )
    idempotency_window_seconds: int = Field(
        default=300,
        ge=0,
        description=(
            "Duration in seconds for which message-id idempotency is "
            "enforced (Chapter 08, Section 3.5)."
        ),
    )
    timestamp_tolerance_seconds: int = Field(
        default=300,
        ge=0,
        description=(
            "Maximum allowed deviation between message timestamp and "
            "server time in seconds (Chapter 08, Section 3.6)."
        ),
    )
    rate_limit_requests_per_minute: int = Field(
        default=120,
        ge=0,
        description="Default per-agent rate limit.",
    )
