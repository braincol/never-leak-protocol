"""NL Protocol Level 6 -- Automated response engine.

This module implements the four-tier automated response system defined in
Chapter 06, Section 5 of the NL Protocol specification.  It provides:

* **ResponseAction** -- immutable result describing the actions to take.
* **ResponseEngine** -- engine that determines the appropriate response
  based on a threat score.

Response levels (Section 5.1.1):

* **GREEN** (0-29): Log only.
* **YELLOW** (30-59): Enhanced logging, rate limiting (50%), admin notify.
* **ORANGE** (60-79): Block action, restrict scope, urgent admin alert.
* **RED** (80-100): Suspend agent, revoke AID, block all, critical alert,
  incident response workflow, revoke delegation tokens.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime

from nl_protocol.core.types import ThreatLevel
from nl_protocol.detection.threat_scoring import ThreatScore, threat_level_from_score

# ---------------------------------------------------------------------------
# Response actions
# ---------------------------------------------------------------------------

class ResponseActionType(enum.StrEnum):
    """Concrete actions that may appear in a ResponseAction."""

    LOG = "log"
    ENHANCED_LOGGING = "enhanced_logging"
    RATE_LIMIT = "rate_limit"
    NOTIFY_ADMIN = "notify_admin"
    BLOCK_ACTION = "block_action"
    RESTRICT_SCOPE = "restrict_scope"
    NOTIFY_ADMIN_URGENT = "notify_admin_urgent"
    REVOKE_AID = "revoke_aid"
    BLOCK_ALL_ACTIONS = "block_all_actions"
    CRITICAL_ALERT = "critical_alert"
    INCIDENT_RESPONSE = "incident_response"
    REVOKE_DELEGATION_TOKENS = "revoke_delegation_tokens"


@dataclass(frozen=True, slots=True)
class ResponseAction:
    """The result of a response determination.

    Attributes
    ----------
    level : ThreatLevel
        The threat level that triggered this response.
    actions : list[ResponseActionType]
        Ordered list of concrete actions to take.
    reason : str
        Human-readable description of why this response was triggered.
    threat_score : int
        The agent's threat score at the time of the response.
    timestamp : datetime
        UTC timestamp of when this response was determined.
    rate_limit_factor : float | None
        If rate limiting is applied, the factor to apply (e.g. 0.5 = 50%).
    """

    level: ThreatLevel
    actions: list[ResponseActionType]
    reason: str
    threat_score: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    rate_limit_factor: float | None = None


# ---------------------------------------------------------------------------
# Response engine
# ---------------------------------------------------------------------------

# Pre-defined response templates per threat level (Section 5.1.1)
_GREEN_ACTIONS: list[ResponseActionType] = [
    ResponseActionType.LOG,
]

_YELLOW_ACTIONS: list[ResponseActionType] = [
    ResponseActionType.LOG,
    ResponseActionType.ENHANCED_LOGGING,
    ResponseActionType.RATE_LIMIT,
    ResponseActionType.NOTIFY_ADMIN,
]

_ORANGE_ACTIONS: list[ResponseActionType] = [
    ResponseActionType.LOG,
    ResponseActionType.BLOCK_ACTION,
    ResponseActionType.RESTRICT_SCOPE,
    ResponseActionType.NOTIFY_ADMIN_URGENT,
]

_RED_ACTIONS: list[ResponseActionType] = [
    ResponseActionType.LOG,
    ResponseActionType.REVOKE_AID,
    ResponseActionType.BLOCK_ALL_ACTIONS,
    ResponseActionType.CRITICAL_ALERT,
    ResponseActionType.INCIDENT_RESPONSE,
    ResponseActionType.REVOKE_DELEGATION_TOKENS,
]

_RESPONSE_REASONS: dict[ThreatLevel, str] = {
    ThreatLevel.GREEN: (
        "Normal behaviour. Incident logged; no further action."
    ),
    ThreatLevel.YELLOW: (
        "Elevated threat. Enhanced monitoring applied, rate limit reduced "
        "by 50%, administrator notified."
    ),
    ThreatLevel.ORANGE: (
        "High threat. Triggering action blocked, agent scope restricted "
        "to safe subset, urgent administrator notification sent."
    ),
    ThreatLevel.RED: (
        "Critical threat. Agent suspended immediately, AID revoked, "
        "all actions blocked, critical alert sent to on-call team, "
        "incident response workflow triggered, delegation tokens revoked."
    ),
}


class ResponseEngine:
    """Determine automated response actions based on threat scores.

    The engine maps threat levels to pre-defined response action sets
    as specified in Section 5.1.1.

    Parameters
    ----------
    rate_limit_factor : float
        Rate-limit reduction factor for YELLOW responses.
        Spec recommends 0.5 (50% reduction).
    """

    __slots__ = ("_rate_limit_factor",)

    def __init__(self, *, rate_limit_factor: float = 0.5) -> None:
        self._rate_limit_factor = rate_limit_factor

    def determine_response(self, threat_score: ThreatScore) -> ResponseAction:
        """Determine the response action for the given *threat_score*.

        Parameters
        ----------
        threat_score : ThreatScore
            The agent's current computed threat score.

        Returns
        -------
        ResponseAction
            The response to execute.
        """
        level = threat_level_from_score(threat_score.int_score)
        return self._build_response(level, threat_score.int_score)

    def determine_response_for_score(self, int_score: int) -> ResponseAction:
        """Convenience: determine response directly from an integer score.

        Parameters
        ----------
        int_score : int
            Agent threat score (0-100).

        Returns
        -------
        ResponseAction
            The response to execute.
        """
        level = threat_level_from_score(int_score)
        return self._build_response(level, int_score)

    def _build_response(self, level: ThreatLevel, int_score: int) -> ResponseAction:
        """Build a ResponseAction for the given level and score."""
        if level == ThreatLevel.GREEN:
            actions = list(_GREEN_ACTIONS)
        elif level == ThreatLevel.YELLOW:
            actions = list(_YELLOW_ACTIONS)
        elif level == ThreatLevel.ORANGE:
            actions = list(_ORANGE_ACTIONS)
        else:
            actions = list(_RED_ACTIONS)

        rate_factor = (
            self._rate_limit_factor if level == ThreatLevel.YELLOW else None
        )

        return ResponseAction(
            level=level,
            actions=actions,
            reason=_RESPONSE_REASONS[level],
            threat_score=int_score,
            rate_limit_factor=rate_factor,
        )
