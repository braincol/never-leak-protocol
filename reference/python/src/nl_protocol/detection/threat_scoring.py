"""NL Protocol Level 6 -- Threat score calculation.

This module implements the threat scoring system defined in Chapter 06,
Sections 2 and 3 of the NL Protocol specification.  It provides:

* **AttackType** -- enum of the 11 canonical attack types (T1-T11).
* **ThreatScore** -- immutable result of a scoring evaluation.
* **Incident** -- a single recorded attack incident used for scoring.
* **ThreatScorer** -- the scoring engine that computes per-agent threat
  scores using the weighted formula from Section 3.3.
"""
from __future__ import annotations

import enum
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from nl_protocol.core.types import ThreatLevel

# ---------------------------------------------------------------------------
# Attack type taxonomy (Section 2)
# ---------------------------------------------------------------------------

_ATTACK_CATEGORIES: dict[str, str] = {
    "T1": "direct_exfiltration",
    "T2": "direct_exfiltration",
    "T3": "evasion",
    "T4": "evasion",
    "T5": "evasion",
    "T6": "manipulation",
    "T7": "manipulation",
    "T8": "output_exfiltration",
    "T9": "output_exfiltration",
    "T10": "infrastructure",
    "T11": "infrastructure",
}


class AttackType(enum.Enum):
    """Canonical NL Protocol attack types (Section 2).

    Each member carries its identifier string and base severity score as
    defined in the specification.
    """

    T1 = ("T1", 20, "Direct Secret Request")
    T2 = ("T2", 30, "Bulk Export")
    T3 = ("T3", 40, "Encoding Bypass")
    T4 = ("T4", 35, "Indirect Execution")
    T5 = ("T5", 40, "Shell Expansion")
    T6 = ("T6", 50, "Prompt Injection")
    T7 = ("T7", 45, "Social Engineering")
    T8 = ("T8", 60, "Secret in Output")
    T9 = ("T9", 80, "Network Exfiltration")
    T10 = ("T10", 50, "File System Access")
    T11 = ("T11", 70, "Memory Inspection")

    def __init__(self, identifier: str, severity: int, description: str) -> None:
        self.identifier = identifier
        self.severity = severity
        self.description = description

    @property
    def base_severity(self) -> float:
        """Return the base severity normalised to 0.0 -- 1.0 (Section 3.3)."""
        return self.severity / 100.0

    @property
    def category(self) -> str:
        """Return the attack category string for this type."""
        return _ATTACK_CATEGORIES[self.identifier]


# ---------------------------------------------------------------------------
# Threat-level mapping per Chapter 06, Section 3.2
# ---------------------------------------------------------------------------

def threat_level_from_score(score: int) -> ThreatLevel:
    """Map an integer threat score (0-100) to a ThreatLevel.

    Uses the ranges defined in Chapter 06, Section 3.2:

    * GREEN:  0 -- 29
    * YELLOW: 30 -- 59
    * ORANGE: 60 -- 79
    * RED:    80 -- 100
    """
    if score < 30:
        return ThreatLevel.GREEN
    if score < 60:
        return ThreatLevel.YELLOW
    if score < 80:
        return ThreatLevel.ORANGE
    return ThreatLevel.RED


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ThreatScore:
    """The result of a threat-score evaluation for an agent.

    Attributes
    ----------
    score : float
        Cumulative score in the range 0.0 -- 1.0 (pre-projection).
    int_score : int
        Projected integer score in the range 0 -- 100.
    level : ThreatLevel
        Discrete threat level derived from *int_score*.
    factors : list[dict[str, Any]]
        Per-incident contribution breakdown for auditability.
    timestamp : datetime
        UTC timestamp of when this score was computed.
    """

    score: float
    int_score: int
    level: ThreatLevel
    factors: list[dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class Incident:
    """A single recorded attack incident (Section 3.3).

    Attributes
    ----------
    attack_type : AttackType
        Which of the T1-T11 attack types this incident represents.
    timestamp : datetime
        UTC timestamp of when the incident occurred.
    agent_uri : str
        The agent that triggered this incident.
    evidence : dict[str, Any]
        Free-form evidence data (command, pattern matched, etc.).
    """

    attack_type: AttackType
    timestamp: datetime
    agent_uri: str
    evidence: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

_DEFAULT_LAMBDA = 0.05  # Recency decay constant (Section 3.3)
_DEFAULT_WINDOW_HOURS = 24.0  # Frequency counting window (Section 3.3)
_DEFAULT_PROJECTION = 100  # Projection factor (Section 3.3)


class ThreatScorer:
    """Compute per-agent threat scores using the spec formula (Section 3.3).

    Parameters
    ----------
    decay_lambda : float
        Exponential recency decay constant (default 0.05).
    window_hours : float
        Sliding window in hours for frequency counting (default 24).
    projection_factor : int
        Multiplier that projects the raw sum onto 0-100 (default 100).
    """

    __slots__ = ("_incidents", "_decay_lambda", "_window_hours", "_projection")

    def __init__(
        self,
        *,
        decay_lambda: float = _DEFAULT_LAMBDA,
        window_hours: float = _DEFAULT_WINDOW_HOURS,
        projection_factor: int = _DEFAULT_PROJECTION,
    ) -> None:
        self._incidents: dict[str, list[Incident]] = {}
        self._decay_lambda = decay_lambda
        self._window_hours = window_hours
        self._projection = projection_factor

    # -- Incident management ------------------------------------------------

    def record_incident(self, incident: Incident) -> ThreatScore:
        """Record an incident and return the agent's updated threat score."""
        agent = incident.agent_uri
        self._incidents.setdefault(agent, []).append(incident)
        return self.compute_score(agent)

    def get_incidents(self, agent_uri: str) -> list[Incident]:
        """Return all recorded incidents for *agent_uri*."""
        return list(self._incidents.get(agent_uri, []))

    def clear_incidents(self, agent_uri: str) -> None:
        """Clear all incidents for *agent_uri* (score reset per Section 3.6)."""
        self._incidents.pop(agent_uri, None)

    # -- Score computation --------------------------------------------------

    def compute_score(
        self,
        agent_uri: str,
        *,
        at_time: datetime | None = None,
    ) -> ThreatScore:
        """Compute the threat score for *agent_uri* at *at_time*.

        Implements the formula from Section 3.3::

            ThreatScore = min(100, ROUND(SUM(BaseSeverity * Recency * Frequency)))

        Parameters
        ----------
        agent_uri : str
            The agent to score.
        at_time : datetime | None
            Point-in-time for the calculation.  Defaults to ``utcnow()``.

        Returns
        -------
        ThreatScore
            The computed score with full factor breakdown.
        """
        now = at_time or datetime.now(UTC)
        incidents = self._incidents.get(agent_uri, [])

        if not incidents:
            return ThreatScore(
                score=0.0,
                int_score=0,
                level=ThreatLevel.GREEN,
                factors=[],
                timestamp=now,
            )

        # Count occurrences of each attack type within the sliding window
        window_start = now.timestamp() - (self._window_hours * 3600)
        type_counts: dict[AttackType, int] = {}
        for inc in incidents:
            if inc.timestamp.timestamp() >= window_start:
                type_counts[inc.attack_type] = type_counts.get(inc.attack_type, 0) + 1

        raw_sum = 0.0
        factors: list[dict[str, Any]] = []

        for inc in incidents:
            hours_since = max(
                0.0,
                (now.timestamp() - inc.timestamp.timestamp()) / 3600.0,
            )
            recency = math.exp(-self._decay_lambda * hours_since)

            count = type_counts.get(inc.attack_type, 1)
            frequency = 1.0 + round(math.log2(max(count, 1)), 2)

            contribution = inc.attack_type.base_severity * recency * frequency

            factors.append({
                "attack_type": inc.attack_type.identifier,
                "base_severity": inc.attack_type.base_severity,
                "hours_since": round(hours_since, 4),
                "recency": round(recency, 6),
                "frequency_count": count,
                "frequency_multiplier": round(frequency, 2),
                "contribution": round(contribution, 6),
            })

            raw_sum += contribution

        projected = raw_sum * self._projection
        int_score = min(100, round(projected))

        return ThreatScore(
            score=round(raw_sum, 6),
            int_score=int_score,
            level=threat_level_from_score(int_score),
            factors=factors,
            timestamp=now,
        )
