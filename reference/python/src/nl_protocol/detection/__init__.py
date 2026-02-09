"""NL Protocol Level 6 -- Attack Detection & Response.

This subpackage implements the attack detection layer as defined in the
NL Protocol Specification v1.0, Chapter 06.  It provides:

* **AttackType** -- enum of the 11 canonical attack types (T1-T11).
* **ThreatScore** -- immutable scoring result with level and factors.
* **Incident** -- a single recorded attack incident.
* **ThreatScorer** -- per-agent threat scoring engine (Section 3).
* **BehavioralBaseline** -- EWMA-based metric baseline tracker (Section 4.4).
* **AgentProfile** -- per-agent behavioral profile.
* **ResponseAction** -- automated response result.
* **ResponseActionType** -- enum of concrete response action types.
* **ResponseEngine** -- four-tier automated response engine (Section 5).
* **HoneypotEntry** -- honeypot token metadata.
* **HoneypotManager** -- honeypot creation and access scoring (Section 4.5).
* **threat_level_from_score** -- score-to-level mapping per Section 3.2.
"""
from __future__ import annotations

from nl_protocol.detection.behavioral import AgentProfile, BehavioralBaseline
from nl_protocol.detection.honeypot import HoneypotEntry, HoneypotManager
from nl_protocol.detection.response import ResponseAction, ResponseActionType, ResponseEngine
from nl_protocol.detection.threat_scoring import (
    AttackType,
    Incident,
    ThreatScore,
    ThreatScorer,
    threat_level_from_score,
)

__all__ = [
    "AttackType",
    "ThreatScore",
    "Incident",
    "ThreatScorer",
    "threat_level_from_score",
    "BehavioralBaseline",
    "AgentProfile",
    "ResponseAction",
    "ResponseActionType",
    "ResponseEngine",
    "HoneypotEntry",
    "HoneypotManager",
]
