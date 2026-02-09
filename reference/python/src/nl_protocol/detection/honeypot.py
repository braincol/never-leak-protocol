"""NL Protocol Level 6 -- Honeypot (canary) token management.

This module implements the honeypot token system defined in Chapter 06,
Section 4.5 of the NL Protocol specification.  It provides:

* **HoneypotEntry** -- metadata for a registered honeypot token.
* **HoneypotManager** -- in-memory registry for creating, checking,
  and scoring honeypot access events.

Key invariant from the spec: any access to a honeypot token is, by
definition, unauthorized.  Honeypot access has a fixed severity of 80,
overriding the normal base severity of whatever attack type would
otherwise apply (Section 4.5.3).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from nl_protocol.core.types import SecretRef
from nl_protocol.detection.threat_scoring import (
    AttackType,
    Incident,
    ThreatScore,
    threat_level_from_score,
)

# ---------------------------------------------------------------------------
# Honeypot entry
# ---------------------------------------------------------------------------

_HONEYPOT_SEVERITY = 80  # Fixed severity per Section 4.5.3


@dataclass(slots=True)
class HoneypotEntry:
    """Metadata for a registered honeypot token.

    Attributes
    ----------
    honeypot_id : str
        Unique identifier for the honeypot (e.g. ``hp-2026-02-08-0042``).
    name : str
        The name under which the honeypot is stored (e.g. ``ADMIN_API_KEY``).
    secret_ref : SecretRef
        The NL Protocol secret reference for this honeypot.
    category : str
        Categorisation label (e.g. ``admin``, ``production``).
    created_at : datetime
        UTC timestamp of creation.
    access_log : list[dict[str, Any]]
        Log of all access attempts for forensic analysis.
    """

    honeypot_id: str
    name: str
    secret_ref: SecretRef
    category: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    access_log: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Honeypot manager
# ---------------------------------------------------------------------------

class HoneypotManager:
    """In-memory honeypot token registry.

    Manages creation, lookup, and access-event scoring for honeypot
    (canary) tokens as defined in Section 4.5.
    """

    __slots__ = ("_by_ref", "_by_id", "_counter")

    def __init__(self) -> None:
        self._by_ref: dict[str, HoneypotEntry] = {}
        self._by_id: dict[str, HoneypotEntry] = {}
        self._counter: int = 0

    def create_honeypot(
        self,
        name: str,
        category: str,
        *,
        honeypot_id: str | None = None,
    ) -> SecretRef:
        """Register a new honeypot token and return its :class:`SecretRef`.

        Parameters
        ----------
        name : str
            Secret name for the honeypot (e.g. ``ADMIN_API_KEY``).
        category : str
            Category label (e.g. ``admin``, ``production``).
        honeypot_id : str | None
            Optional explicit ID.  Auto-generated if omitted.

        Returns
        -------
        SecretRef
            The secret reference for the newly created honeypot.
        """
        self._counter += 1
        hp_id = honeypot_id or f"hp-{uuid.uuid4().hex[:12]}-{self._counter:04d}"
        ref = SecretRef(f"{category}/{name}")

        entry = HoneypotEntry(
            honeypot_id=hp_id,
            name=name,
            secret_ref=ref,
            category=category,
        )

        self._by_ref[str(ref)] = entry
        self._by_id[hp_id] = entry
        return ref

    def is_honeypot(self, ref: SecretRef) -> bool:
        """Return True if *ref* is a registered honeypot."""
        return str(ref) in self._by_ref

    def get_entry(self, ref: SecretRef) -> HoneypotEntry | None:
        """Return the HoneypotEntry for *ref*, or None if not a honeypot."""
        return self._by_ref.get(str(ref))

    def get_entry_by_id(self, honeypot_id: str) -> HoneypotEntry | None:
        """Return the HoneypotEntry by its honeypot_id."""
        return self._by_id.get(honeypot_id)

    @property
    def honeypot_count(self) -> int:
        """Return the total number of registered honeypots."""
        return len(self._by_ref)

    def list_honeypots(self) -> list[HoneypotEntry]:
        """Return all registered honeypot entries."""
        return list(self._by_ref.values())

    def on_access(self, ref: SecretRef, agent_uri: str) -> ThreatScore:
        """Score a honeypot access event.

        Any access to a honeypot is treated as a confirmed attack with
        fixed severity 80 (Section 4.5.3).  The resulting ThreatScore
        will always be >= 80 (RED level).

        Parameters
        ----------
        ref : SecretRef
            The honeypot's secret reference.
        agent_uri : str
            The agent that accessed the honeypot.

        Returns
        -------
        ThreatScore
            A threat score reflecting the honeypot access.

        Raises
        ------
        ValueError
            If *ref* is not a registered honeypot.
        """
        entry = self._by_ref.get(str(ref))
        if entry is None:
            msg = f"Not a registered honeypot: {ref}"
            raise ValueError(msg)

        now = datetime.now(UTC)

        # Record the access event
        entry.access_log.append({
            "agent_uri": agent_uri,
            "timestamp": now.isoformat(),
            "honeypot_id": entry.honeypot_id,
        })

        # Honeypot access severity is fixed at 80 (Section 4.5.3)
        int_score = _HONEYPOT_SEVERITY
        level = threat_level_from_score(int_score)

        return ThreatScore(
            score=_HONEYPOT_SEVERITY / 100.0,
            int_score=int_score,
            level=level,
            factors=[{
                "attack_type": AttackType.T1.identifier,
                "detection_method": "honeypot",
                "honeypot_id": entry.honeypot_id,
                "honeypot_name": entry.name,
                "honeypot_category": entry.category,
                "agent_uri": agent_uri,
                "severity_override": _HONEYPOT_SEVERITY,
                "reason": (
                    f"Agent accessed honeypot token {entry.name!r}. "
                    "No legitimate workflow requires access to this secret."
                ),
            }],
            timestamp=now,
        )

    def create_incident(
        self,
        ref: SecretRef,
        agent_uri: str,
        *,
        attack_type: AttackType = AttackType.T1,
    ) -> Incident:
        """Create an Incident object for a honeypot access event.

        Parameters
        ----------
        ref : SecretRef
            The honeypot's secret reference.
        agent_uri : str
            The agent that accessed the honeypot.
        attack_type : AttackType
            The attack type classification (default T1).

        Returns
        -------
        Incident
            An incident suitable for recording in the ThreatScorer.

        Raises
        ------
        ValueError
            If *ref* is not a registered honeypot.
        """
        entry = self._by_ref.get(str(ref))
        if entry is None:
            msg = f"Not a registered honeypot: {ref}"
            raise ValueError(msg)

        return Incident(
            attack_type=attack_type,
            timestamp=datetime.now(UTC),
            agent_uri=agent_uri,
            evidence={
                "detection_method": "honeypot",
                "honeypot_id": entry.honeypot_id,
                "honeypot_name": entry.name,
                "honeypot_category": entry.category,
                "severity_override": _HONEYPOT_SEVERITY,
                "matched_secret_ref": str(ref),
            },
        )
