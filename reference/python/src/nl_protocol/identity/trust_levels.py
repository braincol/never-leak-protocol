"""Trust level evaluation and capability management.

Implements NL Protocol Specification v1.0, Chapter 01 -- Section 7.
Maps each trust level to its permitted :class:`ActionType` set and
provides methods for capability validation, action authorization, and
trust-level promotion/demotion guards.
"""
from __future__ import annotations

from nl_protocol.core.errors import TrustLevelInsufficient
from nl_protocol.core.types import (
    AID,
    ActionType,
    TrustLevel,
)


class TrustLevelManager:
    """Manages trust level evaluation and transitions.

    Each :class:`TrustLevel` maps to a fixed set of allowed
    :class:`ActionType` values:

    * **L0 (Self-Attested)** -- no capabilities.
    * **L1 (Org-Verified)** -- ``READ`` only.
    * **L2 (Vendor-Attested)** -- ``READ`` + ``TEMPLATE``.
    * **L3 (Third-Party-Certified)** -- all action types
      (``READ``, ``TEMPLATE``, ``EXEC``, ``HTTP``).

    These mappings are deliberately conservative.  Actual access is
    further restricted by Scope Grants (Level 2).
    """

    LEVEL_CAPABILITIES: dict[TrustLevel, frozenset[ActionType]] = {
        TrustLevel.L0: frozenset(),
        TrustLevel.L1: frozenset({ActionType.READ}),
        TrustLevel.L2: frozenset({ActionType.READ, ActionType.TEMPLATE}),
        TrustLevel.L3: frozenset(
            {ActionType.READ, ActionType.TEMPLATE, ActionType.EXEC, ActionType.HTTP}
        ),
    }
    """Mapping from trust level to the set of action types it permits."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def can_perform_action(
        self, trust_level: TrustLevel, action_type: ActionType
    ) -> bool:
        """Check whether a trust level permits a specific action type.

        Parameters
        ----------
        trust_level:
            The agent's current trust level.
        action_type:
            The action type to check.

        Returns
        -------
        bool
            ``True`` if the action is allowed at this trust level.
        """
        allowed = self.LEVEL_CAPABILITIES.get(trust_level, frozenset())
        return action_type in allowed

    def validate_capabilities(self, aid: AID) -> None:
        """Validate that an AID's declared capabilities do not exceed its trust level.

        Per spec Section 7.3, rule 2: the system MUST verify that the
        claimed trust level is supported by the evidence provided.
        This method enforces that declared capabilities are a subset
        of the capabilities permitted by the AID's trust level.

        Parameters
        ----------
        aid:
            The Agent Identity Document to validate.

        Raises
        ------
        TrustLevelInsufficient
            If any capability in the AID is not permitted by its
            trust level.
        """
        allowed = self.LEVEL_CAPABILITIES.get(aid.trust_level, frozenset())
        for capability in aid.capabilities:
            if capability not in allowed:
                raise TrustLevelInsufficient(
                    f"Agent '{aid.agent_uri}' declares capability "
                    f"'{capability.value}' which is not permitted at "
                    f"trust level {aid.trust_level.value}. "
                    f"Allowed at {aid.trust_level.value}: "
                    f"{sorted(a.value for a in allowed) if allowed else 'none'}.",
                    details={
                        "agent_uri": str(aid.agent_uri),
                        "required": capability.value,
                        "actual": aid.trust_level.value,
                    },
                )

    def can_promote(self, current: TrustLevel, target: TrustLevel) -> bool:
        """Check whether promotion from *current* to *target* is valid.

        Per spec Section 7.4, trust levels may be promoted as evidence
        is provided:  L0 -> L1 -> L2 -> L3.

        Parameters
        ----------
        current:
            The agent's current trust level.
        target:
            The desired trust level after promotion.

        Returns
        -------
        bool
            ``True`` if *target* is strictly higher than *current*.
        """
        return self._level_ordinal(target) > self._level_ordinal(current)

    def can_demote(self, current: TrustLevel, target: TrustLevel) -> bool:
        """Check whether demotion from *current* to *target* would be valid.

        Per spec Section 7.5, trust level demotion is NOT permitted
        for active agents.  This method only checks the ordinal
        relationship; callers should use this to *detect* an invalid
        demotion attempt and respond accordingly (typically by revoking
        the agent and issuing a new AID at the lower level).

        Parameters
        ----------
        current:
            The agent's current trust level.
        target:
            The proposed (lower) trust level.

        Returns
        -------
        bool
            ``True`` if *target* is strictly lower than *current*,
            meaning a demotion *would* be required (but is not
            permitted on active agents).
        """
        return self._level_ordinal(target) < self._level_ordinal(current)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _level_ordinal(level: TrustLevel) -> int:
        """Return a numeric ordinal for a trust level.

        Extracts the integer from the enum value (e.g. ``"L2"`` -> 2).
        Falls back to the enum's position in the ``TrustLevel`` members
        if the value format is unexpected.
        """
        value = level.value
        if isinstance(value, str) and value.startswith("L") and value[1:].isdigit():
            return int(value[1:])
        # Defensive fallback: use member index
        members = list(TrustLevel)
        return members.index(level)
