"""NL Protocol Level 2 -- Scope grant evaluation.

This module implements the scope grant evaluation algorithm defined in
Chapter 02, Section 8 of the NL Protocol specification.

Key responsibilities:

* **Find** the first valid, matching scope grant for a given agent, secret
  reference, and action type.
* **Consume** usage counts atomically, raising :class:`UseLimitExceeded`
  when the grant is exhausted.
* **Evaluate** grant conditions (time bounds, usage limits).
* **Verify** the subset rule for delegation: a delegated scope can only be
  equal to or narrower than the parent grant.

The evaluation algorithm follows a fail-fast strategy: as soon as a
condition is not met, the grant is skipped.
"""
from __future__ import annotations

from datetime import UTC, datetime
from fnmatch import fnmatch
from typing import TYPE_CHECKING

from nl_protocol.core.errors import (
    NoScopeGrant,
    ScopeExpired,
    UseLimitExceeded,
)
from nl_protocol.core.types import (
    ActionType,
    AgentURI,
    DelegationScope,
    ScopeConditions,
    ScopeGrant,
    SecretRef,
)

if TYPE_CHECKING:
    from nl_protocol.core.interfaces import ScopeGrantStore


class ScopeEvaluator:
    """Evaluates scope grants against action requests.

    Implements the scope evaluation algorithm from Section 8.4, including:

    * Grant matching (secret pattern, action type, conditions).
    * Condition evaluation (time bounds, usage limits).
    * Usage consumption with atomic semantics.
    * Delegation subset verification (Section 5.7 / Level 7).

    Parameters
    ----------
    grant_store:
        A :class:`~nl_protocol.core.interfaces.ScopeGrantStore` that
        provides grant retrieval and usage tracking.
    """

    def __init__(self, grant_store: ScopeGrantStore) -> None:
        self._store = grant_store

    # -- Public API ---------------------------------------------------------

    async def find_matching_grant(
        self,
        agent_uri: AgentURI,
        secret_ref: SecretRef,
        action_type: ActionType,
    ) -> ScopeGrant:
        """Find a valid, matching scope grant for the request.

        Iterates through all active grants for the agent and returns the
        first one that:

        1. Is not revoked.
        2. Matches the secret reference (glob pattern).
        3. Permits the requested action type.
        4. Has all conditions satisfied (time, usage).

        Parameters
        ----------
        agent_uri:
            The requesting agent's URI.
        secret_ref:
            The secret being accessed.
        action_type:
            The action type being performed.

        Returns
        -------
        ScopeGrant
            The first matching, valid grant.

        Raises
        ------
        NoScopeGrant
            If no valid grant exists for the given combination.
        ScopeExpired
            If a matching grant was found but its time window has expired.
        """
        grants = await self._store.get_grants(agent_uri)
        now = datetime.now(UTC)

        # Track whether we found an expired-but-otherwise-matching grant
        # so we can give a more specific error.
        found_expired = False

        for grant in grants:
            # Skip revoked grants immediately
            if grant.revoked:
                continue

            # Check secret pattern match (glob)
            if not self._matches_secret(grant.secret, str(secret_ref)):
                continue

            # Check action type
            if action_type not in grant.actions:
                continue

            # Check time and usage conditions
            if not self._check_conditions(grant.conditions, now):
                # Distinguish expired from other failures for better errors
                if self._is_expired(grant.conditions, now):
                    found_expired = True
                continue

            return grant

        # No matching grant found -- raise the most specific error
        if found_expired:
            raise ScopeExpired(
                f"Scope grant for secret '{secret_ref}' has expired "
                f"(agent: {agent_uri})",
                details={
                    "agent_uri": str(agent_uri),
                    "secret_ref": str(secret_ref),
                },
            )

        raise NoScopeGrant(
            f"No active scope grant covers secret '{secret_ref}' "
            f"for action '{action_type}' (agent: {agent_uri})",
            details={
                "agent_uri": str(agent_uri),
                "secret_ref": str(secret_ref),
                "action_type": str(action_type),
            },
        )

    async def consume_usage(self, grant: ScopeGrant) -> None:
        """Increment usage count for a grant.

        Per Section 8.4.2, usage consumption is atomic: if two concurrent
        actions race for the last available use, exactly one succeeds.

        Parameters
        ----------
        grant:
            The grant whose usage count should be incremented.

        Raises
        ------
        UseLimitExceeded
            If the grant has reached its ``max_uses`` limit.
        """
        if grant.conditions.max_uses is not None:
            new_count = await self._store.increment_usage(grant.grant_id)
            if new_count > grant.conditions.max_uses:
                raise UseLimitExceeded(
                    f"Scope grant '{grant.grant_id}' has exceeded its "
                    f"max_uses limit of {grant.conditions.max_uses}",
                    details={
                        "grant_id": grant.grant_id,
                        "max_uses": grant.conditions.max_uses,
                        "current_uses": new_count,
                    },
                )

    def is_subset(self, parent: ScopeGrant, child_scope: DelegationScope) -> bool:
        """Check if *child_scope* is a subset of *parent* grant.

        Used for delegation (Level 7): a delegated scope can only be equal
        to or narrower than the delegating agent's own grant.  This enforces
        the **subset rule** -- no privilege escalation through delegation.

        Parameters
        ----------
        parent:
            The delegating agent's scope grant.
        child_scope:
            The proposed delegation scope.

        Returns
        -------
        bool
            ``True`` if every aspect of *child_scope* is covered by *parent*.
        """
        # Every secret in child must match parent's pattern
        for secret in child_scope.secrets:
            if not self._matches_secret(parent.secret, secret):
                return False

        # Every action in child must be in parent's actions
        for action in child_scope.actions:
            if action not in parent.actions:
                return False

        # Child conditions must be equal or stricter than parent's
        if child_scope.conditions is not None:
            parent_cond = parent.conditions
            child_cond = child_scope.conditions

            # valid_until: child cannot extend beyond parent
            if parent_cond.valid_until is not None:
                if child_cond.valid_until is None:
                    # Parent has an expiry but child doesn't -- escalation
                    return False
                if child_cond.valid_until > parent_cond.valid_until:
                    return False

            # valid_from: child cannot start before parent
            if (
                parent_cond.valid_from is not None
                and child_cond.valid_from is not None
                and child_cond.valid_from < parent_cond.valid_from
            ):
                return False

            # max_uses: child cannot have more uses than parent
            if parent_cond.max_uses is not None:
                if child_cond.max_uses is None:
                    # Parent has a limit but child doesn't -- escalation
                    return False
                if child_cond.max_uses > parent_cond.max_uses:
                    return False

        return True

    # -- Private helpers ----------------------------------------------------

    @staticmethod
    def _matches_secret(pattern: str, ref: str) -> bool:
        """Check if a secret reference matches a grant's secret pattern.

        Uses glob-style matching (``fnmatch``).  The pattern ``"api/*"``
        matches ``"api/GITHUB_TOKEN"`` but not ``"database/DB_PASSWORD"``.
        The pattern ``"*"`` matches everything.

        Parameters
        ----------
        pattern:
            The grant's secret pattern (glob syntax).
        ref:
            The actual secret reference string.

        Returns
        -------
        bool
            ``True`` if the ref matches the pattern.
        """
        return fnmatch(ref, pattern)

    @staticmethod
    def _check_conditions(conditions: ScopeConditions, now: datetime) -> bool:
        """Check all conditions on a scope grant are currently met.

        Implements the fail-fast evaluation strategy from Section 8.4.1.

        Parameters
        ----------
        conditions:
            The conditions to evaluate.
        now:
            The current UTC timestamp.

        Returns
        -------
        bool
            ``True`` if all conditions pass.
        """
        # 1. Time window: valid_from
        if conditions.valid_from is not None and now < conditions.valid_from:
            return False

        # 2. Time window: valid_until
        if conditions.valid_until is not None and now >= conditions.valid_until:
            return False

        # 3. Usage limit
        if conditions.max_uses is not None:
            return conditions.current_uses < conditions.max_uses
        return True

    @staticmethod
    def _is_expired(conditions: ScopeConditions, now: datetime) -> bool:
        """Check specifically whether the time window has expired.

        Used to provide more specific error messages when a grant
        is found but expired.
        """
        return bool(conditions.valid_until is not None and now >= conditions.valid_until)
