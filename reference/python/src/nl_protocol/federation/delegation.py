"""NL Protocol Level 7 -- Delegation token creation.

This module implements delegation token creation as described in Chapter 07,
Sections 2-3 of the NL Protocol specification.

Key invariants:
* **Subset rule**: The delegated scope MUST be a subset of the parent grant.
* **Depth limit**: ``delegation_depth_remaining`` MUST be strictly less than
  the issuer's own remaining depth.
* **Time bound**: The token's validity MUST fall within the parent grant's
  validity window.
* **Use limit**: ``max_uses`` MUST be finite and positive.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from nl_protocol.core.errors import (
    DelegationDepthExceeded,
    DelegationSubsetViolation,
)
from nl_protocol.core.types import (
    AgentURI,
    DelegationScope,
    DelegationToken,
    ScopeGrant,
)

if TYPE_CHECKING:
    from nl_protocol.access.scope_grants import ScopeEvaluator
    from nl_protocol.core.interfaces import DelegationStore


class DelegationManager:
    """Creates and stores delegation tokens with full validation.

    Enforces the subset rule (Section 3.6), depth limits (Section 2.3),
    and time bounds before issuing a new delegation token.

    Parameters
    ----------
    delegation_store:
        The backend store for persisting delegation tokens.
    scope_evaluator:
        Used to verify the subset rule between parent grant and
        delegated scope.
    max_delegation_depth:
        Provider-level maximum delegation depth (default 3).
    """

    def __init__(
        self,
        delegation_store: DelegationStore,
        scope_evaluator: ScopeEvaluator,
        *,
        max_delegation_depth: int = 3,
    ) -> None:
        self._store = delegation_store
        self._scope_evaluator = scope_evaluator
        self._max_depth = max_delegation_depth

    async def create_token(
        self,
        parent_grant: ScopeGrant,
        child_agent_uri: AgentURI,
        scope: DelegationScope,
        ttl: timedelta | None = None,
        *,
        parent_token: DelegationToken | None = None,
    ) -> DelegationToken:
        """Create a new delegation token.

        Parameters
        ----------
        parent_grant:
            The issuer's scope grant from which authority derives.
        child_agent_uri:
            The AID URI of the delegate (subject).
        scope:
            The proposed delegation scope (must be a subset of parent).
        ttl:
            Time-to-live for the token.  Defaults to 5 minutes per spec
            recommendation.  MUST NOT exceed the parent grant's
            ``valid_until``.
        parent_token:
            If this is a re-delegation, the parent delegation token.
            Used to compute depth and register parent-child relationships.

        Returns
        -------
        DelegationToken
            The newly created delegation token.

        Raises
        ------
        DelegationSubsetViolation
            If the requested scope exceeds the parent grant.
        DelegationDepthExceeded
            If the maximum delegation depth has been reached.
        """
        # 1. Enforce subset rule
        if not self._scope_evaluator.is_subset(parent_grant, scope):
            raise DelegationSubsetViolation(
                "Delegation scope is not a subset of the parent grant",
                details={
                    "parent_grant_id": parent_grant.grant_id,
                    "parent_secret": parent_grant.secret,
                    "requested_secrets": scope.secrets,
                    "requested_actions": [str(a) for a in scope.actions],
                },
            )

        # 2. Compute depth and enforce depth limit
        current_depth = 0
        if parent_token is not None:
            current_depth = parent_token.current_depth + 1

        if current_depth >= self._max_depth:
            raise DelegationDepthExceeded(
                f"Maximum delegation depth of {self._max_depth} has been reached "
                f"(current depth: {current_depth})",
                details={
                    "max_depth": self._max_depth,
                    "current_depth": current_depth,
                },
            )

        # 3. Compute expiration with time bound rule
        now = datetime.now(UTC)
        default_ttl = timedelta(minutes=5)
        effective_ttl = ttl if ttl is not None else default_ttl
        expires_at = now + effective_ttl

        # Token must not exceed parent grant's valid_until
        if (
            parent_grant.conditions.valid_until is not None
            and expires_at > parent_grant.conditions.valid_until
        ):
            expires_at = parent_grant.conditions.valid_until

        # Token must not exceed parent token's expiration (if re-delegation)
        if parent_token is not None and expires_at > parent_token.expires_at:
            expires_at = parent_token.expires_at

        # 4. Build the delegation token
        token = DelegationToken(
            token_id=str(uuid.uuid4()),
            issuer=parent_grant.agent_uri,
            subject=child_agent_uri,
            scope=scope,
            issued_at=now,
            expires_at=expires_at,
            max_delegation_depth=self._max_depth,
            current_depth=current_depth,
        )

        # 5. Store the token
        await self._store.store_token(token)

        # 6. Register parent-child relationship if re-delegation
        if parent_token is not None and hasattr(self._store, "register_child"):
            self._store.register_child(parent_token.token_id, token.token_id)

        return token
