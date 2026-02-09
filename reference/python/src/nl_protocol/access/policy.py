"""NL Protocol Level 2 -- Policy evaluation order.

This module implements the five-step policy evaluation order defined in
the NL Protocol specification overview (Chapter 00) and applied to
action requests:

1. **Deny rules (Level 4)** -- if any deny rule matches, BLOCK immediately.
2. **Agent Identity Scope (Level 1)** -- AID scope boundary check.
3. **Scope Grant Authorization (Level 2)** -- valid scope grant check.
4. **Conditional Evaluation (Level 2)** -- conditions check (already done
   as part of step 3 in :class:`ScopeEvaluator`).
5. **Delegation Verification (Level 7)** -- delegation chain validity.

The :class:`PolicyEvaluator` composes components from multiple protocol
levels (identity, access, defense, federation) to implement the full
evaluation pipeline.  Optional components (deny engine, delegation
verifier) gracefully degrade when not available.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from nl_protocol.access.placeholders import PlaceholderResolver
from nl_protocol.core.errors import NoScopeGrant
from nl_protocol.core.types import (
    AID,
    ActionRequest,
    AgentURI,
    ScopeGrant,
    SecretRef,
)

if TYPE_CHECKING:
    from nl_protocol.access.scope_grants import ScopeEvaluator
    from nl_protocol.identity.aid import AIDManager


# ---------------------------------------------------------------------------
# Protocol interfaces for optional Level 4 / Level 7 components
# ---------------------------------------------------------------------------

@runtime_checkable
class DenyEngine(Protocol):
    """Interface for the Level 4 deny engine (defense module).

    Implementations check a template against deny rules and raise
    :class:`~nl_protocol.core.errors.ActionBlocked` if a match is found.
    """

    def check(self, template: str) -> None:
        """Check a template against deny rules.

        Raises
        ------
        nl_protocol.core.errors.ActionBlocked
            If the template matches a deny rule.
        """
        ...


@runtime_checkable
class DelegationVerifier(Protocol):
    """Interface for Level 7 delegation chain verification.

    Implementations verify delegation token validity and chain integrity.
    """

    async def verify(
        self, token_id: str, agent_uri: AgentURI
    ) -> Any:
        """Verify a delegation token for the given agent.

        Parameters
        ----------
        token_id:
            The delegation token ID to verify.
        agent_uri:
            The agent claiming to act under this token.

        Returns
        -------
        Any
            Delegation metadata (token details, chain info).

        Raises
        ------
        nl_protocol.core.errors.InvalidDelegationToken
            If the token is invalid.
        nl_protocol.core.errors.DelegationTokenExpired
            If the token has expired.
        """
        ...


# ---------------------------------------------------------------------------
# Policy decision result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The result of a policy evaluation.

    Holds all artifacts produced during the five-step evaluation:
    the resolved AID, the matching scope grant, delegation metadata,
    and the list of secret references extracted from the template.

    Attributes
    ----------
    allowed:
        Whether the request is permitted.
    aid:
        The verified Agent Identity Document.
    grant:
        The matching scope grant (may be ``None`` if no secrets are
        referenced in the template).
    delegation:
        Delegation verification result (``None`` if no delegation token).
    secret_refs:
        The list of secret references extracted from the template.
    """

    allowed: bool
    aid: AID
    grant: ScopeGrant | None = None
    delegation: Any = None
    secret_refs: list[SecretRef] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Policy evaluator
# ---------------------------------------------------------------------------

class PolicyEvaluator:
    """Implements the 5-step policy evaluation order from the spec.

    1. Deny rules (Level 4) -- if any match, BLOCK immediately.
    2. Agent Identity Scope (Level 1) -- AID scope boundary check.
    3. Scope Grant Authorization (Level 2) -- valid scope grant check.
    4. Conditional Evaluation (Level 2) -- conditions check.
    5. Delegation Verification (Level 7) -- delegation chain validity.

    Parameters
    ----------
    aid_manager:
        The Level 1 AID manager for agent identity verification.
    scope_evaluator:
        The Level 2 scope evaluator for grant matching.
    deny_engine:
        Optional Level 4 deny engine.  When ``None``, step 1 is skipped.
    delegation_verifier:
        Optional Level 7 delegation verifier.  When ``None``, step 5
        is skipped.
    """

    def __init__(
        self,
        aid_manager: AIDManager,
        scope_evaluator: ScopeEvaluator,
        deny_engine: DenyEngine | None = None,
        delegation_verifier: DelegationVerifier | None = None,
    ) -> None:
        self._aid = aid_manager
        self._scope = scope_evaluator
        self._deny = deny_engine
        self._delegation = delegation_verifier

    async def evaluate(self, request: ActionRequest) -> PolicyDecision:
        """Evaluate an action request against all policy layers.

        Executes the five-step policy evaluation in order.  Each step
        either passes silently or raises an appropriate
        :class:`~nl_protocol.core.errors.NLProtocolError` subclass.

        Parameters
        ----------
        request:
            The action request to evaluate.

        Returns
        -------
        PolicyDecision
            Contains the verified AID, matching grant, delegation info,
            and extracted secret refs.

        Raises
        ------
        nl_protocol.core.errors.ActionBlocked
            Step 1: deny rule matched.
        nl_protocol.core.errors.NoScopeGrant
            Step 2/3: agent scope or grant does not cover the request.
        nl_protocol.core.errors.ScopeExpired
            Step 3: matching grant has expired.
        nl_protocol.core.errors.InvalidDelegationToken
            Step 5: delegation token is invalid.
        """
        # -- Step 1: Deny rules (Level 4) -----------------------------------
        if self._deny is not None:
            self._deny.check(request.action.template)

        # -- Step 2: Verify agent identity and AID scope --------------------
        aid = await self._aid.verify_agent(request.agent_id)

        # Extract secret refs from the action template
        refs = PlaceholderResolver.extract_refs_static(request.action.template)

        # Check each ref against the AID's scope boundary
        for ref in refs:
            if not self._aid.check_scope(aid, str(ref)):
                raise NoScopeGrant(
                    f"Agent '{request.agent_id}' AID scope does not cover "
                    f"secret '{ref}' for action '{request.action.type}'",
                    details={
                        "agent_uri": str(request.agent_id),
                        "secret_ref": str(ref),
                        "action_type": str(request.action.type),
                    },
                )

        # -- Step 3 & 4: Find matching scope grant (includes conditions) ----
        grant: ScopeGrant | None = None
        for ref in refs:
            grant = await self._scope.find_matching_grant(
                request.agent_id, ref, request.action.type
            )

        # -- Step 5: Delegation verification (Level 7) ----------------------
        delegation = None
        if request.delegation_token_id and self._delegation is not None:
            delegation = await self._delegation.verify(
                request.delegation_token_id, request.agent_id
            )

        return PolicyDecision(
            allowed=True,
            aid=aid,
            grant=grant,
            delegation=delegation,
            secret_refs=refs,
        )
