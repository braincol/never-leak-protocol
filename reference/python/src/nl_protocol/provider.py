"""NL Protocol Provider -- the main orchestrator.

This module implements the :class:`NLProvider` class, the primary entry
point for the NL Protocol reference implementation.  It composes all
level-specific components (identity, access, isolation, defense, audit,
detection, federation) and routes action requests through the correct
pipeline.

Pipeline (7-level integration)
------------------------------

1. **Validate** -- action payload structure check.
2. **Evasion detection (L4)** -- Unicode homoglyphs, null bytes, template injection.
3. **Policy evaluation** -- deny rules (L4), AID scope (L1), scope grants (L2),
   conditions (L2), delegation verification (L7).
4. **Resolve placeholders (L2)** -- ``{{nl:...}}`` -> secret values.
5. **Audit recording (L5)** -- SHA-256 hash chain via :class:`ChainManager`.
6. **Threat scoring (L6)** -- update per-agent threat score, determine response.
7. **Return result** with audit reference.

Usage
-----
::

    from nl_protocol.core.config import NLProviderConfig
    from nl_protocol.core.interfaces import (
        InMemoryAgentRegistry,
        InMemoryAuditStore,
        InMemorySecretStore,
        InMemoryScopeGrantStore,
    )
    from nl_protocol.provider import NLProvider

    provider = NLProvider(
        config=NLProviderConfig(provider_id="my-provider"),
        secret_store=InMemorySecretStore(),
        agent_registry=InMemoryAgentRegistry(),
        scope_grant_store=InMemoryScopeGrantStore(),
        audit_store=InMemoryAuditStore(),
    )

    response = await provider.process_action(request)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from nl_protocol.access.actions import ActionValidator
from nl_protocol.access.placeholders import PlaceholderResolver
from nl_protocol.access.policy import PolicyEvaluator
from nl_protocol.access.sanitization import OutputSanitizer
from nl_protocol.access.scope_grants import ScopeEvaluator
from nl_protocol.audit.chain import ChainManager
from nl_protocol.core.errors import (
    AuthenticationError,
    AuthorizationError,
    DefenseError,
    DetectionError,
    ExecutionError,
    NLProtocolError,
)
from nl_protocol.core.types import (
    AID,
    ActionError,
    ActionRequest,
    ActionResponse,
    ActionResult,
    AgentURI,
    ScopeGrant,
)
from nl_protocol.defense.deny_rules import DenyRuleEngine
from nl_protocol.defense.validation import CommandValidator
from nl_protocol.detection.response import ResponseEngine
from nl_protocol.detection.threat_scoring import AttackType, Incident, ThreatScorer
from nl_protocol.federation.nonce import NonceManager
from nl_protocol.federation.verification import DelegationVerifier
from nl_protocol.identity.aid import AIDManager
from nl_protocol.identity.lifecycle import LifecycleManager

if TYPE_CHECKING:
    from nl_protocol.core.config import NLProviderConfig
    from nl_protocol.core.interfaces import (
        AgentRegistry,
        AuditStore,
        DelegationStore,
        NonceStore,
        ScopeGrantStore,
        SecretStore,
    )
    from nl_protocol.detection.response import ResponseAction
    from nl_protocol.detection.threat_scoring import ThreatScore


class NLProvider:
    """The main orchestrator -- processes action requests through the 7-level pipeline.

    This is the primary entry point for the NL Protocol.  It composes all
    level-specific components and routes action requests through them
    in the correct order:

    * **Level 1** -- Agent Identity (AID management, lifecycle, trust levels)
    * **Level 2** -- Action-Based Access (scope grants, placeholders, sanitization)
    * **Level 4** -- Pre-Execution Defense (deny rules, evasion detection)
    * **Level 5** -- Audit Integrity (SHA-256 hash chain)
    * **Level 6** -- Attack Detection & Response (threat scoring, 4-tier response)
    * **Level 7** -- Cross-Agent Trust & Federation (delegation tokens)

    Level 3 (Execution Isolation) is available as a standalone
    :class:`~nl_protocol.isolation.subprocess.IsolatedExecutor` for callers
    that need to execute resolved commands in an isolated subprocess.

    Parameters
    ----------
    config:
        Provider configuration controlling timeouts, limits, and
        supported levels.
    secret_store:
        Backend for secret resolution.
    agent_registry:
        Backend for agent identity management.
    scope_grant_store:
        Backend for scope grant persistence.
    audit_store:
        Optional backend for the append-only audit chain (Level 5).
        When ``None``, audit recording is skipped.
    nonce_store:
        Optional backend for replay prevention.
        When ``None``, replay detection is skipped.
    delegation_store:
        Optional backend for delegation token persistence (Level 7).
        When ``None``, delegation features are unavailable.
    """

    def __init__(
        self,
        config: NLProviderConfig,
        secret_store: SecretStore,
        agent_registry: AgentRegistry,
        scope_grant_store: ScopeGrantStore,
        audit_store: AuditStore | None = None,
        nonce_store: NonceStore | None = None,
        delegation_store: DelegationStore | None = None,
    ) -> None:
        self._config = config
        self._secret_store = secret_store
        self._agent_registry = agent_registry
        self._scope_grant_store = scope_grant_store
        self._audit_store = audit_store
        self._nonce_store = nonce_store
        self._delegation_store = delegation_store

        # -- Level 1: Agent Identity -------------------------------------------
        self._aid_manager = AIDManager(agent_registry)
        self._lifecycle_manager = LifecycleManager(agent_registry)

        # -- Level 2: Action-Based Access --------------------------------------
        self._scope_evaluator = ScopeEvaluator(scope_grant_store)
        self._placeholder_resolver = PlaceholderResolver(secret_store)
        self._action_validator = ActionValidator()
        self._output_sanitizer = OutputSanitizer()

        # -- Level 4: Pre-Execution Defense ------------------------------------
        self._deny_engine: DenyRuleEngine | None = None
        self._command_validator: CommandValidator | None = None
        if 4 in config.supported_levels:
            self._deny_engine = DenyRuleEngine()
            self._command_validator = CommandValidator()

        # -- Level 5: Audit Integrity (SHA-256 hash chain) ---------------------
        self._chain_manager: ChainManager | None = None
        self._chain_initialized = False
        if audit_store is not None and 5 in config.supported_levels:
            self._chain_manager = ChainManager(store=audit_store)

        # -- Level 6: Attack Detection & Response ------------------------------
        self._threat_scorer: ThreatScorer | None = None
        self._response_engine: ResponseEngine | None = None
        if 6 in config.supported_levels:
            self._threat_scorer = ThreatScorer()
            self._response_engine = ResponseEngine()

        # -- Level 7: Cross-Agent Trust & Federation ---------------------------
        self._delegation_verifier: DelegationVerifier | None = None
        if (
            delegation_store is not None
            and nonce_store is not None
            and 7 in config.supported_levels
        ):
            nonce_manager = NonceManager(nonce_store)
            self._delegation_verifier = DelegationVerifier(
                delegation_store=delegation_store,
                agent_registry=agent_registry,
                scope_grant_store=scope_grant_store,
                nonce_manager=nonce_manager,
            )

        # -- Policy evaluator (composes L1, L2, L4, L7) -----------------------
        self._policy_evaluator = PolicyEvaluator(
            aid_manager=self._aid_manager,
            scope_evaluator=self._scope_evaluator,
            deny_engine=self._deny_engine,
            delegation_verifier=self._delegation_verifier,
        )

    # ------------------------------------------------------------------
    # Properties for introspection
    # ------------------------------------------------------------------

    @property
    def config(self) -> NLProviderConfig:
        """The provider configuration."""
        return self._config

    @property
    def aid_manager(self) -> AIDManager:
        """The Level 1 AID manager."""
        return self._aid_manager

    @property
    def lifecycle_manager(self) -> LifecycleManager:
        """The Level 1 lifecycle manager."""
        return self._lifecycle_manager

    @property
    def scope_evaluator(self) -> ScopeEvaluator:
        """The Level 2 scope evaluator."""
        return self._scope_evaluator

    @property
    def output_sanitizer(self) -> OutputSanitizer:
        """The Level 2 output sanitizer."""
        return self._output_sanitizer

    @property
    def policy_evaluator(self) -> PolicyEvaluator:
        """The policy evaluator (composes L1, L2, L4, L7)."""
        return self._policy_evaluator

    @property
    def deny_engine(self) -> DenyRuleEngine | None:
        """The Level 4 deny rule engine (``None`` if L4 disabled)."""
        return self._deny_engine

    @property
    def command_validator(self) -> CommandValidator | None:
        """The Level 4 command validator (``None`` if L4 disabled)."""
        return self._command_validator

    @property
    def chain_manager(self) -> ChainManager | None:
        """The Level 5 audit chain manager (``None`` if L5 disabled)."""
        return self._chain_manager

    @property
    def threat_scorer(self) -> ThreatScorer | None:
        """The Level 6 threat scorer (``None`` if L6 disabled)."""
        return self._threat_scorer

    @property
    def response_engine(self) -> ResponseEngine | None:
        """The Level 6 response engine (``None`` if L6 disabled)."""
        return self._response_engine

    @property
    def delegation_verifier(self) -> DelegationVerifier | None:
        """The Level 7 delegation verifier (``None`` if L7 disabled)."""
        return self._delegation_verifier

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    async def process_action(self, request: ActionRequest) -> ActionResponse:
        """Process an action request through the full NL Protocol pipeline.

        The pipeline executes the following steps:

        1. **Validate request** -- check message structure and action payload.
        2. **Evasion detection (L4)** -- check for Unicode evasion,
           null bytes, template injection.
        3. **Policy evaluation** -- deny rules (L4), AID scope (L1),
           scope grants (L2), conditions (L2), delegation (L7).
        4. **Resolve placeholders (L2)** -- ``{{nl:...}}`` -> secret values.
        5. **Audit recording (L5)** -- SHA-256 hash chain.
        6. **Threat scoring (L6)** -- update threat score, determine response.
        7. **Return result** with audit reference.

        All errors are caught and converted to an :class:`ActionResponse`
        with the appropriate status and error code.

        Parameters
        ----------
        request:
            The action request submitted by an agent.

        Returns
        -------
        ActionResponse
            The result of the action.  ``status`` is one of
            ``"success"``, ``"error"``, or ``"denied"``.
        """
        audit_ref: str | None = None
        try:
            # -- Step 1: Validate action payload structure ------------------
            self._action_validator.validate_or_raise(request.action)

            # -- Step 2: Evasion detection (Level 4) -----------------------
            if self._command_validator is not None and request.action.template:
                self._command_validator.validate_or_raise(request.action.template)

            # -- Step 3: Policy evaluation (L1 + L2 + L4 deny + L7) --------
            decision = await self._policy_evaluator.evaluate(request)

            # -- Step 4: Resolve placeholders (within isolation boundary) ---
            resolved_secrets: list[str] = []
            if decision.secret_refs:
                _resolved_template, refs = await self._placeholder_resolver.resolve(
                    request.action.template,
                )
                resolved_secrets = [str(r) for r in refs]

                # Consume usage on the matching grant (if applicable)
                if decision.grant is not None:
                    await self._scope_evaluator.consume_usage(decision.grant)

            # -- Step 5: Audit recording (Level 5 -- SHA-256 chain) ---------
            audit_ref = await self._record_audit(
                agent_uri=request.agent_id,
                action_type=str(request.action.type),
                secrets_used=resolved_secrets,
                result_summary="success",
            )

            # -- Step 6: Threat scoring (Level 6) --------------------------
            # Successful actions don't generate incidents; scoring is
            # updated only when violations are detected (see _handle_threat).

            # -- Step 7: Return success response ---------------------------
            return ActionResponse(
                status="success",
                result=ActionResult(
                    exit_code=0,
                    stdout=f"Action '{request.action.type}' completed successfully",
                    stderr="",
                ),
                audit_ref=audit_ref,
            )

        except (AuthenticationError, AuthorizationError, DefenseError) as exc:
            # Record threat incident for denied actions (Level 6)
            self._handle_threat(request, exc)
            return self._error_response("denied", exc, audit_ref)

        except DetectionError as exc:
            return self._error_response("denied", exc, audit_ref)

        except NLProtocolError as exc:
            # All other NL Protocol errors -> "error" status
            return self._error_response("error", exc, audit_ref)

        except Exception as exc:
            # Unexpected errors are caught and wrapped to prevent
            # uncontrolled error propagation to the agent.
            wrapped = ExecutionError(
                f"Internal error: {type(exc).__name__}: {exc}",
                details={"exception_type": type(exc).__name__},
            )
            return self._error_response("error", wrapped, audit_ref)

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------

    async def register_agent(self, aid: AID) -> None:
        """Register a new agent.

        Delegates to the Level 1 :class:`AIDManager` which validates
        the AID structure and persists it in the registry.

        Parameters
        ----------
        aid:
            The Agent Identity Document to register.

        Raises
        ------
        nl_protocol.core.errors.InvalidAgent
            If the AID fails structural validation.
        """
        await self._aid_manager.register_agent(aid)

    async def revoke_agent(self, agent_uri: AgentURI) -> None:
        """Revoke an agent, permanently disabling it.

        This transitions the agent to the ``REVOKED`` lifecycle state,
        which is terminal.  A new AID must be registered if the agent
        software needs to operate again.

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI of the agent to revoke.

        Raises
        ------
        nl_protocol.core.errors.InvalidAgent
            If the agent does not exist.
        nl_protocol.identity.lifecycle.InvalidLifecycleTransition
            If the transition is not valid from the current state.
        """
        await self._lifecycle_manager.revoke(agent_uri)

    # ------------------------------------------------------------------
    # Scope grant management
    # ------------------------------------------------------------------

    async def create_scope_grant(self, grant: ScopeGrant) -> str:
        """Create a scope grant for an agent.

        Persists the grant in the scope grant store.  The grant
        becomes immediately active (subject to its conditions).

        Parameters
        ----------
        grant:
            The scope grant to create.

        Returns
        -------
        str
            The grant ID (``grant.grant_id``).
        """
        await self._scope_grant_store.create_grant(grant)
        return grant.grant_id

    async def revoke_scope_grant(self, grant_id: str) -> None:
        """Revoke a scope grant.

        Marks the grant as revoked so it will no longer match
        during policy evaluation.

        Parameters
        ----------
        grant_id:
            The ID of the grant to revoke.
        """
        await self._scope_grant_store.revoke_grant(grant_id)

    # ------------------------------------------------------------------
    # Threat scoring (Level 6)
    # ------------------------------------------------------------------

    def get_threat_score(self, agent_uri: AgentURI) -> ThreatScore | None:
        """Return the current threat score for an agent.

        Parameters
        ----------
        agent_uri:
            The agent URI to score.

        Returns
        -------
        ThreatScore | None
            The score, or ``None`` if Level 6 is disabled.
        """
        if self._threat_scorer is None:
            return None
        return self._threat_scorer.compute_score(str(agent_uri))

    def get_threat_response(self, agent_uri: AgentURI) -> ResponseAction | None:
        """Determine the automated response for an agent's current threat level.

        Parameters
        ----------
        agent_uri:
            The agent URI to evaluate.

        Returns
        -------
        ResponseAction | None
            The response action, or ``None`` if Level 6 is disabled.
        """
        if self._threat_scorer is None or self._response_engine is None:
            return None
        score = self._threat_scorer.compute_score(str(agent_uri))
        return self._response_engine.determine_response(score)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error_response(
        status: str,
        exc: NLProtocolError,
        audit_ref: str | None,
    ) -> ActionResponse:
        """Build an :class:`ActionResponse` from an NL Protocol error."""
        return ActionResponse(
            status=status,  # type: ignore[arg-type]
            error=ActionError(
                code=exc.code,
                message=exc.message,
                details=exc.details,
            ),
            audit_ref=audit_ref,
        )

    def _handle_threat(
        self,
        request: ActionRequest,
        exc: NLProtocolError,
    ) -> None:
        """Record a threat incident for denied actions (Level 6).

        Maps error types to attack categories for threat scoring.
        Only runs when Level 6 (detection) is enabled.
        """
        if self._threat_scorer is None:
            return

        from datetime import UTC, datetime

        # Map error codes to attack types
        attack_type = _error_to_attack_type(exc)
        if attack_type is None:
            return

        self._threat_scorer.record_incident(
            Incident(
                attack_type=attack_type,
                timestamp=datetime.now(UTC),
                agent_uri=str(request.agent_id),
                evidence={
                    "error_code": exc.code,
                    "action_type": str(request.action.type),
                    "template_preview": request.action.template[:80]
                    if request.action.template
                    else "",
                },
            )
        )

    async def _record_audit(
        self,
        agent_uri: AgentURI,
        action_type: str,
        secrets_used: list[str],
        result_summary: str,
    ) -> str | None:
        """Record an audit entry using the SHA-256 hash chain (Level 5).

        Lazily initialises the chain on first call (genesis entry).

        Parameters
        ----------
        agent_uri:
            The agent that performed the action.
        action_type:
            The type of action performed.
        secrets_used:
            List of secret names (NEVER values) used in the action.
        result_summary:
            A brief summary of the action result.

        Returns
        -------
        str | None
            The audit record ID, or ``None`` if audit is not configured.
        """
        if self._chain_manager is None:
            return None

        # Lazy initialisation: create genesis entry on first audit call.
        if not self._chain_initialized:
            await self._chain_manager.initialise()
            self._chain_initialized = True

        target = ",".join(secrets_used) if secrets_used else action_type
        record = await self._chain_manager.append(
            action_type=action_type,
            target=target,
            result=result_summary,
            agent_uri=agent_uri,
            secrets_used=secrets_used,
        )
        return record.record_id


# ---------------------------------------------------------------------------
# Error-to-attack-type mapping for threat scoring (Level 6)
# ---------------------------------------------------------------------------

def _error_to_attack_type(exc: NLProtocolError) -> AttackType | None:
    """Map an NL Protocol error to an attack type for threat scoring.

    Returns ``None`` for errors that are not indicative of an attack
    (e.g. expired grants, expired AIDs).
    """
    code = exc.code
    _map: dict[str, AttackType] = {
        # Defense errors -> evasion
        "NL-E400": AttackType.T3,  # ActionBlocked (deny rule hit)
        "NL-E401": AttackType.T3,  # EvasionDetected
        # Authorization errors that suggest attack behaviour
        "NL-E200": AttackType.T1,  # NoScopeGrant (probing)
        # Federation errors
        "NL-E700": AttackType.T6,  # InvalidDelegationToken
    }
    return _map.get(code)
