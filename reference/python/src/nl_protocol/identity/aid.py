"""Agent Identity Document (AID) management.

Implements NL Protocol Specification v1.0, Chapter 01 -- Sections 3, 4,
and 10.  Provides AID validation, agent registration, retrieval,
verification (lifecycle + expiration), and scope evaluation.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from nl_protocol.core.errors import (
    AgentRevoked,
    AgentSuspended,
    AIDExpired,
    AuthenticationError,
    InvalidAgent,
)
from nl_protocol.core.types import (
    AID,
    AgentURI,
    LifecycleState,
    TrustLevel,
)

if TYPE_CHECKING:
    from nl_protocol.core.interfaces import AgentRegistry

# ---------------------------------------------------------------------------
# Agent URI validation
# ---------------------------------------------------------------------------

# Matches: nl://vendor.domain/agent-type/MAJOR.MINOR.PATCH[-pre][+build]
#
# Per spec Section 3.2 ABNF:
#   vendor       = domain-name          (lowercase DNS labels, no port)
#   agent-type   = LCALPHA *(LCALPHA / DIGIT / "-") LCALPHA / LCALPHA
#   version      = MAJOR "." MINOR "." PATCH [pre-release] [build]
_AGENT_URI_RE: re.Pattern[str] = re.compile(
    r"^nl://"
    r"(?P<vendor>[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*)"  # DNS-style domain
    r"/"
    r"(?P<agent_type>[a-z](?:[a-z0-9-]*[a-z0-9])?)"  # kebab-case identifier
    r"/"
    r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?(?:\+[A-Za-z0-9.]+)?)"
    r"$"
)

# Scope glob patterns -- allowed characters per spec Section 4.3.5
_SCOPE_PATTERN_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_.*?/\-]+$")


class AIDManager:
    """Manages Agent Identity Documents.

    Provides the full lifecycle of AID operations:

    * **register_agent** -- validate and persist a new AID.
    * **get_agent** -- retrieve an AID by its Agent URI.
    * **verify_agent** -- retrieve, then assert lifecycle == ACTIVE
      and ``expires_at`` is in the future.
    * **check_scope** -- evaluate whether a secret reference falls
      within an AID's declared scope patterns.

    Parameters
    ----------
    registry:
        An :class:`AgentRegistry` implementation used for persistence.
    """

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry: AgentRegistry = registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def register_agent(self, aid: AID) -> None:
        """Register a new agent after validating its AID structure.

        Parameters
        ----------
        aid:
            The Agent Identity Document to register.

        Raises
        ------
        InvalidAgent
            If the AID fails structural validation (malformed URI,
            invalid scope patterns, inconsistent timestamps, etc.).
        """
        self._validate_aid(aid)
        await self._registry.register(aid)

    async def get_agent(self, agent_uri: AgentURI) -> AID:
        """Retrieve an agent's AID by its Agent URI.

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI identifying the agent.

        Returns
        -------
        AID
            The stored Agent Identity Document.

        Raises
        ------
        InvalidAgent
            If no agent with the given URI exists in the registry.
        """
        aid = await self._registry.get_aid(agent_uri)
        if aid is None:
            raise InvalidAgent(
                f"No agent found for URI: {agent_uri}",
                details={"agent_uri": str(agent_uri)},
            )
        return aid

    async def verify_agent(self, agent_uri: AgentURI) -> AID:
        """Verify that an agent is valid for performing actions.

        This method performs the identity verification steps required
        by the spec (Section 10.2):

        1. The agent must exist in the registry.
        2. The agent's lifecycle state must be ``ACTIVE``.
        3. The agent must not be expired (``expires_at > now()``).

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI identifying the agent.

        Returns
        -------
        AID
            The verified Agent Identity Document.

        Raises
        ------
        InvalidAgent
            If the agent does not exist.
        AgentSuspended
            If the agent is in the ``SUSPENDED`` state.
        AgentRevoked
            If the agent is in the ``REVOKED`` state.
        AuthenticationError
            If the agent is in a non-active state other than
            suspended or revoked (e.g. ``PENDING``).
        AIDExpired
            If ``now() >= aid.expires_at``.
        """
        aid = await self.get_agent(agent_uri)
        self._check_lifecycle(aid)
        self._check_expiration(aid)
        return aid

    def check_scope(self, aid: AID, secret_ref: str) -> bool:
        """Check whether a secret reference is within the AID's scope.

        Uses :func:`fnmatch.fnmatch` for glob-pattern matching as
        specified in Chapter 01, Section 4.3.5.

        Parameters
        ----------
        aid:
            The Agent Identity Document whose scope to evaluate.
        secret_ref:
            A secret reference string (e.g. ``"api/KEY"``,
            ``"database/DB_PASSWORD"``).

        Returns
        -------
        bool
            ``True`` if **any** scope pattern in ``aid.scope`` matches
            the *secret_ref*; ``False`` otherwise.  If the AID has no
            scope patterns (empty list or ``None``), returns ``True``
            (no scope restriction -- access is governed entirely by
            Scope Grants at Level 2).
        """
        if not aid.scope:
            # No scope restriction on the AID itself.
            return True

        ref_path = PurePosixPath(secret_ref)
        return any(ref_path.match(pattern) for pattern in aid.scope)

    # ------------------------------------------------------------------
    # Internal validation helpers
    # ------------------------------------------------------------------

    def _validate_aid(self, aid: AID) -> None:
        """Validate AID structure per spec Chapter 01, Sections 3-4.

        Checks performed:
        * ``agent_uri`` conforms to ``nl://vendor/agent-type/version``.
        * ``scope`` patterns contain only valid glob characters.
        * ``expires_at > created_at``.
        * ``trust_level`` is a valid :class:`TrustLevel` member.

        Raises
        ------
        InvalidAgent
            On any validation failure.
        """
        # 1. Validate agent_uri format --------------------------------
        uri_str = str(aid.agent_uri)
        match = _AGENT_URI_RE.match(uri_str)
        if match is None:
            raise InvalidAgent(
                f"Invalid agent_uri format: '{uri_str}'. "
                "Expected nl://vendor/agent-type/version "
                "(see spec Section 3.2).",
                details={"agent_uri": uri_str},
            )

        # 2. Validate scope patterns ----------------------------------
        if aid.scope:
            for pattern in aid.scope:
                if not _SCOPE_PATTERN_RE.match(pattern):
                    raise InvalidAgent(
                        f"Invalid scope pattern: '{pattern}'. "
                        "Patterns must use only alphanumeric characters, "
                        "underscores, hyphens, dots, slashes, and glob "
                        "wildcards (*, **, ?).",
                        details={"agent_uri": uri_str, "pattern": pattern},
                    )

        # 3. Validate expiration > creation ---------------------------
        if aid.expires_at <= aid.created_at:
            raise InvalidAgent(
                f"expires_at ({aid.expires_at.isoformat()}) must be "
                f"strictly after created_at ({aid.created_at.isoformat()}).",
                details={"agent_uri": uri_str},
            )

        # 4. Validate trust_level is a known enum value ---------------
        if not isinstance(aid.trust_level, TrustLevel):
            raise InvalidAgent(
                f"Invalid trust_level: {aid.trust_level!r}.",
                details={"agent_uri": uri_str},
            )

    def _check_lifecycle(self, aid: AID) -> None:
        """Assert that the agent's lifecycle state is ``ACTIVE``.

        Per spec Section 6.3, rule 1: the system MUST reject action
        requests from agents in any state other than ``active``.

        Raises
        ------
        AgentSuspended
            If the agent is ``SUSPENDED``.
        AgentRevoked
            If the agent is ``REVOKED``.
        AuthenticationError
            If the agent is in any other non-active state
            (e.g. ``PENDING``).
        """
        state = aid.lifecycle_state
        uri_str = str(aid.agent_uri)

        if state == LifecycleState.ACTIVE:
            return

        if state == LifecycleState.SUSPENDED:
            raise AgentSuspended(
                f"Agent '{uri_str}' is suspended",
                details={"agent_uri": uri_str},
            )

        if state == LifecycleState.REVOKED:
            raise AgentRevoked(
                f"Agent '{uri_str}' has been revoked",
                details={"agent_uri": uri_str},
            )

        # Covers PENDING and any future states
        raise AuthenticationError(
            f"Agent '{uri_str}' is in lifecycle state "
            f"'{state.value}' -- only ACTIVE agents may "
            "perform actions.",
            details={"agent_uri": uri_str, "lifecycle_state": state.value},
        )

    def _check_expiration(self, aid: AID) -> None:
        """Assert that the agent has not expired.

        Uses **strict less-than** per the spec's expiration boundary
        semantics (Section 4.3.1): the AID is valid while
        ``now() < expires_at``.  An AID whose ``expires_at`` equals
        ``now()`` is considered expired.

        Raises
        ------
        AIDExpired
            If ``now() >= aid.expires_at``.
        """
        now = datetime.now(UTC)
        if now >= aid.expires_at:
            raise AIDExpired(
                f"Agent '{aid.agent_uri}' has expired",
                details={"agent_uri": str(aid.agent_uri)},
            )
