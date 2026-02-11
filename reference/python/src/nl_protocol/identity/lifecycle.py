"""Agent lifecycle state machine.

Implements NL Protocol Specification v1.0, Chapter 01 -- Section 6.
Enforces the valid lifecycle transitions and provides convenience
methods for common operations (suspend, revoke, reactivate).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from nl_protocol.core.errors import (
    AuthenticationError,
    InvalidAgent,
)
from nl_protocol.core.types import (
    AgentURI,
    LifecycleState,
)

if TYPE_CHECKING:
    from nl_protocol.core.interfaces import AgentRegistry


class InvalidLifecycleTransition(AuthenticationError):
    """Raised when an invalid lifecycle state transition is attempted.

    This is a subclass of :class:`AuthenticationError` because
    lifecycle violations are fundamentally authentication-domain
    errors -- an agent in a non-active state is not authenticated
    for performing actions.
    """

    def __init__(
        self,
        agent_uri: str,
        from_state: LifecycleState,
        to_state: LifecycleState,
    ) -> None:
        self.agent_uri = agent_uri
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(
            f"Invalid lifecycle transition for agent '{agent_uri}': "
            f"'{from_state.value}' -> '{to_state.value}' is not permitted. "
            f"See spec Chapter 01, Section 6.2 for valid transitions.",
            details={
                "agent_uri": agent_uri,
                "from_state": from_state.value,
                "to_state": to_state.value,
            },
        )


class LifecycleManager:
    """Manages agent lifecycle transitions per spec Chapter 01 Section 6.

    The lifecycle state machine is:

    .. code-block:: text

        PENDING ──activate──> ACTIVE
                                 |  \\
                            suspend  revoke
                                 |      \\
                                 v       v
                            SUSPENDED  REVOKED (terminal)
                                 |
                            reactivate -> ACTIVE
                            revoke     -> REVOKED

    Parameters
    ----------
    registry:
        An :class:`AgentRegistry` implementation used to look up and
        persist lifecycle state changes.
    """

    VALID_TRANSITIONS: ClassVar[set[tuple[LifecycleState, LifecycleState]]] = {
        (LifecycleState.PENDING, LifecycleState.ACTIVE),
        (LifecycleState.ACTIVE, LifecycleState.SUSPENDED),
        (LifecycleState.ACTIVE, LifecycleState.REVOKED),
        (LifecycleState.SUSPENDED, LifecycleState.ACTIVE),
        (LifecycleState.SUSPENDED, LifecycleState.REVOKED),
    }
    """The set of permitted ``(from_state, to_state)`` transitions.

    ``REVOKED`` is a terminal state with no outgoing transitions.
    """

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry: AgentRegistry = registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def transition(
        self,
        agent_uri: AgentURI,
        target_state: LifecycleState,
    ) -> LifecycleState:
        """Transition an agent to a new lifecycle state.

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI of the agent whose state to change.
        target_state:
            The desired lifecycle state.

        Returns
        -------
        LifecycleState
            The new lifecycle state (same as *target_state*) on success.

        Raises
        ------
        InvalidAgent
            If no agent with the given URI exists in the registry.
        InvalidLifecycleTransition
            If the transition from the agent's current state to
            *target_state* is not in :attr:`VALID_TRANSITIONS`.
        """
        aid = await self._registry.get_aid(agent_uri)
        if aid is None:
            raise InvalidAgent(
                f"No agent found for URI: {agent_uri}",
                details={"agent_uri": str(agent_uri)},
            )

        current_state = aid.lifecycle_state
        if (current_state, target_state) not in self.VALID_TRANSITIONS:
            raise InvalidLifecycleTransition(
                agent_uri=str(agent_uri),
                from_state=current_state,
                to_state=target_state,
            )

        await self._registry.update_lifecycle(agent_uri, target_state)
        return target_state

    async def activate(self, agent_uri: AgentURI) -> None:
        """Activate a pending agent (PENDING -> ACTIVE).

        This is triggered by the first successful authentication or
        an explicit admin action (spec Section 6.2).

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI of the agent to activate.
        """
        await self.transition(agent_uri, LifecycleState.ACTIVE)

    async def suspend(self, agent_uri: AgentURI) -> None:
        """Suspend an active agent (ACTIVE -> SUSPENDED).

        Per spec Section 6.3, rule 2: when an agent transitions to
        ``SUSPENDED``, all outstanding delegation tokens issued by
        that agent MUST be invalidated immediately.

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI of the agent to suspend.
        """
        await self.transition(agent_uri, LifecycleState.SUSPENDED)

    async def revoke(self, agent_uri: AgentURI) -> None:
        """Revoke an agent (ACTIVE/SUSPENDED -> REVOKED).

        This is an **irreversible** operation.  Per spec Section 6.3,
        rule 3: the ``REVOKED`` state is terminal.  A new AID with a
        new ``instance_id`` must be issued if the agent software needs
        to operate again.

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI of the agent to revoke.
        """
        await self.transition(agent_uri, LifecycleState.REVOKED)

    async def reactivate(self, agent_uri: AgentURI) -> None:
        """Reactivate a suspended agent (SUSPENDED -> ACTIVE).

        Per spec Section 6.2, reactivation requires explicit
        administrator action.

        Parameters
        ----------
        agent_uri:
            The ``nl://`` URI of the agent to reactivate.
        """
        await self.transition(agent_uri, LifecycleState.ACTIVE)
