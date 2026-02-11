"""NL Protocol abstract interfaces and in-memory implementations.

This module defines the *structural* interfaces (``typing.Protocol``) for
all backend stores consumed by the NL Protocol engine, plus lightweight
in-memory implementations suitable for testing and local development.

Every Protocol class is decorated with ``@runtime_checkable`` so that
``isinstance`` checks work at run-time in addition to static analysis.

In-memory implementations are **not** thread-safe.  Production deployments
MUST substitute persistent, concurrency-safe backends.
"""
from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from nl_protocol.core.errors import (
    InvalidAgent,
    SecretNotFound,
)
from nl_protocol.core.types import (
    AID,
    AgentURI,
    AuditRecord,
    DelegationToken,
    LifecycleState,
    ScopeGrant,
    SecretRef,
    SecretValue,
)

# ===================================================================
# Protocol (interface) definitions
# ===================================================================

@runtime_checkable
class SecretStore(Protocol):
    """Backend for secret resolution.

    Implementations MUST never return secret *values* to any component
    outside the isolation boundary.
    """

    async def get(self, ref: SecretRef) -> SecretValue:
        """Retrieve the current value for *ref*.

        Raises :class:`SecretNotFound` if the reference does not exist.
        """
        ...

    async def exists(self, ref: SecretRef) -> bool:
        """Return ``True`` if *ref* exists in the store."""
        ...

    async def list_refs(self) -> list[SecretRef]:
        """List all known secret references (names only, NEVER values)."""
        ...


@runtime_checkable
class AgentRegistry(Protocol):
    """Backend for agent identity management (Chapter 01)."""

    async def get_aid(self, agent_uri: AgentURI) -> AID | None:
        """Return the AID for *agent_uri*, or ``None`` if not registered."""
        ...

    async def register(self, aid: AID) -> None:
        """Register a new agent.  Raises on duplicate ``agent_uri``."""
        ...

    async def update_lifecycle(
        self, agent_uri: AgentURI, state: LifecycleState
    ) -> None:
        """Transition the agent to *state*.

        Raises :class:`InvalidAgent` if the agent is not found.
        """
        ...

    async def list_agents(self) -> list[AID]:
        """Return all registered agents."""
        ...


@runtime_checkable
class ScopeGrantStore(Protocol):
    """Backend for scope-grant persistence (Chapter 02)."""

    async def get_grants(self, agent_uri: AgentURI) -> list[ScopeGrant]:
        """Return all grants (including revoked) for *agent_uri*."""
        ...

    async def create_grant(self, grant: ScopeGrant) -> None:
        """Persist a new scope grant."""
        ...

    async def revoke_grant(self, grant_id: str) -> None:
        """Mark the grant identified by *grant_id* as revoked."""
        ...

    async def increment_usage(self, grant_id: str) -> int:
        """Atomically increment ``current_uses`` and return the new count."""
        ...


@runtime_checkable
class AuditStore(Protocol):
    """Backend for the append-only audit chain (Chapter 05)."""

    async def append(self, record: AuditRecord) -> str:
        """Append *record* to the chain and return its ``record_id``."""
        ...

    async def get_latest(self) -> AuditRecord | None:
        """Return the most recent audit record, or ``None`` for an empty chain."""
        ...

    async def get_chain(
        self,
        from_hash: str | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """Return up to *limit* records starting from *from_hash*.

        If *from_hash* is ``None``, returns from the head of the chain.
        """
        ...


@runtime_checkable
class NonceStore(Protocol):
    """Backend for nonce / replay-prevention tracking."""

    async def check_and_store(self, nonce: str, expires_at: datetime) -> bool:
        """Return ``True`` if *nonce* is novel and was stored successfully.

        Return ``False`` if the nonce has already been seen (replay).
        """
        ...

    async def cleanup_expired(self) -> int:
        """Remove all expired nonces and return the number removed."""
        ...


@runtime_checkable
class DelegationStore(Protocol):
    """Backend for delegation-token persistence (Chapter 07)."""

    async def store_token(self, token: DelegationToken) -> None:
        """Persist a delegation token."""
        ...

    async def get_token(self, token_id: str) -> DelegationToken | None:
        """Return the token, or ``None`` if not found."""
        ...

    async def revoke_token(self, token_id: str) -> None:
        """Mark the token as revoked (sets ``signature`` to ``None`` as a
        simple revocation marker for the in-memory implementation)."""
        ...

    async def get_children(self, token_id: str) -> list[DelegationToken]:
        """Return all tokens whose issuer delegated from *token_id*."""
        ...


# ===================================================================
# In-memory implementations (testing / development)
# ===================================================================

class InMemorySecretStore:
    """In-memory secret store for testing and development.

    Secrets are held in a plain ``dict``.  This implementation is
    NOT suitable for production use.
    """

    def __init__(self) -> None:
        self._secrets: dict[str, SecretValue] = {}

    # -- mutation helpers (not part of the Protocol) --------------------

    def put(self, ref: SecretRef, value: SecretValue) -> None:
        """Store a secret (test helper -- not part of the Protocol)."""
        self._secrets[str(ref)] = value

    def remove(self, ref: SecretRef) -> None:
        """Remove a secret (test helper)."""
        self._secrets.pop(str(ref), None)

    # -- Protocol implementation ---------------------------------------

    async def get(self, ref: SecretRef) -> SecretValue:
        """Retrieve the current value for *ref*."""
        key = str(ref)
        if key not in self._secrets:
            raise SecretNotFound(f"Secret not found: {key}")
        return self._secrets[key]

    async def exists(self, ref: SecretRef) -> bool:
        """Return ``True`` if *ref* exists."""
        return str(ref) in self._secrets

    async def list_refs(self) -> list[SecretRef]:
        """List all known secret references."""
        return [SecretRef(k) for k in sorted(self._secrets)]


class InMemoryAgentRegistry:
    """In-memory agent registry for testing and development."""

    def __init__(self) -> None:
        self._agents: dict[str, AID] = {}

    async def get_aid(self, agent_uri: AgentURI) -> AID | None:
        """Return the AID for *agent_uri*, or ``None``."""
        return self._agents.get(str(agent_uri))

    async def register(self, aid: AID) -> None:
        """Register a new agent.

        Raises :class:`ValueError` if the agent_uri is already registered.
        """
        key = str(aid.agent_uri)
        if key in self._agents:
            raise ValueError(f"Agent already registered: {key}")
        self._agents[key] = aid

    async def update_lifecycle(
        self, agent_uri: AgentURI, state: LifecycleState
    ) -> None:
        """Transition the agent to *state*."""
        key = str(agent_uri)
        aid = self._agents.get(key)
        if aid is None:
            raise InvalidAgent(f"Agent not found: {key}")
        aid.lifecycle_state = state

    async def list_agents(self) -> list[AID]:
        """Return all registered agents."""
        return list(self._agents.values())


class InMemoryScopeGrantStore:
    """In-memory scope-grant store for testing and development."""

    def __init__(self) -> None:
        self._grants: dict[str, ScopeGrant] = {}

    async def get_grants(self, agent_uri: AgentURI) -> list[ScopeGrant]:
        """Return all grants for *agent_uri*."""
        uri = str(agent_uri)
        return [g for g in self._grants.values() if str(g.agent_uri) == uri]

    async def create_grant(self, grant: ScopeGrant) -> None:
        """Persist a new scope grant."""
        self._grants[grant.grant_id] = grant

    async def revoke_grant(self, grant_id: str) -> None:
        """Mark the grant as revoked."""
        grant = self._grants.get(grant_id)
        if grant is not None:
            grant.revoked = True

    async def increment_usage(self, grant_id: str) -> int:
        """Increment ``current_uses`` and return the new count."""
        grant = self._grants.get(grant_id)
        if grant is None:
            raise ValueError(f"Grant not found: {grant_id}")
        grant.conditions.current_uses += 1
        return grant.conditions.current_uses


class InMemoryAuditStore:
    """In-memory audit store for testing and development.

    Records are stored in append order.  No actual hash-chain
    verification is performed by this implementation; that is the
    responsibility of the audit engine.
    """

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._index: dict[str, int] = {}  # record_id -> list index
        self._hash_index: dict[str, int] = {}  # record_hash -> list index

    async def append(self, record: AuditRecord) -> str:
        """Append *record* and return its ``record_id``."""
        idx = len(self._records)
        self._records.append(record)
        self._index[record.record_id] = idx
        self._hash_index[record.record_hash] = idx
        return record.record_id

    async def get_latest(self) -> AuditRecord | None:
        """Return the most recent record, or ``None``."""
        if not self._records:
            return None
        return self._records[-1]

    async def get_chain(
        self,
        from_hash: str | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """Return up to *limit* records starting from *from_hash*."""
        if from_hash is None:
            return list(self._records[:limit])
        start = self._hash_index.get(from_hash)
        if start is None:
            return []
        return list(self._records[start : start + limit])


class InMemoryNonceStore:
    """In-memory nonce store for replay-prevention testing."""

    def __init__(self) -> None:
        self._nonces: dict[str, datetime] = {}  # nonce -> expires_at

    async def check_and_store(self, nonce: str, expires_at: datetime) -> bool:
        """Return ``True`` if *nonce* is novel; ``False`` on replay."""
        if nonce in self._nonces:
            return False
        self._nonces[nonce] = expires_at
        return True

    async def cleanup_expired(self) -> int:
        """Remove expired nonces and return the count removed."""
        now = datetime.now(UTC)
        expired = [n for n, exp in self._nonces.items() if exp <= now]
        for n in expired:
            del self._nonces[n]
        return len(expired)


class InMemoryDelegationStore:
    """In-memory delegation-token store for testing and development."""

    def __init__(self) -> None:
        self._tokens: dict[str, DelegationToken] = {}
        self._revoked: set[str] = set()
        # parent_token_id -> list of child token_ids
        self._children: dict[str, list[str]] = {}

    async def store_token(self, token: DelegationToken) -> None:
        """Persist a delegation token."""
        self._tokens[token.token_id] = copy.deepcopy(token)

    async def get_token(self, token_id: str) -> DelegationToken | None:
        """Return the token, or ``None`` if not found or revoked."""
        if token_id in self._revoked:
            return None
        return self._tokens.get(token_id)

    async def revoke_token(self, token_id: str) -> None:
        """Mark the token as revoked.

        Also recursively revokes all child tokens (cascade revocation
        as required by Chapter 07).
        """
        if token_id not in self._tokens:
            return
        self._revoked.add(token_id)
        # Cascade to children
        for child_id in self._children.get(token_id, []):
            await self.revoke_token(child_id)

    async def get_children(self, token_id: str) -> list[DelegationToken]:
        """Return all child tokens delegated from *token_id*."""
        child_ids = self._children.get(token_id, [])
        result: list[DelegationToken] = []
        for cid in child_ids:
            tok = self._tokens.get(cid)
            if tok is not None and cid not in self._revoked:
                result.append(tok)
        return result

    def register_child(self, parent_token_id: str, child_token_id: str) -> None:
        """Register a parent-child relationship (test helper)."""
        self._children.setdefault(parent_token_id, []).append(child_token_id)
