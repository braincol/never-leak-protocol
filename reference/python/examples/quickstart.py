#!/usr/bin/env python3
"""NL Protocol quickstart -- Hello World example.

Demonstrates the core workflow of the Never-Leak Protocol:

1. Create an NL Provider with in-memory stores.
2. Register an agent (AID).
3. Add a secret to the secret store.
4. Create a scope grant authorising the agent.
5. Process an action request through the provider pipeline.
6. Inspect the response.

Run:
    python examples/quickstart.py
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from nl_protocol import NLProvider, NLProviderConfig
from nl_protocol.core.interfaces import (
    InMemoryAgentRegistry,
    InMemoryAuditStore,
    InMemoryScopeGrantStore,
    InMemorySecretStore,
)
from nl_protocol.core.types import (
    AID,
    ActionPayload,
    ActionRequest,
    ActionType,
    AgentURI,
    ScopeConditions,
    ScopeGrant,
    SecretRef,
    SecretValue,
    TrustLevel,
)


async def main() -> None:
    # -- Step 1: Create the provider with in-memory stores -------------------
    secret_store = InMemorySecretStore()
    provider = NLProvider(
        config=NLProviderConfig(provider_id="quickstart-provider"),
        secret_store=secret_store,
        agent_registry=InMemoryAgentRegistry(),
        scope_grant_store=InMemoryScopeGrantStore(),
        audit_store=InMemoryAuditStore(),
    )
    print("[1] Provider created: quickstart-provider")

    # -- Step 2: Register an agent -------------------------------------------
    agent_uri = AgentURI("nl://acme/web-deployer/1.0.0")
    aid = AID(
        agent_uri=agent_uri,
        display_name="ACME Web Deployer",
        vendor="acme",
        version="1.0.0",
        scope=["api/*"],
        trust_level=TrustLevel.L1,
        capabilities=[ActionType.HTTP, ActionType.EXEC],
        expires_at=datetime.now(UTC) + timedelta(days=365),
    )
    await provider.register_agent(aid)
    print(f"[2] Agent registered: {agent_uri}")

    # -- Step 3: Add a secret ------------------------------------------------
    # The secret store is populated out-of-band (admin action).
    # Agents never see the raw value -- only opaque {{nl:...}} handles.
    secret_store.put(
        SecretRef("api/DEPLOY_TOKEN"),
        SecretValue("sk-live-abc123-NEVER-SHOWN-TO-AGENTS"),
    )
    print("[3] Secret added: api/DEPLOY_TOKEN")

    # -- Step 4: Create a scope grant ----------------------------------------
    grant = ScopeGrant(
        grant_id=str(uuid.uuid4()),
        agent_uri=agent_uri,
        secret="api/*",
        actions=[ActionType.HTTP],
        conditions=ScopeConditions(
            valid_until=datetime.now(UTC) + timedelta(hours=8),
            max_uses=50,
        ),
    )
    grant_id = await provider.create_scope_grant(grant)
    print(f"[4] Scope grant created: {grant_id}")

    # -- Step 5: Process an action request -----------------------------------
    request = ActionRequest(
        agent_uri=agent_uri,
        action=ActionPayload(
            type=ActionType.HTTP,
            template="curl -H 'Authorization: Bearer {{nl:api/DEPLOY_TOKEN}}' https://api.example.com/deploy",
            purpose="Trigger production deployment via API",
            timeout=30,
        ),
    )
    response = await provider.process_action(request)

    # -- Step 6: Inspect the response ----------------------------------------
    print(f"[5] Action response status: {response.status}")
    if response.result:
        print(f"    exit_code: {response.result.exit_code}")
        print(f"    stdout:    {response.result.stdout}")
    if response.audit_ref:
        print(f"    audit_ref: {response.audit_ref}")
    if response.error:
        print(f"    error:     [{response.error.code}] {response.error.message}")

    print("\nDone. The agent never saw the secret value.")


if __name__ == "__main__":
    asyncio.run(main())
