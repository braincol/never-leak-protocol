#!/usr/bin/env python3
"""NL Protocol attestation and lifecycle example.

Demonstrates:
1. Generating an ES256 key pair (ECDSA P-256).
2. Creating a signed JWT attestation token for an agent.
3. Verifying the attestation token.
4. Walking through the agent lifecycle state machine:
       ACTIVE -> SUSPENDED -> ACTIVE -> REVOKED

Run:
    python examples/attestation_example.py
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ec

from nl_protocol import AttestationService, LifecycleManager
from nl_protocol.core.interfaces import InMemoryAgentRegistry
from nl_protocol.core.types import (
    AID,
    ActionType,
    AgentURI,
    TrustLevel,
)

DIVIDER = "-" * 60


async def main() -> None:
    # ================================================================
    # Step 1: Generate an ES256 key pair
    # ================================================================
    print(DIVIDER)
    print("Step 1: Generate ES256 key pair")
    print(DIVIDER)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    print("  Generated ECDSA P-256 key pair")

    # ================================================================
    # Step 2: Register an agent and create an attestation JWT
    # ================================================================
    print(f"\n{DIVIDER}")
    print("Step 2: Create attestation JWT")
    print(DIVIDER)

    agent_uri = AgentURI("nl://acme.corp/data-analyst/1.0.0")
    aid = AID(
        agent_uri=agent_uri,
        display_name="ACME Data Analyst",
        vendor="acme.corp",
        version="1.0.0",
        scope=["analytics/*"],
        trust_level=TrustLevel.L2,
        capabilities=[ActionType.READ, ActionType.HTTP],
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )

    service = AttestationService()
    token = service.create_attestation(aid, private_key, algorithm="ES256")
    print(f"  Agent: {agent_uri}")
    print(f"  JWT (first 80 chars): {token[:80]}...")
    print(f"  JWT length: {len(token)} bytes")

    # ================================================================
    # Step 3: Verify the attestation JWT
    # ================================================================
    print(f"\n{DIVIDER}")
    print("Step 3: Verify attestation JWT")
    print(DIVIDER)

    payload = service.verify_attestation(
        token,
        public_key,
        expected_agent_uri=agent_uri,
    )
    print("  Verified successfully!")
    print(f"  sub:          {payload['sub']}")
    print(f"  iss:          {payload['iss']}")
    print(f"  trust_level:  {payload['trust_level']}")
    print(f"  capabilities: {payload['capabilities']}")
    print(f"  scope:        {payload['scope']}")

    # ================================================================
    # Step 4: Lifecycle transitions
    # ================================================================
    print(f"\n{DIVIDER}")
    print("Step 4: Lifecycle transitions")
    print(DIVIDER)

    registry = InMemoryAgentRegistry()
    await registry.register(aid)
    lifecycle = LifecycleManager(registry)

    # Current state is ACTIVE (default for newly registered agents)
    current = (await registry.get_aid(agent_uri))
    assert current is not None
    print(f"  Initial state: {current.lifecycle_state.value}")

    # ACTIVE -> SUSPENDED
    await lifecycle.suspend(agent_uri)
    current = await registry.get_aid(agent_uri)
    assert current is not None
    print(f"  After suspend: {current.lifecycle_state.value}")

    # SUSPENDED -> ACTIVE (reactivate)
    await lifecycle.reactivate(agent_uri)
    current = await registry.get_aid(agent_uri)
    assert current is not None
    print(f"  After reactivate: {current.lifecycle_state.value}")

    # ACTIVE -> REVOKED (terminal -- no way back)
    await lifecycle.revoke(agent_uri)
    current = await registry.get_aid(agent_uri)
    assert current is not None
    print(f"  After revoke: {current.lifecycle_state.value}")

    # Demonstrate that REVOKED is terminal
    try:
        await lifecycle.reactivate(agent_uri)
        print("  ERROR: should not reach here")
    except Exception as exc:
        print(f"  Reactivate after revoke -> {type(exc).__name__}")
        print(f"    {exc}")

    print(f"\n{DIVIDER}")
    print("Attestation and lifecycle demo complete.")
    print(DIVIDER)


if __name__ == "__main__":
    asyncio.run(main())
