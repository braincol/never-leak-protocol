#!/usr/bin/env python3
"""NL Protocol full pipeline -- 7-level demonstration.

Walks through every layer of the NL Protocol reference implementation:

  Level 1  Agent Identity       -- register agent, lifecycle management
  Level 2  Action-Based Access  -- scope grants, action processing
  Level 4  Pre-Execution Defense -- deny rule engine (integrated in provider)
  Level 5  Audit Integrity      -- SHA-256 hash-chain audit records
  Level 6  Attack Detection     -- threat scoring (integrated in provider)
  Level 7  Federation           -- delegation tokens

Run:
    python examples/full_pipeline.py
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from nl_protocol import (
    ChainManager,
    DelegationManager,
    DenyRuleEngine,
    NLProvider,
    NLProviderConfig,
    ThreatScorer,
    verify_chain,
)
from nl_protocol.core.interfaces import (
    InMemoryAgentRegistry,
    InMemoryAuditStore,
    InMemoryDelegationStore,
    InMemoryNonceStore,
    InMemoryScopeGrantStore,
    InMemorySecretStore,
)
from nl_protocol.core.types import (
    AID,
    ActionPayload,
    ActionRequest,
    ActionType,
    AgentURI,
    DelegationScope,
    ScopeConditions,
    ScopeGrant,
    SecretRef,
    SecretValue,
    TrustLevel,
)
from nl_protocol.detection.threat_scoring import AttackType, Incident

DIVIDER = "-" * 60


async def main() -> None:
    # ================================================================
    # Setup: create stores and provider (all 7 levels wired)
    # ================================================================
    secret_store = InMemorySecretStore()
    scope_grant_store = InMemoryScopeGrantStore()
    audit_store = InMemoryAuditStore()
    delegation_store = InMemoryDelegationStore()

    provider = NLProvider(
        config=NLProviderConfig(provider_id="full-pipeline-demo"),
        secret_store=secret_store,
        agent_registry=InMemoryAgentRegistry(),
        scope_grant_store=scope_grant_store,
        audit_store=audit_store,
        nonce_store=InMemoryNonceStore(),
        delegation_store=delegation_store,
    )

    # ================================================================
    # Level 1 -- Agent Identity
    # ================================================================
    print(DIVIDER)
    print("LEVEL 1: Agent Identity")
    print(DIVIDER)

    orchestrator_uri = AgentURI("nl://acme.corp/orchestrator/2.0.0")
    orchestrator_aid = AID(
        agent_uri=orchestrator_uri,
        display_name="ACME Orchestrator",
        vendor="acme.corp",
        version="2.0.0",
        scope=["api/*", "db/*"],
        trust_level=TrustLevel.L2,
        capabilities=[ActionType.HTTP, ActionType.EXEC, ActionType.DELEGATE],
        expires_at=datetime.now(UTC) + timedelta(days=90),
    )
    await provider.register_agent(orchestrator_aid)
    print(f"  Registered: {orchestrator_uri}")
    print(f"  Trust level: {orchestrator_aid.trust_level}")
    print(f"  Capabilities: {[c.value for c in orchestrator_aid.capabilities]}")

    # ================================================================
    # Level 2 -- Action-Based Access (secrets + grants + processing)
    # ================================================================
    print(f"\n{DIVIDER}")
    print("LEVEL 2: Action-Based Access")
    print(DIVIDER)

    # Populate secrets (admin operation)
    secret_store.put(SecretRef("api/GITHUB_TOKEN"), SecretValue("ghp_xxxx"))
    secret_store.put(SecretRef("db/POSTGRES_URL"), SecretValue("postgres://..."))
    print("  Secrets loaded: api/GITHUB_TOKEN, db/POSTGRES_URL")

    # Create a scope grant
    grant = ScopeGrant(
        grant_id=str(uuid.uuid4()),
        agent_uri=orchestrator_uri,
        secret="api/*",
        actions=[ActionType.HTTP, ActionType.EXEC],
        conditions=ScopeConditions(
            valid_until=datetime.now(UTC) + timedelta(hours=24),
            max_uses=100,
        ),
    )
    await provider.create_scope_grant(grant)
    print("  Scope grant created: secret='api/*', max_uses=100")

    # Process a legitimate action (passes all 7 levels)
    request = ActionRequest(
        agent_uri=orchestrator_uri,
        action=ActionPayload(
            type=ActionType.HTTP,
            template=(
                "curl -H 'Authorization: token {{nl:api/GITHUB_TOKEN}}' "
                "https://api.github.com/repos"
            ),
            purpose="List repositories via GitHub API",
            timeout=30,
        ),
    )
    response = await provider.process_action(request)
    print(f"  Action response: status={response.status}")
    print(f"  Audit ref: {response.audit_ref}")

    # ================================================================
    # Level 4 -- Pre-Execution Defense (deny rules)
    # ================================================================
    print(f"\n{DIVIDER}")
    print("LEVEL 4: Pre-Execution Defense")
    print(DIVIDER)

    # The deny engine is integrated into the provider pipeline.
    # Let's also demonstrate it standalone:
    deny_engine = DenyRuleEngine()
    print(f"  Loaded {len(deny_engine.standard_rules)} standard deny rules")

    # Check a safe template -- should pass
    safe_template = (
        "curl -H 'Authorization: Bearer {{nl:api/GITHUB_TOKEN}}' "
        "https://api.example.com"
    )
    try:
        deny_engine.check(safe_template)
        print(f"  PASS: '{safe_template[:50]}...'")
    except Exception as exc:
        print(f"  BLOCKED: {exc}")

    # Check a dangerous template -- should be blocked
    dangerous_template = "cat .env"
    try:
        deny_engine.check(dangerous_template)
        print(f"  PASS: '{dangerous_template}'")
    except Exception as exc:
        print(f"  BLOCKED: '{dangerous_template}' -> {type(exc).__name__}")

    # Provider integration: dangerous template is blocked in pipeline
    blocked_request = ActionRequest(
        agent_uri=orchestrator_uri,
        action=ActionPayload(
            type=ActionType.EXEC,
            template="cat .env",
            purpose="Try to read .env (should be blocked)",
        ),
    )
    blocked_response = await provider.process_action(blocked_request)
    print(f"  Pipeline block: status={blocked_response.status}, "
          f"code={blocked_response.error.code if blocked_response.error else 'N/A'}")

    # ================================================================
    # Level 5 -- Audit Integrity (hash chain)
    # ================================================================
    print(f"\n{DIVIDER}")
    print("LEVEL 5: Audit Integrity")
    print(DIVIDER)

    # The provider already maintains a SHA-256 hash chain.
    # Let's also demonstrate ChainManager standalone:
    standalone_audit = InMemoryAuditStore()
    chain = ChainManager(store=standalone_audit, agent_uri=orchestrator_uri)

    # Initialise the genesis entry
    genesis = await chain.initialise()
    print(f"  Genesis record: hash={genesis.record_hash[:30]}...")

    # Append a record for the action we processed
    record = await chain.append(
        action_type="http",
        target="api/GITHUB_TOKEN",
        result="success",
        secrets_used=["api/GITHUB_TOKEN"],
    )
    print(f"  Appended record #{chain.sequence}: "
          f"hash={record.record_hash[:30]}...")

    # Verify the chain
    verification = verify_chain(chain.records)
    print(
        f"  Chain verification: valid={verification.valid}, "
        f"entries={verification.entries_verified}"
    )

    # Show provider's integrated chain
    if provider.chain_manager:
        print(f"  Provider chain: {provider.chain_manager.sequence} records, "
              f"head={provider.chain_manager.head_hash[:30]}...")

    # ================================================================
    # Level 6 -- Attack Detection (threat scoring)
    # ================================================================
    print(f"\n{DIVIDER}")
    print("LEVEL 6: Attack Detection")
    print(DIVIDER)

    # The provider integrates threat scoring. Check the orchestrator's score:
    score = provider.get_threat_score(orchestrator_uri)
    if score:
        print(f"  Orchestrator threat score: {score.int_score} ({score.level.value})")

    # The blocked action above should have increased the threat score
    threat_response = provider.get_threat_response(orchestrator_uri)
    if threat_response:
        print(f"  Automated response: {threat_response.level.value}")
        print(f"    Actions: {[a.value for a in threat_response.actions]}")

    # Demonstrate standalone threat scoring with a rogue agent
    scorer = ThreatScorer()
    rogue_uri = "nl://unknown.net/rogue-agent/0.1.0"
    now = datetime.now(UTC)
    scorer.record_incident(Incident(
        attack_type=AttackType.T1,
        timestamp=now,
        agent_uri=rogue_uri,
        evidence={"command": "vault get production/DB_PASSWORD"},
    ))
    scorer.record_incident(Incident(
        attack_type=AttackType.T3,
        timestamp=now,
        agent_uri=rogue_uri,
        evidence={"command": "echo secret"},
    ))

    rogue_score = scorer.compute_score(rogue_uri)
    print(f"  Rogue agent threat score: "
          f"{rogue_score.int_score} ({rogue_score.level.value})")
    print("  Incident factors:")
    for factor in rogue_score.factors:
        print(f"    - {factor['attack_type']}: "
              f"severity={factor['base_severity']}, "
              f"contribution={factor['contribution']:.4f}")

    # ================================================================
    # Level 7 -- Federation (delegation tokens)
    # ================================================================
    print(f"\n{DIVIDER}")
    print("LEVEL 7: Federation (Delegation)")
    print(DIVIDER)

    delegation_mgr = DelegationManager(
        delegation_store=delegation_store,
        scope_evaluator=provider.scope_evaluator,
        max_delegation_depth=3,
    )

    # The orchestrator delegates a narrow scope to a sub-agent
    sub_agent_uri = AgentURI("nl://acme.corp/deploy-worker/1.0.0")
    delegation_scope = DelegationScope(
        secrets=["api/GITHUB_TOKEN"],
        actions=[ActionType.HTTP],
    )

    token = await delegation_mgr.create_token(
        parent_grant=grant,
        child_agent_uri=sub_agent_uri,
        scope=delegation_scope,
        ttl=timedelta(minutes=5),
    )
    print(f"  Delegation token created: {token.token_id}")
    print(f"    issuer:  {token.issuer}")
    print(f"    subject: {token.subject}")
    print(f"    depth:   {token.current_depth}/{token.max_delegation_depth}")
    print(f"    expires: {token.expires_at.isoformat()}")
    print(f"    secrets: {token.scope.secrets}")

    print(f"\n{DIVIDER}")
    print("All 7 levels demonstrated successfully.")
    print(DIVIDER)


if __name__ == "__main__":
    asyncio.run(main())
