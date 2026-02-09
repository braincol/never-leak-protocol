"""Never-Leak Protocol -- Reference Implementation.

The open standard for AI agent secret governance.
Agents request actions, not secrets.

Levels
------
1. Agent Identity (:mod:`nl_protocol.identity`)
2. Action-Based Access (:mod:`nl_protocol.access`)
3. Execution Isolation (:mod:`nl_protocol.isolation`)
4. Pre-Execution Defense (:mod:`nl_protocol.defense`)
5. Audit Integrity (:mod:`nl_protocol.audit`)
6. Attack Detection & Response (:mod:`nl_protocol.detection`)
7. Cross-Agent Trust & Federation (:mod:`nl_protocol.federation`)
8. Wire Protocol & Transport (:mod:`nl_protocol.wire`)
"""
from __future__ import annotations

__version__ = "1.0.0a1"

# ---------------------------------------------------------------------------
# Level 0 -- Core types, errors, config, interfaces
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Level 2 -- Action-Based Access
# ---------------------------------------------------------------------------
from nl_protocol.access import (
    ActionValidator,
    OutputSanitizer,
    PlaceholderResolver,
    PolicyDecision,
    PolicyEvaluator,
    ScopeEvaluator,
)

# ---------------------------------------------------------------------------
# Level 5 -- Audit Integrity
# ---------------------------------------------------------------------------
from nl_protocol.audit import (
    ChainManager,
    ChainVerificationResult,
    ForkDetectionResult,
    canonical_json,
    compute_hash,
    create_audit_record,
    sign_record,
    verify_chain,
    verify_signature,
)
from nl_protocol.core.config import NLProviderConfig
from nl_protocol.core.errors import (
    AuditError,
    # Category bases
    AuthenticationError,
    AuthorizationError,
    DefenseError,
    DetectionError,
    ExecutionError,
    FederationError,
    NLProtocolError,
    TransportError,
)
from nl_protocol.core.types import (
    AID,
    ActionError,
    ActionPayload,
    ActionRequest,
    ActionResponse,
    ActionResult,
    ActionType,
    AgentURI,
    AuditRecord,
    DelegationScope,
    DelegationToken,
    LifecycleState,
    ScopeConditions,
    ScopeGrant,
    SecretRef,
    SecretValue,
    ThreatLevel,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# Level 4 -- Pre-Execution Defense
# ---------------------------------------------------------------------------
from nl_protocol.defense import (
    CommandValidator,
    DenyMatch,
    DenyRule,
    DenyRuleEngine,
    EvasionFinding,
    PatternEngine,
)

# ---------------------------------------------------------------------------
# Level 6 -- Attack Detection & Response
# ---------------------------------------------------------------------------
from nl_protocol.detection import (
    AgentProfile,
    AttackType,
    BehavioralBaseline,
    HoneypotEntry,
    HoneypotManager,
    Incident,
    ResponseAction,
    ResponseActionType,
    ResponseEngine,
    ThreatScore,
    ThreatScorer,
)

# ---------------------------------------------------------------------------
# Level 7 -- Cross-Agent Trust & Federation
# ---------------------------------------------------------------------------
from nl_protocol.federation import (
    CascadeEngine,
    DelegationManager,
    DelegationVerifier,
    NonceManager,
    TokenBinding,
)

# ---------------------------------------------------------------------------
# Level 1 -- Agent Identity
# ---------------------------------------------------------------------------
from nl_protocol.identity import (
    AIDManager,
    AttestationService,
    InvalidLifecycleTransition,
    LifecycleManager,
    TrustLevelManager,
)

# ---------------------------------------------------------------------------
# Level 3 -- Execution Isolation
# ---------------------------------------------------------------------------
from nl_protocol.isolation import (
    EnvironmentManager,
    IsolatedExecutor,
    ResourceLimits,
    SandboxConfig,
    SecureMemory,
)

# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
from nl_protocol.provider import NLProvider

# ---------------------------------------------------------------------------
# Level 8 -- Wire Protocol & Transport
# ---------------------------------------------------------------------------
from nl_protocol.wire import (
    NL_CONTENT_TYPE,
    NL_PROTOCOL_VERSION,
    DiscoveryDocument,
    HTTPTransport,
    MessageEnvelope,
    NDJSONReader,
    NDJSONWriter,
    StdioTransport,
    create_discovery_document,
    create_http_handler,
    format_error_response,
    negotiate_version,
    parse_message,
    serialize_discovery,
    serialize_message,
    validate_content_type,
)

__all__ = [
    # Meta
    "__version__",
    # Core types & enums
    "AgentURI",
    "SecretRef",
    "SecretValue",
    "TrustLevel",
    "LifecycleState",
    "ActionType",
    "ThreatLevel",
    "AID",
    "ScopeGrant",
    "ScopeConditions",
    "ActionRequest",
    "ActionPayload",
    "ActionResponse",
    "ActionResult",
    "ActionError",
    "DelegationToken",
    "DelegationScope",
    "AuditRecord",
    # Config
    "NLProviderConfig",
    # Error hierarchy
    "NLProtocolError",
    "AuthenticationError",
    "AuthorizationError",
    "ExecutionError",
    "DefenseError",
    "AuditError",
    "DetectionError",
    "FederationError",
    "TransportError",
    # Level 1 -- Identity
    "AIDManager",
    "AttestationService",
    "LifecycleManager",
    "TrustLevelManager",
    "InvalidLifecycleTransition",
    # Level 2 -- Access
    "PlaceholderResolver",
    "ScopeEvaluator",
    "OutputSanitizer",
    "PolicyEvaluator",
    "PolicyDecision",
    "ActionValidator",
    # Level 3 -- Isolation
    "IsolatedExecutor",
    "EnvironmentManager",
    "SecureMemory",
    "SandboxConfig",
    "ResourceLimits",
    # Level 4 -- Defense
    "DenyRuleEngine",
    "DenyRule",
    "DenyMatch",
    "CommandValidator",
    "EvasionFinding",
    "PatternEngine",
    # Level 5 -- Audit
    "ChainManager",
    "canonical_json",
    "create_audit_record",
    "compute_hash",
    "sign_record",
    "verify_signature",
    "verify_chain",
    "ChainVerificationResult",
    "ForkDetectionResult",
    # Level 6 -- Detection
    "AttackType",
    "ThreatScore",
    "Incident",
    "ThreatScorer",
    "BehavioralBaseline",
    "AgentProfile",
    "ResponseAction",
    "ResponseActionType",
    "ResponseEngine",
    "HoneypotEntry",
    "HoneypotManager",
    # Level 7 -- Federation
    "DelegationManager",
    "DelegationVerifier",
    "NonceManager",
    "CascadeEngine",
    "TokenBinding",
    # Level 8 -- Wire
    "NL_PROTOCOL_VERSION",
    "NL_CONTENT_TYPE",
    "MessageEnvelope",
    "format_error_response",
    "parse_message",
    "serialize_message",
    "negotiate_version",
    "validate_content_type",
    "NDJSONReader",
    "NDJSONWriter",
    "StdioTransport",
    "HTTPTransport",
    "create_http_handler",
    "DiscoveryDocument",
    "create_discovery_document",
    "serialize_discovery",
    # Orchestrator
    "NLProvider",
]
