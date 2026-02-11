"""NL Protocol error-code hierarchy.

Every error code defined in Chapter 08, Section 6 of the NL Protocol
specification (v1.0) is represented as a concrete exception class.

Hierarchy
---------
::

    NLProtocolError
    +-- AuthenticationError   (NL-E1xx)
    +-- AuthorizationError    (NL-E2xx)
    +-- ExecutionError        (NL-E3xx)
    +-- DefenseError          (NL-E4xx)
    +-- AuditError            (NL-E5xx)
    +-- DetectionError        (NL-E6xx)
    +-- FederationError       (NL-E7xx)
    +-- TransportError        (NL-E8xx)

Usage
-----
Raise concrete subclasses directly::

    raise SecretNotFound("production/DB_PASSWORD")

Catch by category::

    try:
        ...
    except AuthorizationError:
        # handles NoScopeGrant, ScopeExpired, UseLimitExceeded, etc.
        ...
"""
from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class NLProtocolError(Exception):
    """Base exception for all NL Protocol errors.

    Attributes
    ----------
    code : str
        NL Protocol error code, e.g. ``"NL-E100"``.
    http_status : int
        Recommended HTTP status code for this error.
    message : str
        Human-readable description (MUST NOT contain secret values).
    details : dict[str, Any]
        Machine-readable context specific to the error instance.
    resolution : str
        Suggested action for the caller.
    """

    code: str = "NL-E000"
    http_status: int = 500
    message: str = "Unknown NL Protocol error"
    resolution: str = ""

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        resolution: str | None = None,
    ) -> None:
        self.details: dict[str, Any] = details or {}
        if message is not None:
            self.message = message
        if resolution is not None:
            self.resolution = resolution
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the error to the wire-protocol error format (Section 6.2)."""
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.details:
            payload["detail"] = self.details
        if self.resolution:
            payload["resolution"] = self.resolution
        payload["doc_url"] = f"https://nlprotocol.org/docs/errors/{self.code}"
        return {"error": payload}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# ===================================================================
# Category base classes
# ===================================================================

class AuthenticationError(NLProtocolError):
    """NL-E1xx -- Authentication and identity errors (Chapter 01)."""

    code = "NL-E1XX"
    http_status = 401


class AuthorizationError(NLProtocolError):
    """NL-E2xx -- Authorisation and scope errors (Chapter 02)."""

    code = "NL-E2XX"
    http_status = 403


class ExecutionError(NLProtocolError):
    """NL-E3xx -- Action execution errors (Chapters 02, 03)."""

    code = "NL-E3XX"
    http_status = 500


class DefenseError(NLProtocolError):
    """NL-E4xx -- Pre-execution defense and interception errors (Chapter 04)."""

    code = "NL-E4XX"
    http_status = 403


class AuditError(NLProtocolError):
    """NL-E5xx -- Audit integrity errors (Chapter 05)."""

    code = "NL-E5XX"
    http_status = 500


class DetectionError(NLProtocolError):
    """NL-E6xx -- Attack detection and threat errors (Chapter 06)."""

    code = "NL-E6XX"
    http_status = 403


class FederationError(NLProtocolError):
    """NL-E7xx -- Federation and delegation errors (Chapter 07)."""

    code = "NL-E7XX"
    http_status = 403


class TransportError(NLProtocolError):
    """NL-E8xx -- Transport and protocol errors (Chapter 08)."""

    code = "NL-E8XX"
    http_status = 400


# ===================================================================
# NL-E1xx  Authentication & Identity Errors
# ===================================================================

class InvalidAgent(AuthenticationError):
    """NL-E100 -- The agent identity could not be verified."""

    code = "NL-E100"
    http_status = 401
    message = "Agent identity could not be verified"
    resolution = (
        "Verify the agent credential is correct and the agent is registered."
    )


class ExpiredAttestation(AuthenticationError):
    """NL-E101 -- The agent's attestation JWT has expired."""

    code = "NL-E101"
    http_status = 401
    message = "Agent attestation JWT has expired"
    resolution = (
        "Obtain a fresh attestation JWT from the platform provider."
    )


class TrustLevelInsufficient(AuthenticationError):
    """NL-E102 -- Trust level does not meet the minimum required."""

    code = "NL-E102"
    http_status = 403
    message = "Agent trust level is insufficient for the requested operation"
    resolution = (
        "Upgrade the agent's trust level by obtaining vendor attestation "
        "or third-party certification."
    )


class AgentSuspended(AuthenticationError):
    """NL-E103 -- The agent is suspended and cannot perform actions."""

    code = "NL-E103"
    http_status = 403
    message = "Agent is suspended"
    resolution = "Contact the administrator to reactivate the agent."


class AgentRevoked(AuthenticationError):
    """NL-E104 -- The agent is permanently revoked."""

    code = "NL-E104"
    http_status = 403
    message = "Agent has been revoked"
    resolution = "Register a new agent instance."


class AIDExpired(AuthenticationError):
    """NL-E105 -- The Agent Identity Document has expired."""

    code = "NL-E105"
    http_status = 401
    message = "Agent identity document has expired"
    resolution = "Re-register or renew the agent identity."


class AttestationSignatureInvalid(AuthenticationError):
    """NL-E106 -- Attestation JWT signature verification failed."""

    code = "NL-E106"
    http_status = 401
    message = "Attestation JWT signature is invalid"
    resolution = (
        "Ensure the attestation was signed by the correct platform "
        "provider key."
    )


class ReplayDetectedAuth(AuthenticationError):
    """NL-E107 -- Attestation JWT ``jti`` has already been used."""

    code = "NL-E107"
    http_status = 401
    message = "Replay detected: attestation JWT has already been used"
    resolution = "Generate a new attestation with a fresh jti."


class CapabilityNotGranted(AuthenticationError):
    """NL-E108 -- The requested action type is not in the AID capabilities."""

    code = "NL-E108"
    http_status = 403
    message = "Requested capability is not granted to this agent"
    resolution = (
        "Request the capability be added to the agent's registration."
    )


# ===================================================================
# NL-E2xx  Authorization & Scope Errors
# ===================================================================

class NoScopeGrant(AuthorizationError):
    """NL-E200 -- No active scope grant covers the request."""

    code = "NL-E200"
    http_status = 403
    message = "No active scope grant covers the requested secret and action"
    resolution = "Request a scope grant from the administrator."


class ScopeExpired(AuthorizationError):
    """NL-E201 -- The applicable scope grant has expired."""

    code = "NL-E201"
    http_status = 403
    message = "Scope grant has expired"
    resolution = (
        "Request a new scope grant with an updated validity window."
    )


class UseLimitExceeded(AuthorizationError):
    """NL-E202 -- max_uses on the scope grant has been reached."""

    code = "NL-E202"
    http_status = 429
    message = "Scope grant usage limit has been exceeded"
    resolution = (
        "Request a new scope grant or contact the administrator to "
        "increase the limit."
    )


class EnvironmentRestricted(AuthorizationError):
    """NL-E203 -- The target environment is not covered by the grant."""

    code = "NL-E203"
    http_status = 403
    message = "Scope grant does not include the target environment"
    resolution = (
        "Request a scope grant that includes the target environment."
    )


class HumanApprovalRequired(AuthorizationError):
    """NL-E204 -- The scope grant requires human approval."""

    code = "NL-E204"
    http_status = 403
    message = "Human approval is required for this action"
    resolution = (
        "Request human approval through the approval workflow."
    )


class ContextMismatch(AuthorizationError):
    """NL-E205 -- Session context does not match scope grant constraints."""

    code = "NL-E205"
    http_status = 403
    message = "Session context does not match scope grant constraints"
    resolution = (
        "Verify you are operating in the correct repository, branch, "
        "or workspace."
    )


class ConcurrentLimit(AuthorizationError):
    """NL-E206 -- max_concurrent limit on the scope grant has been reached."""

    code = "NL-E206"
    http_status = 403
    message = "Concurrent action limit has been reached"
    resolution = (
        "Wait for in-flight actions to complete before submitting new ones."
    )


# ===================================================================
# NL-E3xx  Action Execution Errors
# ===================================================================

class UnknownActionType(ExecutionError):
    """NL-E300 -- Unrecognised action type."""

    code = "NL-E300"
    http_status = 400
    message = "Unknown action type"
    resolution = (
        "Use one of the supported action types: exec, template, "
        "inject_stdin, inject_tempfile, sdk_proxy, delegate."
    )


class InvalidPlaceholder(ExecutionError):
    """NL-E301 -- Malformed ``{{nl:...}}`` placeholder."""

    code = "NL-E301"
    http_status = 400
    message = "Invalid {{nl:...}} placeholder syntax"
    resolution = "Verify the placeholder syntax matches the ABNF grammar."


class SecretNotFound(ExecutionError):
    """NL-E302 -- The referenced secret does not exist."""

    code = "NL-E302"
    http_status = 404
    message = "Secret not found"
    resolution = (
        "Verify the secret name and path. Use a fully qualified reference "
        "to avoid ambiguity."
    )


class ExecutionTimeout(ExecutionError):
    """NL-E303 -- The action execution exceeded its timeout."""

    code = "NL-E303"
    http_status = 408
    message = "Action execution timed out"
    resolution = (
        "Increase the timeout or optimise the command. "
        "Maximum timeout is 600000 ms (10 minutes)."
    )


class AmbiguousReference(ExecutionError):
    """NL-E304 -- A secret reference matched multiple secrets."""

    code = "NL-E304"
    http_status = 400
    message = "Ambiguous secret reference"
    resolution = (
        "Use a categorised, scoped, or fully qualified reference "
        "to disambiguate."
    )


class ProviderUnavailable(ExecutionError):
    """NL-E305 -- External secret provider is unreachable."""

    code = "NL-E305"
    http_status = 502
    message = "External secret provider is unavailable"
    resolution = (
        "Retry after a delay. Check the status of the external "
        "secret provider."
    )


class ProviderNotConfigured(ExecutionError):
    """NL-E306 -- The cross-provider reference targets an unconfigured provider."""

    code = "NL-E306"
    http_status = 400
    message = "Secret provider is not configured"
    resolution = (
        "Configure the secret provider bridge or use a local "
        "secret reference."
    )


class IsolationFailure(ExecutionError):
    """NL-E307 -- The isolated execution environment could not be created."""

    code = "NL-E307"
    http_status = 500
    message = "Isolation environment could not be established"
    resolution = "This is an internal error. Contact the system administrator."


class SanitizationFailure(ExecutionError):
    """NL-E308 -- Output sanitisation failed; result withheld."""

    code = "NL-E308"
    http_status = 500
    message = (
        "Output sanitisation failed; response withheld to prevent "
        "potential secret leakage"
    )
    resolution = (
        "This is an internal error. The action may have succeeded, "
        "but the result cannot be safely returned."
    )


# ===================================================================
# NL-E4xx  Defense & Interception Errors
# ===================================================================

class ActionBlocked(DefenseError):
    """NL-E400 -- Action blocked by a deny rule."""

    code = "NL-E400"
    http_status = 403
    message = "Action blocked by pre-execution defense deny rule"
    resolution = (
        "Review the deny rule and use the NL Protocol-compliant "
        "alternative described in the detail.alternative field."
    )


class EvasionDetected(DefenseError):
    """NL-E401 -- Evasion attempt detected."""

    code = "NL-E401"
    http_status = 403
    message = "Evasion attempt detected"
    resolution = (
        "Use the action-based access model (Chapter 02). "
        "Do not attempt to circumvent security controls."
    )


class InterceptorUnavailable(DefenseError):
    """NL-E402 -- Pre-execution interceptor is down and fail-closed is active."""

    code = "NL-E402"
    http_status = 403
    message = "Pre-execution interceptor is unavailable (fail-closed)"
    resolution = (
        "The interceptor must be restored before actions can be "
        "processed. Contact the administrator."
    )


# ===================================================================
# NL-E5xx  Audit Errors
# ===================================================================

class ChainIntegrityFailure(AuditError):
    """NL-E500 -- Audit hash chain integrity violation detected."""

    code = "NL-E500"
    http_status = 500
    message = "Audit hash chain integrity failure detected"
    resolution = (
        "Initiate a full chain verification (Chapter 05, Section 5.1). "
        "Contact the security team."
    )


class AuditQueryDenied(AuditError):
    """NL-E501 -- The requester is not authorised to query the audit log."""

    code = "NL-E501"
    http_status = 403
    message = "Audit query denied"
    resolution = (
        "Audit queries must be performed by authorised administrators."
    )


class AuditWriteFailure(AuditError):
    """NL-E502 -- Audit entry could not be written; action blocked."""

    code = "NL-E502"
    http_status = 500
    message = (
        "Audit entry could not be written; action blocked to maintain "
        "audit integrity"
    )
    resolution = (
        "This is an internal error. The audit subsystem must be "
        "operational for actions to proceed."
    )


# ===================================================================
# NL-E6xx  Detection & Threat Errors
# ===================================================================

class ThreatLevelExceeded(DetectionError):
    """NL-E600 -- Cumulative threat score exceeds the action threshold."""

    code = "NL-E600"
    http_status = 403
    message = "Agent threat score exceeds the threshold for this action"
    resolution = (
        "The agent's behaviour has triggered anomaly detection. "
        "Reduce the threat score by operating within normal parameters, "
        "or contact the administrator for review."
    )


class AgentRevokedByDetection(DetectionError):
    """NL-E601 -- Agent automatically revoked by attack-detection system."""

    code = "NL-E601"
    http_status = 403
    message = "Agent has been automatically revoked by attack detection"
    resolution = (
        "A new agent instance must be registered after security review."
    )


class HoneypotTriggered(DetectionError):
    """NL-E602 -- Honeypot token was accessed."""

    code = "NL-E602"
    http_status = 403
    message = "Honeypot token accessed; potential exfiltration attempt"
    resolution = (
        "This event has been flagged as a security incident. "
        "Contact the security team."
    )


# ===================================================================
# NL-E7xx  Federation & Delegation Errors
# ===================================================================

class UnknownTrustDomain(FederationError):
    """NL-E700 -- The target trust domain is not a registered partner."""

    code = "NL-E700"
    http_status = 404
    message = "Unknown trust domain"
    resolution = (
        "Establish a federation agreement with the target organisation "
        "(Chapter 07, Section 6.2)."
    )


class FederationAgreementExpired(FederationError):
    """NL-E701 -- Federation agreement with the target has expired."""

    code = "NL-E701"
    http_status = 403
    message = "Federation agreement has expired"
    resolution = "Renew the federation agreement."


class DelegationSubsetViolation(FederationError):
    """NL-E702 -- Delegation scope is not a strict subset of the delegator's."""

    code = "NL-E702"
    http_status = 403
    message = (
        "Delegation scope is not a strict subset of the delegator's scope"
    )
    resolution = (
        "Narrow the delegation scope to fit within your current permissions."
    )


class DelegationDepthExceeded(FederationError):
    """NL-E703 -- Maximum delegation chain depth reached."""

    code = "NL-E703"
    http_status = 403
    message = "Maximum delegation chain depth has been reached"
    resolution = (
        "The delegate must execute the action directly, without "
        "further delegation."
    )


class InvalidDelegationToken(FederationError):
    """NL-E704 -- Delegation token is malformed or has an invalid signature."""

    code = "NL-E704"
    http_status = 400
    message = "Invalid delegation token"
    resolution = (
        "Verify the delegation token was issued by a valid, "
        "registered agent."
    )


class DelegationTokenExpired(FederationError):
    """NL-E705 -- Delegation token has expired."""

    code = "NL-E705"
    http_status = 403
    message = "Delegation token has expired"
    resolution = "Request a new delegation token from the delegator."


class DelegationUseLimit(FederationError):
    """NL-E706 -- Delegation token max_uses limit reached."""

    code = "NL-E706"
    http_status = 429
    message = "Delegation token usage limit has been reached"
    resolution = "Request a new delegation token."


class DelegationTokenRevoked(FederationError):
    """NL-E707 -- Delegation token has been revoked."""

    code = "NL-E707"
    http_status = 403
    message = "Delegation token has been revoked"
    resolution = "Request a new delegation token."


class FederationPartnerUnavailable(FederationError):
    """NL-E708 -- Federated partner NL Provider is not reachable."""

    code = "NL-E708"
    http_status = 502
    message = "Federation partner NL Provider is unavailable"
    resolution = (
        "Retry after a delay. Check the partner's NL Provider status."
    )


class FederationActionNotAllowed(FederationError):
    """NL-E709 -- Action type not allowed by the federation agreement."""

    code = "NL-E709"
    http_status = 403
    message = (
        "Requested action type is not permitted by the federation agreement"
    )
    resolution = "Review the federation agreement's allowed_action_types."


# ===================================================================
# NL-E8xx  Transport & Protocol Errors
# ===================================================================

class MalformedMessage(TransportError):
    """NL-E800 -- Request body is not valid JSON or violates the envelope schema."""

    code = "NL-E800"
    http_status = 400
    message = "Malformed message"
    resolution = (
        "Verify the message is valid JSON and includes all required "
        "envelope fields (nl_version, message_type, message_id, "
        "timestamp, payload)."
    )


class VersionMismatch(TransportError):
    """NL-E801 -- Requested NL Protocol version is not supported."""

    code = "NL-E801"
    http_status = 400
    message = "NL Protocol version is not supported"
    resolution = (
        "Use a supported NL Protocol version. Query the discovery "
        "endpoint to determine supported versions."
    )


class ReplayDetectedTransport(TransportError):
    """NL-E802 -- A message with this message_id has already been processed."""

    code = "NL-E802"
    http_status = 409
    message = "Replay detected: message_id has already been processed"
    resolution = (
        "Generate a new message_id (UUID v4) for each unique request."
    )


class MessageTooLarge(TransportError):
    """NL-E803 -- Request body exceeds the maximum allowed size."""

    code = "NL-E803"
    http_status = 413
    message = "Message exceeds maximum allowed size"
    resolution = (
        "Reduce the message size. The maximum is advertised in the "
        "discovery document."
    )


class UnsupportedMediaType(TransportError):
    """NL-E804 -- Content-Type header is not acceptable."""

    code = "NL-E804"
    http_status = 415
    message = "Unsupported media type"
    resolution = (
        "Set the Content-Type header to application/nl-protocol+json."
    )


class InvalidTimestamp(TransportError):
    """NL-E805 -- Message timestamp is too far in the future or past."""

    code = "NL-E805"
    http_status = 400
    message = "Message timestamp is outside the acceptable window"
    resolution = (
        "Synchronise the client clock using NTP. Timestamps must be "
        "within 5 minutes of server time."
    )


class UnknownMessageType(TransportError):
    """NL-E806 -- Unrecognised message_type field."""

    code = "NL-E806"
    http_status = 400
    message = "Unknown message type"
    resolution = (
        "Use a valid message type from the NL Protocol specification "
        "Section 3.4."
    )


# ---------------------------------------------------------------------------
# Lookup helper
# ---------------------------------------------------------------------------

_CODE_MAP: dict[str, type[NLProtocolError]] = {
    cls.code: cls
    for cls in [
        # E1xx
        InvalidAgent,
        ExpiredAttestation,
        TrustLevelInsufficient,
        AgentSuspended,
        AgentRevoked,
        AIDExpired,
        AttestationSignatureInvalid,
        ReplayDetectedAuth,
        CapabilityNotGranted,
        # E2xx
        NoScopeGrant,
        ScopeExpired,
        UseLimitExceeded,
        EnvironmentRestricted,
        HumanApprovalRequired,
        ContextMismatch,
        ConcurrentLimit,
        # E3xx
        UnknownActionType,
        InvalidPlaceholder,
        SecretNotFound,
        ExecutionTimeout,
        AmbiguousReference,
        ProviderUnavailable,
        ProviderNotConfigured,
        IsolationFailure,
        SanitizationFailure,
        # E4xx
        ActionBlocked,
        EvasionDetected,
        InterceptorUnavailable,
        # E5xx
        ChainIntegrityFailure,
        AuditQueryDenied,
        AuditWriteFailure,
        # E6xx
        ThreatLevelExceeded,
        AgentRevokedByDetection,
        HoneypotTriggered,
        # E7xx
        UnknownTrustDomain,
        FederationAgreementExpired,
        DelegationSubsetViolation,
        DelegationDepthExceeded,
        InvalidDelegationToken,
        DelegationTokenExpired,
        DelegationUseLimit,
        DelegationTokenRevoked,
        FederationPartnerUnavailable,
        FederationActionNotAllowed,
        # E8xx
        MalformedMessage,
        VersionMismatch,
        ReplayDetectedTransport,
        MessageTooLarge,
        UnsupportedMediaType,
        InvalidTimestamp,
        UnknownMessageType,
    ]
}


def error_from_code(code: str, message: str | None = None) -> NLProtocolError:
    """Instantiate the correct exception class for an NL Protocol error code.

    Parameters
    ----------
    code:
        An NL Protocol error code such as ``"NL-E302"``.
    message:
        Optional override for the default error message.

    Raises
    ------
    KeyError
        If *code* is not a recognised NL Protocol error code.
    """
    cls = _CODE_MAP[code]
    return cls(message) if message else cls()
