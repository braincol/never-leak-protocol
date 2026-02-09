"""JWT-based platform attestation.

Implements NL Protocol Specification v1.0, Chapter 01 -- Section 8.
Provides attestation token creation and verification for ES256 (ECDSA
P-256) and EdDSA (Ed25519) algorithms.
"""
from __future__ import annotations

from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from nl_protocol.core.errors import (
    AttestationSignatureInvalid,
    ExpiredAttestation,
)
from nl_protocol.core.types import (
    AID,
    AgentURI,
)

# ---------------------------------------------------------------------------
# Type aliases for key types
# ---------------------------------------------------------------------------

PrivateKey = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
PublicKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey


class AttestationService:
    """Handles agent attestation via signed JWT tokens.

    This service implements the attestation creation and verification
    flows described in Chapter 01, Section 8.  It supports the two
    RECOMMENDED asymmetric algorithms:

    * **ES256** -- ECDSA with the NIST P-256 curve and SHA-256.
    * **EdDSA** -- Ed25519 (RFC 8032).

    Usage
    -----
    Creating an attestation::

        service = AttestationService()
        token = service.create_attestation(aid, private_key, algorithm="ES256")

    Verifying an attestation::

        payload = service.verify_attestation(
            token, public_key, expected_agent_uri=aid.agent_uri
        )
    """

    SUPPORTED_ALGORITHMS: tuple[str, ...] = ("ES256", "EdDSA")
    """Algorithms permitted for attestation signing per spec Section 8.2."""

    # ------------------------------------------------------------------
    # Token creation
    # ------------------------------------------------------------------

    def create_attestation(
        self,
        aid: AID,
        private_key: PrivateKey,
        algorithm: str = "ES256",
    ) -> str:
        """Create a signed JWT attestation token for an agent.

        The token payload contains all claims required by the spec
        (Section 8.2.2): ``sub``, ``iss``, ``iat``, ``exp``, plus
        NL-specific claims (``nl_version``, ``trust_level``,
        ``capabilities``, ``scope``).

        Parameters
        ----------
        aid:
            The Agent Identity Document to attest.
        private_key:
            The private key used to sign the JWT.  Must correspond to
            the chosen *algorithm*.
        algorithm:
            One of ``"ES256"`` or ``"EdDSA"``.  Defaults to
            ``"ES256"`` (the spec RECOMMENDED default).

        Returns
        -------
        str
            The compact-serialized JWT string.

        Raises
        ------
        AttestationSignatureInvalid
            If *algorithm* is not one of the supported algorithms.
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise AttestationSignatureInvalid(
                f"Unsupported attestation algorithm: '{algorithm}'. "
                f"Supported: {', '.join(self.SUPPORTED_ALGORITHMS)}.",
                details={"algorithm": algorithm},
            )

        payload: dict[str, Any] = {
            "sub": str(aid.agent_uri),
            "iss": aid.vendor,
            "iat": int(aid.created_at.timestamp()),
            "exp": int(aid.expires_at.timestamp()),
            "nl_version": "1.0",
            "trust_level": aid.trust_level.value,
            "capabilities": [cap.value for cap in aid.capabilities],
            "scope": aid.scope,
        }

        token: str = jwt.encode(payload, private_key, algorithm=algorithm)
        return token

    # ------------------------------------------------------------------
    # Token verification
    # ------------------------------------------------------------------

    def verify_attestation(
        self,
        token: str,
        public_key: PublicKey,
        expected_agent_uri: AgentURI | None = None,
    ) -> dict[str, Any]:
        """Verify an attestation token and return the decoded payload.

        Performs the verification steps defined in spec Section 8.3:

        1. Decode and verify the JWT signature.
        2. Require the standard claims: ``sub``, ``iss``, ``iat``, ``exp``.
        3. If *expected_agent_uri* is provided, assert that the ``sub``
           claim matches it exactly.

        Parameters
        ----------
        token:
            The compact-serialized JWT to verify.
        public_key:
            The public key used to verify the signature.
        expected_agent_uri:
            If given, the ``sub`` claim in the token MUST match this
            URI.  Enables caller-side binding of a token to a specific
            agent.

        Returns
        -------
        dict[str, Any]
            The decoded JWT payload on successful verification.

        Raises
        ------
        ExpiredAttestation
            If the token's ``exp`` claim is in the past.
        AttestationSignatureInvalid
            If the signature is invalid, required claims are missing,
            or the ``sub`` claim does not match *expected_agent_uri*.
        """
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                public_key,
                algorithms=list(self.SUPPORTED_ALGORITHMS),
                options={"require": ["sub", "iss", "iat", "exp"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise ExpiredAttestation(
                "The attestation JWT has expired.",
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise AttestationSignatureInvalid(
                f"Attestation verification failed: {exc}",
            ) from exc

        # Verify agent URI binding
        if expected_agent_uri is not None:
            token_sub = payload.get("sub")
            if token_sub != str(expected_agent_uri):
                raise AttestationSignatureInvalid(
                    f"Agent URI mismatch in attestation: "
                    f"token sub='{token_sub}', "
                    f"expected='{expected_agent_uri}'.",
                    details={
                        "token_sub": token_sub,
                        "expected_agent_uri": str(expected_agent_uri),
                    },
                )

        return payload
