"""Level 6 -- Attack Detection & Response conformance tests.

Verifies Chapter 06 requirements: threat score calculation with T1-T11
attack types, ThreatLevel boundaries, behavioral baseline (EWMA),
honeypot access triggering immediate RED, and automated response tiers.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nl_protocol.core.types import SecretRef, ThreatLevel
from nl_protocol.detection.behavioral import BehavioralBaseline
from nl_protocol.detection.honeypot import HoneypotManager
from nl_protocol.detection.response import ResponseActionType, ResponseEngine
from nl_protocol.detection.threat_scoring import (
    AttackType,
    Incident,
    ThreatScorer,
)

# ===================================================================
# Section 2 -- Attack type taxonomy
# ===================================================================

class TestAttackTypeTaxonomy:
    """Spec Section 2: 11 attack types T1-T11 with base severities."""

    def test_MUST_define_11_attack_types(self) -> None:
        """There MUST be exactly 11 attack types (T1 through T11)."""
        assert len(AttackType) == 11

    def test_MUST_have_identifier_and_severity(self) -> None:
        """Each attack type MUST have an identifier and severity."""
        for at in AttackType:
            assert at.identifier.startswith("T")
            assert at.severity > 0

    def test_MUST_have_base_severity_normalized(self) -> None:
        """base_severity MUST be normalized to 0.0 -- 1.0."""
        for at in AttackType:
            assert 0.0 < at.base_severity <= 1.0

    def test_T1_MUST_be_direct_secret_request(self) -> None:
        """T1 MUST represent direct secret request with severity 20."""
        assert AttackType.T1.identifier == "T1"
        assert AttackType.T1.severity == 20

    def test_T9_MUST_be_network_exfiltration(self) -> None:
        """T9 MUST represent network exfiltration with severity 80."""
        assert AttackType.T9.identifier == "T9"
        assert AttackType.T9.severity == 80


# ===================================================================
# Section 3.2 -- ThreatLevel boundaries
# ===================================================================

class TestThreatLevelBoundaries:
    """Spec Section 3.2: ThreatLevel score ranges."""

    def test_MUST_classify_score_0_as_GREEN(self) -> None:
        """Score 0 MUST be GREEN."""
        assert ThreatLevel.from_score(0) == ThreatLevel.GREEN

    def test_MUST_classify_score_29_as_GREEN(self) -> None:
        """Score 29 MUST be GREEN (boundary)."""
        assert ThreatLevel.from_score(29) == ThreatLevel.GREEN

    def test_MUST_classify_score_30_as_YELLOW(self) -> None:
        """Score 30 MUST be YELLOW (boundary)."""
        assert ThreatLevel.from_score(30) == ThreatLevel.YELLOW

    def test_MUST_classify_score_59_as_YELLOW(self) -> None:
        """Score 59 MUST be YELLOW."""
        assert ThreatLevel.from_score(59) == ThreatLevel.YELLOW

    def test_MUST_classify_score_60_as_ORANGE(self) -> None:
        """Score 60 MUST be ORANGE (boundary)."""
        assert ThreatLevel.from_score(60) == ThreatLevel.ORANGE

    def test_MUST_classify_score_89_as_ORANGE(self) -> None:
        """Score 89 MUST be ORANGE."""
        assert ThreatLevel.from_score(89) == ThreatLevel.ORANGE

    def test_MUST_classify_score_90_as_RED(self) -> None:
        """Score 90 MUST be RED (boundary)."""
        assert ThreatLevel.from_score(90) == ThreatLevel.RED

    def test_MUST_classify_score_100_as_RED(self) -> None:
        """Score 100 MUST be RED."""
        assert ThreatLevel.from_score(100) == ThreatLevel.RED


# ===================================================================
# Section 3.3 -- Threat score computation
# ===================================================================

class TestThreatScoreComputation:
    """Spec Section 3.3: threat score computation formula."""

    def test_MUST_return_zero_for_no_incidents(self) -> None:
        """No incidents MUST produce a score of 0 (GREEN)."""
        scorer = ThreatScorer()
        score = scorer.compute_score("nl://test/agent/1.0.0")
        assert score.int_score == 0
        assert score.level == ThreatLevel.GREEN

    def test_MUST_increase_score_on_incident(self) -> None:
        """Recording an incident MUST increase the threat score."""
        scorer = ThreatScorer()
        now = datetime.now(UTC)
        incident = Incident(
            attack_type=AttackType.T1,
            timestamp=now,
            agent_uri="nl://test/agent/1.0.0",
        )
        score = scorer.record_incident(incident)
        assert score.int_score > 0

    def test_MUST_cap_score_at_100(self) -> None:
        """Cumulative score MUST NOT exceed 100."""
        scorer = ThreatScorer()
        now = datetime.now(UTC)
        # Record many high-severity incidents
        for _ in range(20):
            scorer.record_incident(Incident(
                attack_type=AttackType.T9,
                timestamp=now,
                agent_uri="nl://test/agent/1.0.0",
            ))
        score = scorer.compute_score("nl://test/agent/1.0.0")
        assert score.int_score <= 100

    def test_MUST_include_factor_breakdown(self) -> None:
        """ThreatScore MUST include a factor breakdown for auditability."""
        scorer = ThreatScorer()
        now = datetime.now(UTC)
        scorer.record_incident(Incident(
            attack_type=AttackType.T3,
            timestamp=now,
            agent_uri="nl://test/agent/1.0.0",
        ))
        score = scorer.compute_score("nl://test/agent/1.0.0")
        assert len(score.factors) > 0
        assert "attack_type" in score.factors[0]

    def test_MUST_clear_incidents_on_reset(self) -> None:
        """Clearing incidents MUST reset the score to 0."""
        scorer = ThreatScorer()
        now = datetime.now(UTC)
        scorer.record_incident(Incident(
            attack_type=AttackType.T1,
            timestamp=now,
            agent_uri="nl://test/agent/1.0.0",
        ))
        scorer.clear_incidents("nl://test/agent/1.0.0")
        score = scorer.compute_score("nl://test/agent/1.0.0")
        assert score.int_score == 0


# ===================================================================
# Section 4.4 -- Behavioral baseline (EWMA)
# ===================================================================

class TestBehavioralBaseline:
    """Spec Section 4.4: EWMA-based behavioral baseline."""

    def test_MUST_accept_alpha_in_valid_range(self) -> None:
        """Alpha MUST be in (0, 0.3]."""
        baseline = BehavioralBaseline(alpha=0.1)
        assert baseline.alpha == 0.1

    def test_MUST_reject_alpha_out_of_range(self) -> None:
        """Alpha > 0.3 or <= 0 MUST be rejected."""
        with pytest.raises(ValueError):
            BehavioralBaseline(alpha=0.5)
        with pytest.raises(ValueError):
            BehavioralBaseline(alpha=0.0)

    def test_MUST_be_in_learning_mode_initially(self) -> None:
        """Baseline MUST start in learning mode."""
        baseline = BehavioralBaseline(alpha=0.1, learning_samples=10)
        assert baseline.is_learning is True

    def test_MUST_NOT_detect_anomalies_during_learning(self) -> None:
        """Anomaly detection MUST be suspended during the learning period."""
        baseline = BehavioralBaseline(alpha=0.1, learning_samples=100)
        for _ in range(5):
            baseline.update(10.0)
        # Even an extreme value should not trigger during learning
        assert baseline.is_anomaly(1000.0) is False

    def test_MUST_detect_anomaly_after_learning(self) -> None:
        """After learning, a high deviation MUST be detected as anomalous."""
        baseline = BehavioralBaseline(alpha=0.1, learning_samples=5)
        for _ in range(10):
            baseline.update(10.0)
        # Value far above mean should be anomalous
        assert baseline.is_anomaly(100.0) is True

    def test_MUST_update_mean_with_EWMA(self) -> None:
        """EWMA update MUST adjust the mean toward new observations."""
        baseline = BehavioralBaseline(alpha=0.1, learning_samples=1)
        baseline.update(100.0)
        initial_mean = baseline.mean
        baseline.update(200.0)
        # Mean should have moved toward 200
        assert baseline.mean > initial_mean


# ===================================================================
# Section 4.5 -- Honeypot (canary) tokens
# ===================================================================

class TestHoneypotTokens:
    """Spec Section 4.5: honeypot access MUST trigger immediate RED."""

    def test_MUST_register_honeypot(self) -> None:
        """Creating a honeypot MUST register it for detection."""
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("ADMIN_KEY", "admin")
        assert mgr.is_honeypot(ref) is True
        assert mgr.honeypot_count == 1

    def test_MUST_NOT_flag_non_honeypot(self) -> None:
        """Non-honeypot refs MUST NOT be flagged."""
        mgr = HoneypotManager()
        mgr.create_honeypot("ADMIN_KEY", "admin")
        assert mgr.is_honeypot(SecretRef("other/key")) is False

    def test_MUST_score_RED_on_honeypot_access(self) -> None:
        """Honeypot access MUST produce a score >= 80 (RED level)."""
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("ADMIN_KEY", "admin")
        score = mgr.on_access(ref, "nl://evil/agent/1.0.0")
        assert score.int_score >= 80
        assert score.level == ThreatLevel.RED

    def test_MUST_log_access_event(self) -> None:
        """Honeypot access MUST be recorded in the access log."""
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("ADMIN_KEY", "admin")
        mgr.on_access(ref, "nl://evil/agent/1.0.0")
        entry = mgr.get_entry(ref)
        assert entry is not None
        assert len(entry.access_log) == 1
        assert entry.access_log[0]["agent_uri"] == "nl://evil/agent/1.0.0"


# ===================================================================
# Section 5 -- Automated response tiers
# ===================================================================

class TestAutomatedResponse:
    """Spec Section 5: four-tier automated response system."""

    def test_MUST_return_LOG_for_GREEN(self) -> None:
        """GREEN response MUST include LOG action only."""
        engine = ResponseEngine()
        resp = engine.determine_response_for_score(10)
        assert resp.level == ThreatLevel.GREEN
        assert ResponseActionType.LOG in resp.actions

    def test_MUST_return_RATE_LIMIT_for_YELLOW(self) -> None:
        """YELLOW response MUST include RATE_LIMIT action."""
        engine = ResponseEngine()
        resp = engine.determine_response_for_score(40)
        assert resp.level == ThreatLevel.YELLOW
        assert ResponseActionType.RATE_LIMIT in resp.actions

    def test_MUST_return_BLOCK_ACTION_for_ORANGE(self) -> None:
        """ORANGE response MUST include BLOCK_ACTION."""
        engine = ResponseEngine()
        resp = engine.determine_response_for_score(70)
        assert resp.level == ThreatLevel.ORANGE
        assert ResponseActionType.BLOCK_ACTION in resp.actions

    def test_MUST_return_REVOKE_AID_for_RED(self) -> None:
        """RED response MUST include REVOKE_AID."""
        engine = ResponseEngine()
        resp = engine.determine_response_for_score(90)
        assert resp.level == ThreatLevel.RED
        assert ResponseActionType.REVOKE_AID in resp.actions
        assert ResponseActionType.BLOCK_ALL_ACTIONS in resp.actions
