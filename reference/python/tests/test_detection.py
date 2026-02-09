"""Comprehensive tests for NL Protocol Level 6 -- Attack Detection & Response.

Tests cover:
- Threat scoring with different attack types
- Score ranges and level mapping
- EWMA baseline calculation
- Anomaly detection
- All 4 response tiers
- Honeypot creation and access detection
- Agent profile building
- Score aggregation
"""
from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.core.types import SecretRef, ThreatLevel
from nl_protocol.detection import (
    AgentProfile,
    AttackType,
    BehavioralBaseline,
    HoneypotManager,
    Incident,
    ResponseActionType,
    ResponseEngine,
    ThreatScore,
    ThreatScorer,
    threat_level_from_score,
)

# ===================================================================
# Attack Type Enum
# ===================================================================


class TestAttackType:
    """Tests for the AttackType enum."""

    def test_all_eleven_types_exist(self) -> None:
        assert len(AttackType) == 11

    def test_t1_properties(self) -> None:
        t = AttackType.T1
        assert t.identifier == "T1"
        assert t.severity == 20
        assert t.description == "Direct Secret Request"
        assert t.base_severity == pytest.approx(0.20)

    def test_t2_properties(self) -> None:
        t = AttackType.T2
        assert t.identifier == "T2"
        assert t.severity == 30
        assert t.base_severity == pytest.approx(0.30)

    def test_t3_properties(self) -> None:
        assert AttackType.T3.severity == 40
        assert AttackType.T3.base_severity == pytest.approx(0.40)

    def test_t4_properties(self) -> None:
        assert AttackType.T4.severity == 35
        assert AttackType.T4.base_severity == pytest.approx(0.35)

    def test_t5_properties(self) -> None:
        assert AttackType.T5.severity == 40

    def test_t6_properties(self) -> None:
        assert AttackType.T6.severity == 50
        assert AttackType.T6.description == "Prompt Injection"

    def test_t7_properties(self) -> None:
        assert AttackType.T7.severity == 45
        assert AttackType.T7.description == "Social Engineering"

    def test_t8_properties(self) -> None:
        assert AttackType.T8.severity == 60
        assert AttackType.T8.description == "Secret in Output"

    def test_t9_properties(self) -> None:
        assert AttackType.T9.severity == 80
        assert AttackType.T9.description == "Network Exfiltration"

    def test_t10_properties(self) -> None:
        assert AttackType.T10.severity == 50
        assert AttackType.T10.description == "File System Access"

    def test_t11_properties(self) -> None:
        assert AttackType.T11.severity == 70
        assert AttackType.T11.description == "Memory Inspection"

    def test_categories(self) -> None:
        assert AttackType.T1.category == "direct_exfiltration"
        assert AttackType.T2.category == "direct_exfiltration"
        assert AttackType.T3.category == "evasion"
        assert AttackType.T4.category == "evasion"
        assert AttackType.T5.category == "evasion"
        assert AttackType.T6.category == "manipulation"
        assert AttackType.T7.category == "manipulation"
        assert AttackType.T8.category == "output_exfiltration"
        assert AttackType.T9.category == "output_exfiltration"
        assert AttackType.T10.category == "infrastructure"
        assert AttackType.T11.category == "infrastructure"


# ===================================================================
# Threat Level Mapping
# ===================================================================


class TestThreatLevelMapping:
    """Tests for threat_level_from_score (Section 3.2 ranges)."""

    def test_green_at_zero(self) -> None:
        assert threat_level_from_score(0) == ThreatLevel.GREEN

    def test_green_at_29(self) -> None:
        assert threat_level_from_score(29) == ThreatLevel.GREEN

    def test_yellow_at_30(self) -> None:
        assert threat_level_from_score(30) == ThreatLevel.YELLOW

    def test_yellow_at_59(self) -> None:
        assert threat_level_from_score(59) == ThreatLevel.YELLOW

    def test_orange_at_60(self) -> None:
        assert threat_level_from_score(60) == ThreatLevel.ORANGE

    def test_orange_at_79(self) -> None:
        assert threat_level_from_score(79) == ThreatLevel.ORANGE

    def test_red_at_80(self) -> None:
        assert threat_level_from_score(80) == ThreatLevel.RED

    def test_red_at_100(self) -> None:
        assert threat_level_from_score(100) == ThreatLevel.RED


# ===================================================================
# ThreatScore Dataclass
# ===================================================================


class TestThreatScore:
    """Tests for the ThreatScore frozen dataclass."""

    def test_basic_creation(self) -> None:
        ts = ThreatScore(
            score=0.5,
            int_score=50,
            level=ThreatLevel.YELLOW,
        )
        assert ts.score == 0.5
        assert ts.int_score == 50
        assert ts.level == ThreatLevel.YELLOW
        assert ts.factors == []

    def test_immutable(self) -> None:
        ts = ThreatScore(score=0.0, int_score=0, level=ThreatLevel.GREEN)
        with pytest.raises(AttributeError):
            ts.score = 1.0  # type: ignore[misc]

    def test_timestamp_auto_populated(self) -> None:
        ts = ThreatScore(score=0.0, int_score=0, level=ThreatLevel.GREEN)
        assert ts.timestamp is not None
        assert ts.timestamp.tzinfo is not None


# ===================================================================
# ThreatScorer
# ===================================================================


class TestThreatScorer:
    """Tests for the ThreatScorer engine."""

    def _make_incident(
        self,
        attack_type: AttackType = AttackType.T1,
        agent: str = "nl://test/agent/1.0",
        hours_ago: float = 0.0,
    ) -> Incident:
        ts = datetime.now(UTC) - timedelta(hours=hours_ago)
        return Incident(
            attack_type=attack_type,
            timestamp=ts,
            agent_uri=agent,
        )

    def test_no_incidents_returns_green(self) -> None:
        scorer = ThreatScorer()
        score = scorer.compute_score("nl://test/agent/1.0")
        assert score.int_score == 0
        assert score.level == ThreatLevel.GREEN

    def test_single_t1_recent(self) -> None:
        scorer = ThreatScorer()
        inc = self._make_incident(AttackType.T1, hours_ago=0.0)
        score = scorer.record_incident(inc)
        # T1 base severity = 0.20, recency ~1.0, frequency = 1 + log2(1) = 1.0
        # contribution ~ 0.20 * 100 = 20
        assert score.int_score == 20
        assert score.level == ThreatLevel.GREEN

    def test_single_t9_goes_red(self) -> None:
        scorer = ThreatScorer()
        inc = self._make_incident(AttackType.T9, hours_ago=0.0)
        score = scorer.record_incident(inc)
        # T9 base severity = 0.80, contribution ~ 80
        assert score.int_score == 80
        assert score.level == ThreatLevel.RED

    def test_spec_example_scoring(self) -> None:
        """Verify the scoring example from Section 3.4."""
        scorer = ThreatScorer()
        now = datetime.now(UTC)

        # Incident 1: T1, 1.5 hours ago
        inc1 = Incident(
            attack_type=AttackType.T1,
            timestamp=now - timedelta(hours=1.5),
            agent_uri="nl://example.com/deploy-bot/2.0.0",
        )
        # Incident 2: T3, 0.5 hours ago
        inc2 = Incident(
            attack_type=AttackType.T3,
            timestamp=now - timedelta(hours=0.5),
            agent_uri="nl://example.com/deploy-bot/2.0.0",
        )
        # Incident 3: T3, 0.25 hours ago (second T3)
        inc3 = Incident(
            attack_type=AttackType.T3,
            timestamp=now - timedelta(hours=0.25),
            agent_uri="nl://example.com/deploy-bot/2.0.0",
        )

        scorer.record_incident(inc1)
        scorer.record_incident(inc2)
        score = scorer.record_incident(inc3)

        # Per spec: raw sum = 0.186 + 0.390 + 0.790 = 1.366
        # Projected = min(100, round(1.366 * 100)) = 100
        # The exact values depend on rounding; score should be RED (>=80)
        assert score.int_score >= 80
        assert score.level == ThreatLevel.RED

    def test_recency_decay(self) -> None:
        """Older incidents contribute less than recent ones."""
        scorer = ThreatScorer()
        now = datetime.now(UTC)

        # Incident 100 hours ago -- heavily decayed
        inc = Incident(
            attack_type=AttackType.T1,
            timestamp=now - timedelta(hours=100),
            agent_uri="nl://test/agent/1.0",
        )
        scorer.record_incident(inc)
        score = scorer.compute_score("nl://test/agent/1.0", at_time=now)

        # e^(-0.05 * 100) = e^(-5) ~ 0.0067
        # contribution ~ 0.20 * 0.0067 * 1.0 * 100 ~ 0.13
        assert score.int_score < 5

    def test_frequency_multiplier(self) -> None:
        """Repeated incidents of the same type amplify the score."""
        scorer = ThreatScorer()
        agent = "nl://test/agent/1.0"

        # Record 4 T1 incidents
        for _ in range(4):
            scorer.record_incident(self._make_incident(AttackType.T1, agent=agent))

        score = scorer.compute_score(agent)
        # Frequency = 1 + log2(4) = 3.0
        # Each incident: 0.20 * ~1.0 * 3.0 = 0.6
        # Total: 4 * 0.6 * 100 = 240 -> capped at 100
        assert score.int_score == 100

    def test_score_capped_at_100(self) -> None:
        scorer = ThreatScorer()
        agent = "nl://test/agent/1.0"
        for _ in range(10):
            scorer.record_incident(self._make_incident(AttackType.T9, agent=agent))
        score = scorer.compute_score(agent)
        assert score.int_score == 100

    def test_clear_incidents_resets_score(self) -> None:
        scorer = ThreatScorer()
        agent = "nl://test/agent/1.0"
        scorer.record_incident(self._make_incident(AttackType.T9, agent=agent))
        scorer.clear_incidents(agent)
        score = scorer.compute_score(agent)
        assert score.int_score == 0

    def test_get_incidents_returns_copy(self) -> None:
        scorer = ThreatScorer()
        agent = "nl://test/agent/1.0"
        scorer.record_incident(self._make_incident(agent=agent))
        incidents = scorer.get_incidents(agent)
        assert len(incidents) == 1
        # Mutating the returned list does not affect internal state
        incidents.clear()
        assert len(scorer.get_incidents(agent)) == 1

    def test_factors_populated(self) -> None:
        scorer = ThreatScorer()
        inc = self._make_incident(AttackType.T3)
        score = scorer.record_incident(inc)
        assert len(score.factors) == 1
        factor = score.factors[0]
        assert factor["attack_type"] == "T3"
        assert factor["base_severity"] == pytest.approx(0.40)
        assert "recency" in factor
        assert "frequency_multiplier" in factor
        assert "contribution" in factor

    def test_multiple_agents_independent(self) -> None:
        scorer = ThreatScorer()
        scorer.record_incident(
            self._make_incident(AttackType.T9, agent="nl://agent-a/1.0")
        )
        score_b = scorer.compute_score("nl://agent-b/1.0")
        assert score_b.int_score == 0

    def test_custom_decay_lambda(self) -> None:
        scorer = ThreatScorer(decay_lambda=0.1)
        now = datetime.now(UTC)
        inc = Incident(
            attack_type=AttackType.T1,
            timestamp=now - timedelta(hours=10),
            agent_uri="nl://test/agent/1.0",
        )
        scorer.record_incident(inc)
        score = scorer.compute_score("nl://test/agent/1.0", at_time=now)
        # With lambda=0.1, recency = e^(-0.1 * 10) = e^(-1) ~ 0.368
        expected = round(0.20 * math.exp(-1.0) * 1.0 * 100)
        assert score.int_score == expected

    def test_mixed_attack_types(self) -> None:
        scorer = ThreatScorer()
        agent = "nl://test/agent/1.0"
        scorer.record_incident(self._make_incident(AttackType.T1, agent=agent))
        scorer.record_incident(self._make_incident(AttackType.T3, agent=agent))
        score = scorer.compute_score(agent)
        # T1 = 20, T3 = 40 => total ~60 => ORANGE
        assert score.int_score == 60
        assert score.level == ThreatLevel.ORANGE


# ===================================================================
# BehavioralBaseline
# ===================================================================


class TestBehavioralBaseline:
    """Tests for the EWMA BehavioralBaseline tracker."""

    def test_default_alpha(self) -> None:
        b = BehavioralBaseline()
        assert b.alpha == 0.1

    def test_alpha_validation_too_high(self) -> None:
        with pytest.raises(ValueError, match="alpha"):
            BehavioralBaseline(alpha=0.5)

    def test_alpha_validation_zero(self) -> None:
        with pytest.raises(ValueError, match="alpha"):
            BehavioralBaseline(alpha=0.0)

    def test_alpha_at_boundary(self) -> None:
        b = BehavioralBaseline(alpha=0.3)
        assert b.alpha == 0.3

    def test_initial_state(self) -> None:
        b = BehavioralBaseline()
        assert b.mean == 0.0
        assert b.variance == 0.0
        assert b.sample_count == 0
        assert b.is_learning

    def test_first_update_sets_mean(self) -> None:
        b = BehavioralBaseline()
        b.update(10.0)
        assert b.mean == 10.0
        assert b.variance == 0.0
        assert b.sample_count == 1

    def test_ewma_update_formula(self) -> None:
        """Verify the EWMA formula from Section 4.4.1."""
        b = BehavioralBaseline(alpha=0.1)
        b.update(100.0)  # mean = 100, variance = 0

        b.update(110.0)
        # new_mean = 0.1 * 110 + 0.9 * 100 = 101
        expected_mean = 101.0
        # new_variance = 0.1 * (110 - 101)^2 + 0.9 * 0 = 0.1 * 81 = 8.1
        expected_var = 8.1
        assert b.mean == pytest.approx(expected_mean)
        assert b.variance == pytest.approx(expected_var)

    def test_stddev_property(self) -> None:
        b = BehavioralBaseline(alpha=0.1)
        b.update(100.0)
        b.update(110.0)
        expected_var = 8.1
        assert b.stddev == pytest.approx(math.sqrt(expected_var))

    def test_learning_period_blocks_anomaly(self) -> None:
        b = BehavioralBaseline(learning_samples=5)
        for _i in range(4):
            b.update(10.0)
        # Still learning (4 < 5)
        assert b.is_learning
        assert not b.is_anomaly(1000.0)

    def test_anomaly_after_learning(self) -> None:
        b = BehavioralBaseline(learning_samples=5, alpha=0.1)
        for _ in range(5):
            b.update(10.0)
        assert not b.is_learning
        # Mean ~10, stddev should be small
        assert b.is_anomaly(100.0, threshold_sigma=2.0)

    def test_no_anomaly_within_range(self) -> None:
        b = BehavioralBaseline(learning_samples=3, alpha=0.2)
        b.update(10.0)
        b.update(12.0)
        b.update(11.0)
        # After learning, mean is ~10-11, value within range
        assert not b.is_anomaly(12.0, threshold_sigma=2.5)

    def test_deviation_magnitude(self) -> None:
        b = BehavioralBaseline(learning_samples=2, alpha=0.1)
        b.update(10.0)
        b.update(10.0)
        # After 2 samples with same value, stddev should be ~0
        # But let's add some variance
        b.update(20.0)  # This will create variance
        magnitude = b.deviation_magnitude(30.0)
        assert magnitude > 0.0

    def test_deviation_magnitude_during_learning(self) -> None:
        b = BehavioralBaseline(learning_samples=100)
        b.update(10.0)
        assert b.deviation_magnitude(1000.0) == 0.0

    def test_zero_stddev_anomaly(self) -> None:
        """When stddev is 0, any deviation from mean should flag."""
        b = BehavioralBaseline(learning_samples=2, alpha=0.1)
        b.update(10.0)
        b.update(10.0)
        # Mean = 10, variance ~= 0
        assert b.is_anomaly(10.1)
        assert not b.is_anomaly(10.0)

    def test_last_updated(self) -> None:
        b = BehavioralBaseline()
        assert b.last_updated is None
        b.update(10.0)
        assert b.last_updated is not None


# ===================================================================
# AgentProfile
# ===================================================================


class TestAgentProfile:
    """Tests for the per-agent AgentProfile."""

    def test_creation(self) -> None:
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        assert p.agent_uri == "nl://test/agent/1.0"
        assert p.actions_per_hour.sample_count == 0
        assert len(p.known_secrets) == 0

    def test_record_activity_updates_baselines(self) -> None:
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        p.record_activity(actions=10.0, unique_secrets=3.0)
        assert p.actions_per_hour.sample_count == 1
        assert p.secrets_per_day.sample_count == 1

    def test_record_activity_tracks_secrets(self) -> None:
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        p.record_activity(secret_names={"API_KEY", "DB_URL"})
        assert p.known_secrets == {"API_KEY", "DB_URL"}

    def test_record_activity_tracks_hours(self) -> None:
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        p.record_activity(hour_of_day=14)
        assert 14 in p.active_hours

    def test_detect_anomalies_during_learning(self) -> None:
        """During learning period, no anomalies should be detected."""
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        p.record_activity(actions=10.0)
        anomalies = p.detect_anomalies(actions=1000.0)
        assert anomalies == []

    def test_detect_anomalies_after_learning(self) -> None:
        """After learning, spikes should be detected."""
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        # Use a short learning period for testing
        p.actions_per_hour = BehavioralBaseline(learning_samples=5, alpha=0.1)
        for _ in range(5):
            p.actions_per_hour.update(10.0)
        anomalies = p.detect_anomalies(actions=1000.0)
        assert "actions_per_hour" in anomalies

    def test_detect_new_secret_access(self) -> None:
        """Access to never-before-seen secrets should be flagged."""
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        p.actions_per_hour = BehavioralBaseline(learning_samples=2, alpha=0.1)
        p.actions_per_hour.update(10.0)
        p.actions_per_hour.update(10.0)
        p.known_secrets = {"API_KEY", "DB_URL"}

        anomalies = p.detect_anomalies(
            secret_names={"API_KEY", "STRIPE_KEY"},  # STRIPE_KEY is new
        )
        assert "new_secret_access" in anomalies

    def test_detect_outside_active_hours(self) -> None:
        """Activity outside established hours should be flagged."""
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        p.actions_per_hour = BehavioralBaseline(learning_samples=2, alpha=0.1)
        p.actions_per_hour.update(10.0)
        p.actions_per_hour.update(10.0)
        p.active_hours = {9, 10, 11, 12, 13, 14, 15, 16, 17}

        anomalies = p.detect_anomalies(hour_of_day=3)
        assert "outside_active_hours" in anomalies

    def test_no_outside_hours_if_in_range(self) -> None:
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        p.actions_per_hour = BehavioralBaseline(learning_samples=2, alpha=0.1)
        p.actions_per_hour.update(10.0)
        p.actions_per_hour.update(10.0)
        p.active_hours = {9, 10, 11}

        anomalies = p.detect_anomalies(hour_of_day=10)
        assert "outside_active_hours" not in anomalies

    def test_multiple_anomalies(self) -> None:
        """Multiple metrics can fire simultaneously."""
        p = AgentProfile(agent_uri="nl://test/agent/1.0")
        for baseline in [
            p.actions_per_hour,
            p.secrets_per_day,
            p.action_types_per_hour,
            p.error_rate_per_hour,
        ]:
            baseline.learning_samples = 2
            baseline.update(10.0)
            baseline.update(10.0)
        p.known_secrets = {"A"}
        p.active_hours = {12}

        anomalies = p.detect_anomalies(
            actions=1000.0,
            unique_secrets=1000.0,
            action_types=1000.0,
            errors=1000.0,
            secret_names={"B"},
            hour_of_day=3,
        )
        assert "actions_per_hour" in anomalies
        assert "secrets_per_day" in anomalies
        assert "new_secret_access" in anomalies
        assert "outside_active_hours" in anomalies


# ===================================================================
# ResponseEngine
# ===================================================================


class TestResponseEngine:
    """Tests for the four-tier ResponseEngine."""

    def _make_score(self, int_score: int) -> ThreatScore:
        return ThreatScore(
            score=int_score / 100.0,
            int_score=int_score,
            level=threat_level_from_score(int_score),
        )

    def test_green_response(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(15))
        assert resp.level == ThreatLevel.GREEN
        assert ResponseActionType.LOG in resp.actions
        assert len(resp.actions) == 1
        assert resp.rate_limit_factor is None

    def test_yellow_response(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(45))
        assert resp.level == ThreatLevel.YELLOW
        assert ResponseActionType.LOG in resp.actions
        assert ResponseActionType.ENHANCED_LOGGING in resp.actions
        assert ResponseActionType.RATE_LIMIT in resp.actions
        assert ResponseActionType.NOTIFY_ADMIN in resp.actions
        assert resp.rate_limit_factor == 0.5

    def test_orange_response(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(70))
        assert resp.level == ThreatLevel.ORANGE
        assert ResponseActionType.LOG in resp.actions
        assert ResponseActionType.BLOCK_ACTION in resp.actions
        assert ResponseActionType.RESTRICT_SCOPE in resp.actions
        assert ResponseActionType.NOTIFY_ADMIN_URGENT in resp.actions
        assert resp.rate_limit_factor is None

    def test_red_response(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(90))
        assert resp.level == ThreatLevel.RED
        assert ResponseActionType.REVOKE_AID in resp.actions
        assert ResponseActionType.BLOCK_ALL_ACTIONS in resp.actions
        assert ResponseActionType.CRITICAL_ALERT in resp.actions
        assert ResponseActionType.INCIDENT_RESPONSE in resp.actions
        assert ResponseActionType.REVOKE_DELEGATION_TOKENS in resp.actions

    def test_boundary_29_is_green(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(29))
        assert resp.level == ThreatLevel.GREEN

    def test_boundary_30_is_yellow(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(30))
        assert resp.level == ThreatLevel.YELLOW

    def test_boundary_59_is_yellow(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(59))
        assert resp.level == ThreatLevel.YELLOW

    def test_boundary_60_is_orange(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(60))
        assert resp.level == ThreatLevel.ORANGE

    def test_boundary_79_is_orange(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(79))
        assert resp.level == ThreatLevel.ORANGE

    def test_boundary_80_is_red(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(80))
        assert resp.level == ThreatLevel.RED

    def test_custom_rate_limit_factor(self) -> None:
        engine = ResponseEngine(rate_limit_factor=0.3)
        resp = engine.determine_response(self._make_score(40))
        assert resp.rate_limit_factor == 0.3

    def test_determine_response_for_score(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response_for_score(75)
        assert resp.level == ThreatLevel.ORANGE
        assert resp.threat_score == 75

    def test_response_has_reason(self) -> None:
        engine = ResponseEngine()
        for score in [10, 40, 70, 90]:
            resp = engine.determine_response(self._make_score(score))
            assert resp.reason != ""

    def test_response_has_timestamp(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(0))
        assert resp.timestamp is not None

    def test_response_action_immutable(self) -> None:
        engine = ResponseEngine()
        resp = engine.determine_response(self._make_score(0))
        with pytest.raises(AttributeError):
            resp.level = ThreatLevel.RED  # type: ignore[misc]


# ===================================================================
# HoneypotManager
# ===================================================================


class TestHoneypotManager:
    """Tests for the HoneypotManager."""

    def test_create_honeypot(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("ADMIN_API_KEY", "admin")
        assert str(ref) == "admin/ADMIN_API_KEY"

    def test_is_honeypot_true(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("ADMIN_API_KEY", "admin")
        assert mgr.is_honeypot(ref)

    def test_is_honeypot_false(self) -> None:
        mgr = HoneypotManager()
        assert not mgr.is_honeypot(SecretRef("real/SECRET"))

    def test_honeypot_count(self) -> None:
        mgr = HoneypotManager()
        mgr.create_honeypot("KEY1", "cat1")
        mgr.create_honeypot("KEY2", "cat2")
        assert mgr.honeypot_count == 2

    def test_list_honeypots(self) -> None:
        mgr = HoneypotManager()
        mgr.create_honeypot("A", "cat")
        mgr.create_honeypot("B", "cat")
        entries = mgr.list_honeypots()
        assert len(entries) == 2

    def test_get_entry(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("KEY", "admin")
        entry = mgr.get_entry(ref)
        assert entry is not None
        assert entry.name == "KEY"
        assert entry.category == "admin"

    def test_get_entry_nonexistent(self) -> None:
        mgr = HoneypotManager()
        assert mgr.get_entry(SecretRef("nope")) is None

    def test_custom_honeypot_id(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("KEY", "cat", honeypot_id="hp-custom-001")
        entry = mgr.get_entry(ref)
        assert entry is not None
        assert entry.honeypot_id == "hp-custom-001"

    def test_get_entry_by_id(self) -> None:
        mgr = HoneypotManager()
        mgr.create_honeypot("KEY", "cat", honeypot_id="hp-test-123")
        entry = mgr.get_entry_by_id("hp-test-123")
        assert entry is not None
        assert entry.name == "KEY"

    def test_on_access_returns_red(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("ADMIN_KEY", "admin")
        score = mgr.on_access(ref, "nl://attacker/1.0")
        assert score.int_score == 80
        assert score.level == ThreatLevel.RED

    def test_on_access_records_log(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("ADMIN_KEY", "admin")
        mgr.on_access(ref, "nl://attacker/1.0")
        entry = mgr.get_entry(ref)
        assert entry is not None
        assert len(entry.access_log) == 1
        assert entry.access_log[0]["agent_uri"] == "nl://attacker/1.0"

    def test_on_access_invalid_ref(self) -> None:
        mgr = HoneypotManager()
        with pytest.raises(ValueError, match="Not a registered honeypot"):
            mgr.on_access(SecretRef("nonexistent"), "nl://test/1.0")

    def test_on_access_factors(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("TOKEN", "prod")
        score = mgr.on_access(ref, "nl://agent/1.0")
        assert len(score.factors) == 1
        factor = score.factors[0]
        assert factor["detection_method"] == "honeypot"
        assert factor["honeypot_name"] == "TOKEN"
        assert factor["severity_override"] == 80

    def test_create_incident(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("KEY", "admin")
        incident = mgr.create_incident(ref, "nl://agent/1.0")
        assert incident.attack_type == AttackType.T1
        assert incident.agent_uri == "nl://agent/1.0"
        assert incident.evidence["detection_method"] == "honeypot"

    def test_create_incident_custom_type(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("KEY", "admin")
        incident = mgr.create_incident(ref, "nl://a/1.0", attack_type=AttackType.T2)
        assert incident.attack_type == AttackType.T2

    def test_create_incident_invalid_ref(self) -> None:
        mgr = HoneypotManager()
        with pytest.raises(ValueError, match="Not a registered honeypot"):
            mgr.create_incident(SecretRef("nope"), "nl://test/1.0")

    def test_multiple_accesses_recorded(self) -> None:
        mgr = HoneypotManager()
        ref = mgr.create_honeypot("KEY", "admin")
        mgr.on_access(ref, "nl://a/1.0")
        mgr.on_access(ref, "nl://b/1.0")
        entry = mgr.get_entry(ref)
        assert entry is not None
        assert len(entry.access_log) == 2


# ===================================================================
# Integration: Scorer + Honeypot + Response
# ===================================================================


class TestIntegration:
    """Integration tests combining scorer, honeypot, and response engine."""

    def test_honeypot_access_triggers_red_response(self) -> None:
        mgr = HoneypotManager()
        engine = ResponseEngine()

        ref = mgr.create_honeypot("ADMIN_KEY", "admin")
        score = mgr.on_access(ref, "nl://attacker/1.0")
        response = engine.determine_response(score)

        assert response.level == ThreatLevel.RED
        assert ResponseActionType.REVOKE_AID in response.actions

    def test_scorer_with_honeypot_incident(self) -> None:
        scorer = ThreatScorer()
        mgr = HoneypotManager()
        agent = "nl://test/agent/1.0"

        ref = mgr.create_honeypot("KEY", "admin")
        incident = mgr.create_incident(ref, agent)
        score = scorer.record_incident(incident)

        # T1 base severity = 20, but this is a honeypot (the scorer uses T1 severity)
        assert score.int_score == 20

    def test_escalation_path_green_to_red(self) -> None:
        """Simulate an agent escalating from GREEN to RED."""
        scorer = ThreatScorer()
        engine = ResponseEngine()
        agent = "nl://test/agent/1.0"

        # First incident: T1 -> score ~20 -> GREEN
        inc1 = Incident(
            attack_type=AttackType.T1,
            timestamp=datetime.now(UTC),
            agent_uri=agent,
        )
        score1 = scorer.record_incident(inc1)
        resp1 = engine.determine_response(score1)
        assert resp1.level == ThreatLevel.GREEN

        # Second incident: T3 -> score ~60 -> ORANGE
        inc2 = Incident(
            attack_type=AttackType.T3,
            timestamp=datetime.now(UTC),
            agent_uri=agent,
        )
        score2 = scorer.record_incident(inc2)
        resp2 = engine.determine_response(score2)
        assert resp2.level == ThreatLevel.ORANGE

        # Third incident: T9 -> score jumps -> RED
        inc3 = Incident(
            attack_type=AttackType.T9,
            timestamp=datetime.now(UTC),
            agent_uri=agent,
        )
        score3 = scorer.record_incident(inc3)
        resp3 = engine.determine_response(score3)
        assert resp3.level == ThreatLevel.RED

    def test_behavioral_anomaly_with_scoring(self) -> None:
        """Behavioral anomaly detection producing incidents that affect scoring."""
        profile = AgentProfile(agent_uri="nl://test/agent/1.0")
        scorer = ThreatScorer()

        # Train the profile
        for baseline in [profile.actions_per_hour]:
            baseline.learning_samples = 3
        for _ in range(3):
            profile.record_activity(actions=10.0)

        # Now detect anomaly
        anomalies = profile.detect_anomalies(actions=100.0)
        assert "actions_per_hour" in anomalies

        # Create incident from anomaly
        inc = Incident(
            attack_type=AttackType.T6,  # Suspected prompt injection
            timestamp=datetime.now(UTC),
            agent_uri=profile.agent_uri,
            evidence={"anomalies": anomalies},
        )
        score = scorer.record_incident(inc)
        assert score.int_score > 0
