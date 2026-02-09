"""NL Protocol Level 6 -- Behavioral baseline and anomaly detection.

This module implements the behavioral analysis system defined in Chapter 06,
Section 4.4 of the NL Protocol specification.  It provides:

* **BehavioralBaseline** -- EWMA-based baseline tracker for a single metric.
* **AgentProfile** -- per-agent profile aggregating multiple metric baselines.

The EWMA update formula (Section 4.4.1)::

    new_mean     = alpha * observed + (1 - alpha) * old_mean
    new_variance = alpha * (observed - new_mean)^2 + (1 - alpha) * old_variance

Anomaly detection triggers when::

    (observed - mean) > (sigma * stddev)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime

# ---------------------------------------------------------------------------
# EWMA baseline tracker
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class BehavioralBaseline:
    """Exponentially Weighted Moving Average (EWMA) baseline for a metric.

    Parameters
    ----------
    alpha : float
        Smoothing factor.  Spec recommends 0.1 (90% historical weight).
        Must satisfy ``0 < alpha <= 0.3``.
    learning_samples : int
        Number of samples required before anomaly detection activates.
        Spec recommends 72 hours of data; this is expressed in sample
        counts.
    """

    alpha: float = 0.1
    learning_samples: int = 72
    mean: float = 0.0
    variance: float = 0.0
    sample_count: int = 0
    last_updated: datetime | None = None

    def __post_init__(self) -> None:
        if not (0 < self.alpha <= 0.3):
            msg = f"alpha must be in (0, 0.3], got {self.alpha}"
            raise ValueError(msg)

    @property
    def stddev(self) -> float:
        """Return the current standard deviation."""
        return math.sqrt(max(self.variance, 0.0))

    @property
    def is_learning(self) -> bool:
        """Return True if still in the learning period."""
        return self.sample_count < self.learning_samples

    def update(self, metric_value: float) -> None:
        """Update the baseline with a new observed value.

        Uses the EWMA update formula from Section 4.4.1.
        During the first sample, mean and variance are initialised directly.
        """
        self.sample_count += 1
        self.last_updated = datetime.now(UTC)

        if self.sample_count == 1:
            self.mean = metric_value
            self.variance = 0.0
            return

        new_mean = self.alpha * metric_value + (1 - self.alpha) * self.mean
        new_variance = (
            self.alpha * (metric_value - new_mean) ** 2
            + (1 - self.alpha) * self.variance
        )
        self.mean = new_mean
        self.variance = new_variance

    def is_anomaly(self, value: float, threshold_sigma: float = 2.5) -> bool:
        """Check whether *value* deviates from baseline by more than *threshold_sigma*.

        Returns ``False`` during the learning period (per spec: anomaly
        detection is suspended during the initial 72-hour learning period).

        Parameters
        ----------
        value : float
            The observed metric value.
        threshold_sigma : float
            Number of standard deviations above the mean to trigger.
            Spec default is 2.5.

        Returns
        -------
        bool
            ``True`` if the value is anomalous; ``False`` otherwise.
        """
        if self.is_learning:
            return False

        if self.stddev == 0.0:
            # If stddev is zero, any deviation from mean is anomalous
            return value != self.mean

        return (value - self.mean) > (threshold_sigma * self.stddev)

    def deviation_magnitude(self, value: float) -> float:
        """Return how many standard deviations *value* is above the mean.

        Returns 0.0 during the learning period or when stddev is 0.
        """
        if self.is_learning or self.stddev == 0.0:
            return 0.0
        return max(0.0, (value - self.mean) / self.stddev)


# ---------------------------------------------------------------------------
# Per-agent behavioral profile
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class AgentProfile:
    """Per-agent behavioral profile aggregating multiple metric baselines.

    Tracks the four required metrics from Section 4.4.1:

    1. actions_per_hour
    2. secrets_per_day (unique secrets accessed per 24h window)
    3. action_types_per_hour (distinct action types used per hour)
    4. error_rate_per_hour (denied/error actions per hour)

    And optional metrics:

    5. network_destinations_per_hour
    6. avg_execution_time_ms
    """

    agent_uri: str
    actions_per_hour: BehavioralBaseline = field(
        default_factory=lambda: BehavioralBaseline(alpha=0.1)
    )
    secrets_per_day: BehavioralBaseline = field(
        default_factory=lambda: BehavioralBaseline(alpha=0.1)
    )
    action_types_per_hour: BehavioralBaseline = field(
        default_factory=lambda: BehavioralBaseline(alpha=0.1)
    )
    error_rate_per_hour: BehavioralBaseline = field(
        default_factory=lambda: BehavioralBaseline(alpha=0.1)
    )
    network_destinations_per_hour: BehavioralBaseline = field(
        default_factory=lambda: BehavioralBaseline(alpha=0.1)
    )
    avg_execution_time_ms: BehavioralBaseline = field(
        default_factory=lambda: BehavioralBaseline(alpha=0.1)
    )
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    known_secrets: set[str] = field(default_factory=set)
    active_hours: set[int] = field(default_factory=set)

    def record_activity(
        self,
        *,
        actions: float = 0.0,
        unique_secrets: float = 0.0,
        action_types: float = 0.0,
        errors: float = 0.0,
        secret_names: set[str] | None = None,
        hour_of_day: int | None = None,
    ) -> None:
        """Update all metric baselines with a single observation window.

        Parameters
        ----------
        actions : float
            Number of actions in the current hour.
        unique_secrets : float
            Number of unique secrets accessed in the current 24h window.
        action_types : float
            Number of distinct action types used in the current hour.
        errors : float
            Number of denied/error actions in the current hour.
        secret_names : set[str] | None
            Set of secret names accessed (to track the known-secrets set).
        hour_of_day : int | None
            Hour of day (0-23) to track active-hours pattern.
        """
        self.actions_per_hour.update(actions)
        self.secrets_per_day.update(unique_secrets)
        self.action_types_per_hour.update(action_types)
        self.error_rate_per_hour.update(errors)

        if secret_names:
            self.known_secrets.update(secret_names)

        if hour_of_day is not None:
            self.active_hours.add(hour_of_day)

    def detect_anomalies(
        self,
        *,
        actions: float = 0.0,
        unique_secrets: float = 0.0,
        action_types: float = 0.0,
        errors: float = 0.0,
        secret_names: set[str] | None = None,
        hour_of_day: int | None = None,
        actions_sigma: float = 2.5,
        secrets_sigma: float = 2.5,
        action_types_sigma: float = 2.5,
        errors_sigma: float = 2.5,
    ) -> list[str]:
        """Check all metrics for anomalies and return a list of deviation names.

        Parameters
        ----------
        actions_sigma : float
            Override sigma for actions_per_hour (default 2.5).
        secrets_sigma : float
            Override sigma for secrets_per_day (default 2.5).
        action_types_sigma : float
            Override sigma for action_types_per_hour (default 2.5).
        errors_sigma : float
            Override sigma for error_rate_per_hour (default 2.5).

        Returns
        -------
        list[str]
            Names of metrics that showed anomalous values.
        """
        anomalies: list[str] = []

        if self.actions_per_hour.is_anomaly(actions, actions_sigma):
            anomalies.append("actions_per_hour")

        if self.secrets_per_day.is_anomaly(unique_secrets, secrets_sigma):
            anomalies.append("secrets_per_day")

        if self.action_types_per_hour.is_anomaly(action_types, action_types_sigma):
            anomalies.append("action_types_per_hour")

        if self.error_rate_per_hour.is_anomaly(errors, errors_sigma):
            anomalies.append("error_rate_per_hour")

        # Check for access to never-before-seen secrets
        if secret_names and not self.actions_per_hour.is_learning:
            new_secrets = secret_names - self.known_secrets
            if new_secrets:
                anomalies.append("new_secret_access")

        # Check for activity outside established hours
        if (
            hour_of_day is not None
            and self.active_hours
            and not self.actions_per_hour.is_learning
            and hour_of_day not in self.active_hours
        ):
            anomalies.append("outside_active_hours")

        return anomalies
