"""Offline tests over pure functions; no client doubles, no network."""

from __future__ import annotations

import importlib.util

import pytest

from jev_vulnops.pipeline import (
    SLA_DAYS,
    build_state,
    disposition,
    estimate_tokens,
    level_bucket,
)
from jev_vulnops.questions import ALL_QUESTIONS, Choice, Score


def test_state_carries_vuln_and_asset():
    vuln = {"cve_id": "CVE-1", "description": "x", "asset": {"name": "a"}}
    state = build_state(vuln)
    assert "vulnerability" in state and "asset" in state
    assert state["asset"]["name"] == "a"


def test_questions_use_three_types():
    assert isinstance(ALL_QUESTIONS["next_action"], Choice)
    assert isinstance(ALL_QUESTIONS["exploit_likelihood_30d"], Score)
    assert len(ALL_QUESTIONS) == 3


def test_sla_days_exist_for_all_choices():
    assert set(ALL_QUESTIONS["next_action"].criteria) == set(SLA_DAYS)


def test_disposition_rule():
    assert disposition(0.95, 0.1, 0.75) == ("AUTO", [])
    decis, reasons = disposition(0.5, 0.1, 0.75)
    assert decis == "ESCALATE" and reasons
    decis, reasons = disposition(0.95, 0.9, 0.75)
    assert decis == "ESCALATE" and "analyst-review" in reasons[0]


@pytest.mark.parametrize("position,bucket", [(0.1, "low"), (0.35, "elevated"), (0.65, "high"), (0.98, "critical")])
def test_level_bucket(position, bucket):
    assert level_bucket(position) == bucket


def test_estimate_tokens_counts_state_and_questions():
    state = build_state({"cve_id": "CVE-1", "description": "x" * 400, "asset": {"name": "a"}})
    assert estimate_tokens(state, ALL_QUESTIONS) > 100


def test_client_requires_sdk_import():
    if importlib.util.find_spec("typesafe_sdk"):
        pytest.skip("typesafe-sdk installed")
    from jev_vulnops.client import TypeSafeLiveClient

    with pytest.raises(RuntimeError, match="typesafe-sdk"):
        TypeSafeLiveClient()
