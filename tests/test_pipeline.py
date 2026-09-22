"""Offline tests: everything runs against the deterministic mock client."""

from __future__ import annotations

import importlib.util

import pytest

from jev_vulnops.client import MockSystemOneClient
from jev_vulnops.data import VULNS
from jev_vulnops.pipeline import build_state, estimate_tokens, level_bucket, triage, triage_all
from jev_vulnops.questions import ALL_QUESTIONS, Choice


def _triaged(threshold: float = 0.75):
    return {d.cve_id: d for d in triage_all(MockSystemOneClient(), VULNS, threshold)}


def test_choice_probabilities_sum_to_one():
    client = MockSystemOneClient()
    for v in VULNS:
        resp = client.system_one(build_state(v), ALL_QUESTIONS)
        for cr in resp.choices.values():
            assert abs(sum(cr.probabilities.values()) - 1.0) < 1e-9
            assert cr.choice in cr.probabilities
            assert 0.0 <= cr.confidence <= 1.0
        for sr in resp.scores.values():
            assert abs(sum(sr.probabilities.values()) - 1.0) < 1e-9
            assert 0.0 <= sr.position <= 1.0


def test_mock_is_deterministic():
    c1, c2 = MockSystemOneClient(), MockSystemOneClient()
    r1 = c1.system_one(build_state(VULNS[0]), ALL_QUESTIONS)
    r2 = c2.system_one(build_state(VULNS[0]), ALL_QUESTIONS)
    assert r1.choices == r2.choices and r1.scores == r2.scores and r1.nouls == r2.nouls


def test_one_request_carries_all_questions():
    client = MockSystemOneClient()
    triage(client, VULNS[0])
    (state, questions) = client.calls[0]
    assert len(client.calls) == 1
    assert set(questions) == {"next_action", "exploit_likelihood_30d", "needs_analyst_review"}
    assert isinstance(questions["next_action"], Choice)


def test_kev_rce_on_exposed_asset_auto_remediates():
    decisions = _triaged()
    d = decisions["CVE-2025-31404"]
    assert d.action == "remediate-now"
    assert d.disposition == "AUTO"
    assert d.exploit_bucket in ("high", "critical")
    assert d.due_days == 14


def test_vague_advisory_escalates():
    decisions = _triaged()
    d = decisions["CVE-2025-30333"]
    assert d.disposition == "ESCALATE"
    assert d.action == "needs-intel" or d.reviewer_probability >= 0.5


def test_unreachable_path_goes_accept_risk_or_escalated():
    decisions = _triaged()
    d = decisions["CVE-2025-50002"]
    # High CVSS but unreachable code path -> either accept-risk or analyst gate.
    assert d.disposition in ("AUTO", "ESCALATE")
    if d.disposition == "AUTO":
        assert d.action == "accept-risk"


@pytest.mark.parametrize("position,bucket", [(0.1, "low"), (0.35, "elevated"), (0.65, "high"), (0.98, "critical")])
def test_level_bucket(position, bucket):
    assert level_bucket(position) == bucket


def test_estimate_tokens_counts_state_and_questions():
    state = build_state(VULNS[0])
    tokens = estimate_tokens(state, ALL_QUESTIONS)
    assert tokens > 100


def test_live_client_requires_sdk():
    if importlib.util.find_spec("typesafe_sdk"):
        pytest.skip("typesafe-sdk installed")
    from jev_vulnops.client import TypeSafeLiveClient

    with pytest.raises(RuntimeError, match="typesafe-sdk"):
        TypeSafeLiveClient()
