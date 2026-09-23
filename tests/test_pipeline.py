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


def test_load_vulns_from_json(tmp_path):
    from jev_vulnops.demo import load_vulns

    p = tmp_path / "vulns.json"
    p.write_text('[{"cve_id": "CVE-1", "description": "x", "asset": {"name": "a"}}]')
    assert load_vulns(str(p))[0]["cve_id"] == "CVE-1"

    bad = tmp_path / "bad.json"
    bad.write_text('[{"cve_id": "CVE-2"}]')
    with pytest.raises(SystemExit, match="missing keys"):
        load_vulns(str(bad))

    not_list = tmp_path / "obj.json"
    not_list.write_text('{"cve_id": "CVE-3"}')
    with pytest.raises(SystemExit, match="JSON array"):
        load_vulns(str(not_list))


def test_fmt_detail_shows_distributions():
    from jev_vulnops.demo import _fmt_detail
    from jev_vulnops.pipeline import TriageDecision

    d = TriageDecision(
        cve_id="CVE-1",
        asset_name="a",
        action="sla-remediate",
        action_confidence=0.8,
        exploit_position=0.5,
        exploit_bucket="elevated",
        reviewer_probability=0.1,
        disposition="AUTO",
        detail={
            "model": "typesafe/jev-1.13",
            "usage": {"input_tokens": 10},
            "next_action": {"choice": "sla-remediate", "confidence": 0.8, "probabilities": {"sla-remediate": 0.8}},
            "exploit_likelihood_30d": {"position": 0.5, "confidence": 0.7, "probabilities": {1: 0.7}},
            "needs_analyst_review": {"probability": 0.1},
        },
    )
    out = _fmt_detail(d)
    assert "typesafe/jev-1.13" in out and "sla-remediate=0.80" in out


def test_provider_label(monkeypatch):
    from jev_vulnops.demo import provider_label

    monkeypatch.delenv("TYPESAFE_BASE_URL", raising=False)
    assert provider_label() == "TypeSafe direct"
    monkeypatch.setenv("TYPESAFE_BASE_URL", "https://openrouter.ai/api")
    assert provider_label() == "OpenRouter"
    monkeypatch.setenv("TYPESAFE_BASE_URL", "https://proxy.example.com")
    assert "custom base" in provider_label()


def test_web_static_files_exist():
    from jev_vulnops.web import STATIC, _questions_payload, _sse

    for name in ("index.html", "app.js", "style.css"):
        assert (STATIC / name).is_file(), name
    frame = _sse("vuln_done", {"cve_id": "CVE-1"})
    assert frame.startswith(b"event: vuln_done\n") and b'"CVE-1"' in frame
    payload = _questions_payload()
    assert {q["type"] for q in payload} == {"choice", "score", "noul"}


def test_client_requires_sdk_import():
    if importlib.util.find_spec("typesafe_sdk"):
        pytest.skip("typesafe-sdk installed")
    from jev_vulnops.client import TypeSafeLiveClient

    with pytest.raises(RuntimeError, match="typesafe-sdk"):
        TypeSafeLiveClient()


def test_to_sdk_question_construction():
    ts = pytest.importorskip("typesafe_sdk")
    from jev_vulnops.client import TypeSafeLiveClient

    client = TypeSafeLiveClient.__new__(TypeSafeLiveClient)  # no network init
    client._sdk_types = {"choice": ts.Choice, "score": ts.Score, "noul": ts.Noul}
    for q in ALL_QUESTIONS.values():
        sdk_q = client._to_sdk(q)
        dumped = sdk_q.model_dump()
        assert dumped["instructions"]
        if dumped.get("type") == "score":
            assert isinstance(dumped["criteria"], list)
            assert len(dumped["criteria"]) == 4


def test_mapper_against_real_sdk_types():
    ts = pytest.importorskip("typesafe_sdk")
    from jev_vulnops.client import TypeSafeLiveClient

    resp = ts.SystemOneResponse(
        model="jev-1.13",
        usage={"input_tokens": 10, "output_tokens": 0},
        answers={
            "next_action": ts.ChoiceAnswer(
                type="choice",
                choice="sla-remediate",
                confidence=0.9,
                probabilities={"sla-remediate": 0.9, "accept-risk": 0.1},
            ),
            "exploit_likelihood_30d": ts.ScoreAnswer(
                type="score",
                score=1.5,
                confidence=0.8,
                legend={0: "low", 1: "elevated"},
                probabilities={0: 0.3, 1: 0.7},
            ),
            "needs_analyst_review": ts.NoulAnswer(type="noul", noul=0.42),
        },
    )
    client = TypeSafeLiveClient.__new__(TypeSafeLiveClient)  # no init: no SDK needed for _map
    mapped = client._map(resp, ALL_QUESTIONS)
    assert mapped.choices["next_action"].choice == "sla-remediate"
    assert abs(mapped.scores["exploit_likelihood_30d"].position - 0.5) < 1e-9
    assert mapped.nouls["needs_analyst_review"].probability == pytest.approx(0.42)
    assert mapped.raw is resp
