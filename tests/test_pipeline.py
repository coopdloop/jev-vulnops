"""Offline tests over pure functions; no client doubles, no network."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess

import pytest

from jev_vulnops.data import VULNS
from jev_vulnops.pipeline import (
    SLA_DAYS,
    build_state,
    disposition,
    estimate_tokens,
    level_bucket,
)
from jev_vulnops.questions import ALL_QUESTIONS, Choice, Score, wire_all


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


def test_wire_format_questions():
    from jev_vulnops.questions import wire_all

    wired = wire_all(ALL_QUESTIONS)
    assert wired["next_action"]["type"] == "choice"
    assert isinstance(wired["next_action"]["criteria"], dict)
    assert wired["exploit_likelihood_30d"]["type"] == "score"
    assert isinstance(wired["exploit_likelihood_30d"]["criteria"], list)
    assert wired["exploit_likelihood_30d"]["criteria"][0]["name"] == "low"
    assert wired["needs_analyst_review"]["type"] == "noul"


def test_ask_raw_rejects_unknown_type():
    ts = pytest.importorskip("typesafe_sdk")
    from jev_vulnops.client import TypeSafeLiveClient

    client = TypeSafeLiveClient.__new__(TypeSafeLiveClient)
    client._sdk_types = {"choice": ts.Choice, "score": ts.Score, "noul": ts.Noul}
    with pytest.raises(ValueError, match="unknown question type"):
        client.ask_raw({}, {"q": {"type": "bogus"}})


def test_web_static_files_exist():
    from jev_vulnops.web import STATIC, _questions_payload, _sse

    for name in ("index.html", "app.js", "routing.js", "studio.js", "style.css"):
        assert (STATIC / name).is_file(), name
    page = (STATIC / "index.html").read_text()
    assert re.search(r'<script src="/static/routing.js"></script>', page)
    assert re.search(r'<script src="/static/studio.js"></script>', page)
    assert 'data-tab="studio"' in page and 'id="tab-studio"' in page and 'id="pgSet"' in page
    # The bars are spans: without display:block the browser ignores their
    # width/height and every probability bar renders as an empty track.
    css = (STATIC / "style.css").read_text()
    assert re.search(r"\.bar-fill\s*\{[^}]*display:\s*block", css), ".bar-fill must be block-level"
    frame = _sse("vuln_done", {"cve_id": "CVE-1"})
    assert frame.startswith(b"event: vuln_done\n") and b'"CVE-1"' in frame
    payload = _questions_payload()
    assert {q["type"] for q in payload} == {"choice", "score", "noul"}


def test_meta_payload_shares_pricing_and_route():
    from jev_vulnops.client import MODELS, PRICE_PER_MTTOK
    from jev_vulnops.questions import ALL_QUESTIONS
    from jev_vulnops.web import _meta_payload

    meta = _meta_payload(VULNS, "built-in fixtures")
    assert meta["models"] == list(MODELS)
    assert meta["price_per_mtok_in"] == PRICE_PER_MTTOK
    assert meta["questions"] == len(ALL_QUESTIONS)
    assert meta["vuln_count"] == len(VULNS) and meta["dataset"] == "built-in fixtures"


def test_default_classifier_sets():
    from jev_vulnops.questions import DEFAULT_SETS, validate_wire_questions

    by_id = {s["id"]: s for s in DEFAULT_SETS}
    assert set(by_id) == {"baseline", "exposure-first", "action-only", "wide"}
    assert all(s["builtin"] and s["description"] for s in DEFAULT_SETS)
    assert len(by_id["action-only"]["questions"]) == 1
    assert len(by_id["wide"]["questions"]) == 5
    assert by_id["baseline"]["questions"] == wire_all(ALL_QUESTIONS)
    for s in DEFAULT_SETS:
        assert validate_wire_questions(s["questions"], s["id"]) is s["questions"]


def test_validate_wire_questions_rejects_bad_sets():
    from jev_vulnops.questions import validate_wire_questions

    cases = {
        "empty": {},
        "spaced name": {"next action": {"type": "choice", "instructions": "x", "criteria": {"a": "1", "b": "2"}}},
        "bad type": {"q": {"type": "rank", "instructions": "x"}},
        "no instructions": {"q": {"type": "noul", "instructions": "  "}},
        "one option": {"q": {"type": "choice", "instructions": "x", "criteria": {"a": "1"}}},
        "score as dict": {"q": {"type": "score", "instructions": "x", "criteria": {"a": "1", "b": "2"}}},
        "choice as list": {"q": {"type": "choice", "instructions": "x", "criteria": [{"name": "a"}]}},
        "blank description": {
            "q": {"type": "score", "instructions": "x", "criteria": [{"name": "a", "description": ""}, {"name": "b", "description": "y"}]}
        },
    }
    for label, questions in cases.items():
        with pytest.raises(ValueError, match="q|questions|next action"):
            validate_wire_questions(questions, label)


def test_load_classifier_sets_from_file(tmp_path):
    from jev_vulnops.questions import load_classifier_sets

    good = tmp_path / "sets.json"
    good.write_text(
        json.dumps(
            {"sets": [{"id": "ops", "name": "Ops view", "questions": {"escalate": {"type": "noul", "instructions": "Escalate?"}}}]}
        )
    )
    loaded = load_classifier_sets(str(good))
    assert loaded[0]["id"] == "ops" and loaded[0]["name"] == "Ops view"
    assert loaded[0]["questions"]["escalate"]["type"] == "noul"

    bad = tmp_path / "bad.json"
    bad.write_text('{"sets": [{"name": "no questions"}]}')
    with pytest.raises(SystemExit, match="non-empty 'questions'"):
        load_classifier_sets(str(bad))

    notlist = tmp_path / "obj.json"
    notlist.write_text('{"foo": 1}')
    with pytest.raises(SystemExit, match="JSON array"):
        load_classifier_sets(str(notlist))


def test_ui_gate_matches_python_gate(tmp_path):
    """The dashboard re-routes locally while the threshold is dragged, so its
    mirrored rule must agree with pipeline.disposition() case by case."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    from jev_vulnops.pipeline import disposition
    from jev_vulnops.web import STATIC

    cases = [
        [conf, reviewer, threshold]
        for conf in (0.0, 0.49, 0.5, 0.74, 0.75, 0.751, 0.99)
        for reviewer in (0.0, 0.49, 0.5, 1.0)
        for threshold in (0.5, 0.75, 0.95)
    ]
    runner = tmp_path / "gate.js"
    runner.write_text(
        f"const {{ routeOf }} = require({json.dumps(str(STATIC / 'routing.js'))});\n"
        f"const cases = {json.dumps(cases)};\n"
        "const routed = cases.map(([conf, reviewer, threshold]) =>\n"
        "  routeOf({ action_confidence: conf, reviewer_probability: reviewer }, threshold).disposition);\n"
        "process.stdout.write(JSON.stringify(routed));\n"
    )
    result = subprocess.run([node, str(runner)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [disposition(c[0], c[1], c[2])[0] for c in cases]


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


def test_studio_wire_roundtrip_matches_backend(tmp_path):
    """The studio edits questions as an array; the API takes the wire map. This
    checks the studio's conversion against the real payloads the backend ships."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    from jev_vulnops.questions import DEFAULT_SETS
    from jev_vulnops.web import STATIC

    fixture = tmp_path / "sets.json"
    fixture.write_text(json.dumps({s["id"]: s["questions"] for s in DEFAULT_SETS}))
    runner = tmp_path / "run-studio.js"
    runner.write_text(
        f"const {{ Studio }} = require({json.dumps(str(STATIC / 'studio.js'))});\n"
        "const fs = require('fs');\n"
        "const sets = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\n"
        "const out = {};\n"
        "for (const [id, wire] of Object.entries(sets)) out[id] = Studio.toWire(Studio.questionsFromWire(wire));\n"
        "out.__good = Studio.validateSet({ name: 'x', questions: [{ name: 'q', type: 'noul', instructions: 'yes?', criteria: [] }] });\n"
        "out.__bad = Studio.validateSet({ name: '', questions: [\n"
        "  { name: 'next action', type: 'choice', instructions: '', criteria: [{ name: 'a', description: '' }] },\n"
        "  { name: 'next action', type: 'score', instructions: 'y', criteria: [] },\n"
        "] });\n"
        "process.stdout.write(JSON.stringify(out));\n"
    )
    result = subprocess.run([node, str(runner), str(fixture)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    for s in DEFAULT_SETS:
        assert out[s["id"]] == s["questions"], f"studio rewrote {s['id']}"
    assert out["__good"] == []
    assert len(out["__bad"]) >= 5, out["__bad"]


def test_triage_records_response_time():
    ts = pytest.importorskip("typesafe_sdk")
    from jev_vulnops.client import TypeSafeLiveClient
    from jev_vulnops.pipeline import triage

    resp = ts.SystemOneResponse(
        model="jev-1.13",
        usage={"input_tokens": 10, "output_tokens": 0},
        answers={
            "next_action": ts.ChoiceAnswer(
                type="choice", choice="remediate-now", confidence=0.9, probabilities={"remediate-now": 0.9}
            ),
            "exploit_likelihood_30d": ts.ScoreAnswer(
                type="score", score=3.0, confidence=0.8, legend={0: "low"}, probabilities={0: 0.2}
            ),
            "needs_analyst_review": ts.NoulAnswer(type="noul", noul=0.2),
        },
    )
    mapped = TypeSafeLiveClient.__new__(TypeSafeLiveClient)._map(resp, ALL_QUESTIONS)

    class StubClient:
        def system_one(self, state, questions, model=None):
            return mapped

    decision = triage(StubClient(), VULNS[0], threshold=0.75)
    assert decision.latency_ms >= 0.0


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
