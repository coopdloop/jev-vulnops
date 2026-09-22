"""System One client: faithful offline mock plus the live Typesafe adapter.

The mock mirrors the published API shape: answers to ALL questions ride on one
request against a single encoding of the state; every answer comes back typed
(choice/scale-position/yes-no-probability) with a probability and confidence.
It is a heuristic over obvious keywords and asset flags -- good enough to demo
the pipeline end to end without an API key, clearly labeled as a mock.

The live path uses `typesafe-sdk` and only activates when TYPESAFE_API_KEY is
set; this demo ships untested against the real endpoint on purpose (marked in
the README).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .questions import Choice, Noul, Score


@dataclass(frozen=True)
class ChoiceResult:
    choice: str
    probabilities: Mapping[str, float]
    confidence: float


@dataclass(frozen=True)
class ScoreResult:
    # 0..1 position along the ordered scale.
    position: float
    probabilities: Mapping[str, float]
    confidence: float


@dataclass(frozen=True)
class NoulResult:
    probability: float


@dataclass
class SystemOneResponse:
    choices: dict[str, ChoiceResult]
    scores: dict[str, ScoreResult]
    nouls: dict[str, NoulResult]


class SystemOneClient:
    def __init__(self) -> None:
        self.calls: list[tuple[dict, dict]] = []

    def system_one(self, state: Mapping[str, Any], questions: Mapping[str, Any]) -> SystemOneResponse:
        raise NotImplementedError


# Mock client

_KEYWORDS = (
    "remote code execution",
    "rce",
    "privilege escalation",
    "authentication bypass",
    "unauthenticated",
    "ssrf",
    "sandbox escape",
    "buffer overflow",
    "use after free",
    "command injection",
    "sql injection",
    "deserialization",
    "path traversal",
)

_VAGUE = ("possible", "under review", "vendor note", "vendor advisory", "deferred")


def _flatten(state: Mapping[str, Any]) -> str:
    return json.dumps(state, default=str).lower()


def _features(state: Mapping[str, Any]) -> dict[str, float]:
    """Hand-rolled feature extraction for the mock; the real model replaces this."""
    vuln = state["vulnerability"]
    asset = state["asset"]
    desc = str(vuln.get("description", "")).lower()
    cvss = float(vuln.get("cvss") or 5.0)
    epss = float(vuln.get("epss") or 0.0)
    kev = bool(vuln.get("known_exploited"))
    exposed = bool(asset.get("internet_exposed"))
    tier = str(asset.get("criticality_tier", "tier-3"))
    criticality = {"tier-0": 1.0, "tier-1": 0.75, "tier-2": 0.5, "tier-3": 0.25}.get(tier, 0.5)

    kw_hits = sum(1 for k in _KEYWORDS if k in desc)
    vague_hits = sum(1 for k in _VAGUE if k in desc)
    # Short advisories with no concrete keyword reads are ambiguous.
    ambiguity = max(0.0, min(1.0, vague_hits * 0.45 + max(0.0, (120.0 - len(desc))) / 120.0))

    signals = {
        "severity": cvss / 10.0,
        "epss": min(epss, 1.0),
        "kev": 1.0 if kev else 0.0,
        "exposed": 1.0 if exposed else 0.0,
        "criticality": criticality,
        "keyword_density": min(kw_hits, 5) / 5.0,
        "ambiguity": ambiguity,
        # "High cvss but unreachable/not-exposed" is a classic conflicting signal.
        "conflict": max(
            0.0,
            (cvss / 10.0) * (1.0 - float(exposed)) * 1.2
            + (1.0 if kev and not exposed else 0.0) * 0.6,
        ),
        "unreachable": 1.0 if re.search(r"not reachable|unreachable|not exploitable", desc) else 0.0,
    }
    return signals


def _normalize(weights: Mapping[str, float]) -> dict[str, float]:
    total = sum(max(w, 0.0) for w in weights.values())
    if total <= 0:
        return {k: 1.0 / len(weights) for k in weights}
    return {k: max(w, 0.0) / total for k, w in weights.items()}


def _sharpen(weights: Mapping[str, float], sharpness: float = 8.0) -> dict[str, float]:
    # Softmax around the max weight: bigger gap -> higher top confidence.
    if not weights:
        return {}
    max_w = max(weights.values())
    exps = {k: math.exp((w - max_w) * sharpness) for k, w in weights.items()}
    total = sum(exps.values())
    return {k: v / total for k, v in exps.items()}


def _flatten_toward_uniform(probs: Mapping[str, float], amount: float) -> dict[str, float]:
    amount = max(0.0, min(1.0, amount))
    n = len(probs)
    return {k: (1.0 - amount) * p + amount / n for k, p in probs.items()}


class MockSystemOneClient(SystemOneClient):
    """Deterministic heuristic mock. Not a model; mirrors the interface."""

    def system_one(self, state: Mapping[str, Any], questions: Mapping[str, Any]) -> SystemOneResponse:
        self.calls.append((dict(state), dict(questions)))
        feats = _features(state)
        choices: dict[str, ChoiceResult] = {}
        scores: dict[str, ScoreResult] = {}
        nouls: dict[str, NoulResult] = {}
        for name, q in questions.items():
            if isinstance(q, Choice):
                choices[name] = self._answer_choice(q, feats)
            elif isinstance(q, Score):
                scores[name] = self._answer_score(q, feats)
            elif isinstance(q, Noul):
                nouls[name] = self._answer_noul(q, feats)
            else:
                raise TypeError(f"unknown question type: {type(q)}")
        return SystemOneResponse(choices=choices, scores=scores, nouls=nouls)

    def _answer_choice(self, q: Choice, f: Mapping[str, float]) -> ChoiceResult:
        options = list(q.criteria) or ["remediate-now", "sla-remediate", "accept-risk", "needs-intel"]
        w = {
            "remediate-now": (
                0.15 * f["severity"] + 0.40 * f["kev"] + 0.20 * f["epss"]
                + 0.15 * f["exposed"] * f["criticality"] + 0.10 * f["keyword_density"]
            ),
            "sla-remediate": (
                0.30 + 0.25 * (f["severity"] - 0.5)
                + 0.20 * (1.0 - f["kev"]) + 0.10 * f["epss"] - 0.25 * f["unreachable"]
            ),
            "accept-risk": (
                0.30 * (1.0 - f["kev"]) + 0.30 * (1.0 - f["exposed"])
                + 0.45 * f["unreachable"] - 0.25 * (f["severity"] - 0.6)
            ),
            "needs-intel": 0.20 + 0.95 * f["ambiguity"],
        }
        weights = {opt: max(w.get(opt, 0.05), 0.01) for opt in options}
        probs = _sharpen(weights)
        # Ambiguity flattens the distribution -> genuinely low confidence.
        probs = _flatten_toward_uniform(probs, f["ambiguity"] * 0.8)
        choice = max(probs, key=probs.get)  # type: ignore[arg-type]
        confidence = max(probs.values())
        return ChoiceResult(choice=choice, probabilities=probs, confidence=round(confidence, 4))

    def _answer_score(self, q: Score, f: Mapping[str, float]) -> ScoreResult:
        levels = list(q.criteria) or ["low", "elevated", "high", "critical"]
        r = (
            0.10
            + 0.34 * f["kev"]
            + 0.20 * f["exposed"] * f["criticality"]
            + 0.16 * f["epss"]
            + 0.12 * f["keyword_density"]
            + 0.08 * f["severity"]
            - 0.18 * f["unreachable"] * f["ambiguity"]
        )
        confidence = max(0.05, 1.0 - 0.9 * f["ambiguity"])
        # Uncertainty pulls the position toward the middle of the scale.
        position = 0.5 + (r - 0.5) * confidence
        center = position * (len(levels) - 1)
        sigma = 0.35 + 1.4 * (1.0 - confidence)
        weights = {lvl: math.exp(-((i - center) ** 2) / (2 * sigma * sigma)) for i, lvl in enumerate(levels)}
        probs = _normalize(weights)
        pos = sum(probs[lvl] * i for i, lvl in enumerate(levels)) / (len(levels) - 1)
        return ScoreResult(
            position=round(pos, 4),
            probabilities=probs,
            confidence=round(confidence, 4),
        )

    def _answer_noul(self, q: Noul, f: Mapping[str, float]) -> NoulResult:
        p = 0.06 + 0.80 * f["ambiguity"] + 0.30 * max(0.0, f["conflict"])
        return NoulResult(probability=round(min(p, 0.98), 4))


# Live client


class TypeSafeLiveClient(SystemOneClient):
    """Adapter over `typesafe-sdk`. Import fails loudly with install hint."""

    def __init__(self) -> None:
        super().__init__()
        try:
            from typesafe_sdk import Choice as SdkChoice  # noqa: PLC0415
            from typesafe_sdk import Noul as SdkNoul  # noqa: PLC0415
            from typesafe_sdk import Score as SdkScore  # noqa: PLC0415
            from typesafe_sdk import TypeSafeClient  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - depends on env
            raise RuntimeError(
                "Live mode needs typesafe-sdk: pip install 'jev-vulnops[live]'"
            ) from exc
        self._sdk_types = {"choice": SdkChoice, "score": SdkScore, "noul": SdkNoul}
        self._sdk_client_cls = TypeSafeClient
        self._client = TypeSafeClient()

    def _to_sdk(self, q: Choice | Score | Noul):  # pragma: no cover
        if isinstance(q, Choice):
            return self._sdk_types["choice"](instructions=q.instructions, criteria=dict(q.criteria))
        if isinstance(q, Score):
            return self._sdk_types["score"](instructions=q.instructions, criteria=dict(q.criteria))
        return self._sdk_types["noul"](instructions=q.instructions)

    def system_one(self, state, questions):  # pragma: no cover - needs API key
        sdk_questions = {name: self._to_sdk(q) for name, q in questions.items()}
        resp = self._client.system_one(state=dict(state), questions=sdk_questions)
        return self._map(resp, questions)

    def _map(self, resp, questions):  # pragma: no cover
        choices, scores, nouls = {}, {}, {}
        raw = getattr(resp, "answers", None) or getattr(resp, "choices", None) or {}
        for name, q in questions.items():
            if isinstance(q, Noul):
                v = getattr(raw, "get", lambda k: None)(name)
                nouls[name] = NoulResult(probability=float(getattr(v, "probability", v or 0)))
            elif isinstance(q, Score):
                v = getattr(raw, "get", lambda k: None)(name)
                scores[name] = ScoreResult(
                    position=float(getattr(v, "position", getattr(v, "score", 0))),
                    probabilities=getattr(v, "probabilities", {}) or {},
                    confidence=float(getattr(v, "confidence", 0) or 0),
                )
            else:
                v = getattr(resp.choices, "get", lambda k: None)(name) if hasattr(resp, "choices") else None
                if v is None and hasattr(raw, "get"):
                    v = raw.get(name)
                choices[name] = ChoiceResult(
                    choice=getattr(v, "choice", getattr(v, "selected", None)),
                    probabilities=getattr(v, "probabilities", getattr(v, "probs", {})) or {},
                    confidence=float(getattr(v, "confidence", 0) or 0),
                )
        return SystemOneResponse(choices=choices, scores=scores, nouls=nouls)
