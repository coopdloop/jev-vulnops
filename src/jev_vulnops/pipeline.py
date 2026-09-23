"""Vulnops triage pipeline on top of the System One client.

Design follows the published guidance:
- arithmetic (SLA day math, tier thresholds) stays in code, never in the model
- one request per vuln, all questions batched in parallel
- confidence gates routing: low-confidence answers escalate to an analyst
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from .client import SystemOneResponse, TypeSafeLiveClient
from .questions import ALL_QUESTIONS, wire_all

LEVELS = ("low", "elevated", "high", "critical")

# SLA due dates computed in code -- the model is documented to be unreliable on
# date arithmetic, so policy math lives here.
SLA_DAYS = {"remediate-now": 14, "sla-remediate": 30, "accept-risk": 90, "needs-intel": 7}


def build_state(vuln: Mapping[str, Any]) -> dict[str, Any]:
    return {"vulnerability": vuln, "asset": vuln["asset"]}


def level_bucket(position: float) -> str:
    idx = min(len(LEVELS) - 1, max(0, int(position * len(LEVELS))))
    return LEVELS[idx]


def estimate_tokens(state: Mapping[str, Any], questions: Mapping[str, Any]) -> int:
    # ~4 chars/token heuristic + per-question overhead.
    state_tokens = len(json.dumps(state, default=str)) // 4
    q_tokens = sum(
        (len(q.instructions) + sum(len(v) for v in getattr(q, "criteria", {}).values() if isinstance(v, str))) // 4 + 20
        for q in questions.values()
    )
    return state_tokens + q_tokens


@dataclass
class TriageDecision:
    cve_id: str
    asset_name: str
    action: str
    action_confidence: float
    exploit_position: float
    exploit_bucket: str
    reviewer_probability: float
    disposition: str  # "AUTO" or "ESCALATE"
    reasons: list[str] = field(default_factory=list)
    due_days: int | None = None
    input_tokens: int = 0
    detail: dict[str, Any] = field(default_factory=dict)  # per-question probabilities + model/usage


def disposition(
    choice_confidence: float,
    reviewer_probability: float,
    threshold: float,
) -> tuple[str, list[str]]:
    """Pure routing rule: gate low-confidence / analyst-flagged answers."""
    reasons: list[str] = []
    if choice_confidence < threshold:
        reasons.append(f"next-action confidence {choice_confidence:.2f} < {threshold:.2f}")
    if reviewer_probability >= 0.5:
        reasons.append(f"analyst-review probability {reviewer_probability:.2f}")
    return ("ESCALATE" if reasons else "AUTO"), reasons


def triage(
    client: TypeSafeLiveClient,
    vuln: Mapping[str, Any],
    threshold: float = 0.75,
    model: str | None = None,
) -> TriageDecision:
    state = build_state(vuln)
    resp: SystemOneResponse = client.system_one(state, ALL_QUESTIONS, model=model)

    choice = resp.choices.get("next_action")
    score = resp.scores.get("exploit_likelihood_30d")
    gate = resp.nouls.get("needs_analyst_review")

    decis, reasons = disposition(
        choice.confidence if choice else 1.0,
        gate.probability if gate else 0.0,
        threshold,
    )

    usage = getattr(resp.raw, "usage", None)
    if usage is not None and hasattr(usage, "model_dump"):
        usage = usage.model_dump()
    raw_response = resp.raw.model_dump() if hasattr(resp.raw, "model_dump") else resp.raw

    return TriageDecision(
        cve_id=vuln["cve_id"],
        asset_name=vuln["asset"]["name"],
        action=choice.choice if choice else "unknown",
        action_confidence=choice.confidence if choice else 0.0,
        exploit_position=score.position if score else 0.0,
        exploit_bucket=level_bucket(score.position) if score else "unknown",
        reviewer_probability=gate.probability if gate else 0.0,
        disposition=decis,
        reasons=reasons,
        due_days=SLA_DAYS.get(choice.choice) if choice else None,
        input_tokens=estimate_tokens(state, ALL_QUESTIONS),
        detail={
            "model": getattr(resp.raw, "model", None),
            "usage": usage,
            "request": {"state": state, "questions": wire_all(ALL_QUESTIONS)},
            "response": raw_response,
            "next_action": {
                "choice": choice.choice if choice else None,
                "confidence": choice.confidence if choice else 0.0,
                "probabilities": dict(choice.probabilities) if choice else {},
            },
            "exploit_likelihood_30d": {
                "position": score.position if score else 0.0,
                "confidence": score.confidence if score else 0.0,
                "probabilities": dict(score.probabilities) if score else {},
            },
            "needs_analyst_review": {"probability": gate.probability if gate else 0.0},
        },
    )


def triage_all(
    client: TypeSafeLiveClient,
    vulns: list[Mapping[str, Any]],
    threshold: float = 0.75,
    model: str | None = None,
) -> list[TriageDecision]:
    return [triage(client, v, threshold, model=model) for v in vulns]
