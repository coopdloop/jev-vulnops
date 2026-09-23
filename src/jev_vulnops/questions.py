"""Question definitions layered on the SDK shape (Choice / Score / Noul).

Plain dataclasses so the mock client and the live adapter both work off the
same definitions. Jev answers all three question types in a single request
against a single encoding of the state, which is why we batch them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Choice:
    instructions: str
    criteria: Mapping[str, str]


@dataclass(frozen=True)
class Score:
    instructions: str
    # Ordered levels, low -> high.
    criteria: Mapping[str, str]


@dataclass(frozen=True)
class Noul:
    instructions: str


NEXT_ACTION = Choice(
    instructions=(
        "Pick the single best next action for this vulnerability in this asset "
        "context, weighing exploitability and exposure. Choose exactly one option."
    ),
    criteria={
        "remediate-now": (
            "Exploitable or actively exploited, and the asset is critical or "
            "internet-exposed. Start remediation immediately."
        ),
        "sla-remediate": "Meaningful risk; fix within the normal remediation SLA.",
        "accept-risk": (
            "Low real-world exploitability, unreachable code path, or internal-only "
            "exposure. Document and accept the residual risk."
        ),
        "needs-intel": (
            "Signals are missing or conflicting; gather vendor/intel data before "
            "deciding."
        ),
    },
)

EXPLOIT_30D = Score(
    instructions=(
        "How likely is this vulnerability to be exploited against this specific "
        "asset within the next 30 days?"
    ),
    criteria={
        "low": "No known exploitation and no workable attacker path to this asset.",
        "elevated": "Plausible exploit path or public PoC exists, but exposure or "
        "asset role limits real risk.",
        "high": "Known exploitation activity, or an internet-exposed critical asset "
        "with a workable exploit.",
        "critical": "Actively exploited (e.g. CISA KEV) on an exposed, business-"
        "critical asset.",
    },
)

ANALYST_REVIEW = Noul(
    instructions=(
        "Answer yes (probability close to 1) if a human analyst should review this "
        "triage because signals conflict or the description is ambiguous; answer no "
        "(probability close to 0) otherwise."
    )
)

ALL_QUESTIONS = {
    "next_action": NEXT_ACTION,
    "exploit_likelihood_30d": EXPLOIT_30D,
    "needs_analyst_review": ANALYST_REVIEW,
}


def wire(q: Choice | Score | Noul) -> dict:
    """Serialize a question to the API wire format (what actually goes to Jev)."""
    if isinstance(q, Choice):
        return {"type": "choice", "instructions": q.instructions, "criteria": dict(q.criteria)}
    if isinstance(q, Score):
        return {
            "type": "score",
            "instructions": q.instructions,
            "criteria": [{"name": k, "description": v} for k, v in q.criteria.items()],
        }
    return {"type": "noul", "instructions": q.instructions}


def wire_all(questions: Mapping[str, Choice | Score | Noul]) -> dict[str, dict]:
    return {name: wire(q) for name, q in questions.items()}
