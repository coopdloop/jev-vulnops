"""Question definitions layered on the SDK shape (Choice / Score / Noul).

Plain dataclasses so the mock client and the live adapter both work off the
same definitions. Jev answers all three question types in a single request
against a single encoding of the state, which is why we batch them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
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


# --- classifier sets -------------------------------------------------------
# Named bundles in API wire format (not the dataclasses above): the studio
# edits, imports and exports exactly this shape, and /api/ask consumes it.

WIRE_TYPES = ("choice", "score", "noul")


def validate_wire_questions(questions: object, where: str = "questions") -> dict:
    """Fail loudly on anything the API would reject, with a useful message."""
    if not isinstance(questions, dict) or not questions:
        raise ValueError(f"{where}: expected a non-empty object of questions")
    for name, q in questions.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{where}: question names must be non-empty strings")
        if " " in name:
            raise ValueError(f"{where}.{name}: question name must not contain spaces")
        if not isinstance(q, dict):
            raise ValueError(f"{where}.{name}: expected an object")
        qtype = q.get("type")
        if qtype not in WIRE_TYPES:
            raise ValueError(f"{where}.{name}: type must be one of {WIRE_TYPES}, got {qtype!r}")
        if not isinstance(q.get("instructions"), str) or not q["instructions"].strip():
            raise ValueError(f"{where}.{name}: instructions must be a non-empty string")
        criteria = q.get("criteria")
        if qtype == "noul":
            continue
        options = list(criteria) if isinstance(criteria, dict) else criteria
        if qtype == "choice" and not isinstance(criteria, dict):
            raise ValueError(f"{where}.{name}: choice criteria must be an object of option -> description")
        if qtype == "score" and not isinstance(criteria, list):
            raise ValueError(f"{where}.{name}: score criteria must be an ordered list of levels")
        if len(options) < 2:
            raise ValueError(f"{where}.{name}: {qtype} needs at least 2 criteria")
        for i, option in enumerate(options):
            if qtype == "choice":
                label, description = option, criteria[option]
            else:
                if not isinstance(option, dict):
                    raise ValueError(f"{where}.{name}.criteria[{i}]: expected {{name, description}}")
                label, description = option.get("name"), option.get("description")
            if not isinstance(label, str) or not label.strip():
                raise ValueError(f"{where}.{name}.criteria[{i}]: name must be a non-empty string")
            if not isinstance(description, str) or not description.strip():
                raise ValueError(f"{where}.{name}.criteria[{i}] ({label}): description must be non-empty")
    return questions


NEXT_ACTION_EXPOSURE_FIRST = {
    "type": "choice",
    "instructions": (
        "Decide the next action from the asset's exposure outward. Reachability "
        "outranks the vulnerability text: an unreachable asset is never urgent, an "
        "exposed business-critical one usually is."
    ),
    "criteria": {
        "remediate-now": "A path from an untrusted network to a tier-0/tier-1 asset exists.",
        "sla-remediate": "Reachable, but only from trusted segments or with limited blast radius.",
        "accept-risk": "No usable path to the asset, or the asset holds nothing of value.",
        "needs-intel": "Exposure or asset role is unknown from the state given.",
    },
}

EXPLOIT_30D_EXPOSURE_FIRST = {
    "type": "score",
    "instructions": (
        "Score the chance of exploitation in the next 30 days using exposure and "
        "asset role as the primary evidence; treat the CVE description as secondary."
    ),
    "criteria": [
        {"name": "low", "description": "Not reachable from any untrusted network."},
        {"name": "elevated", "description": "Reachable, but the asset is low-value or the path is awkward."},
        {"name": "high", "description": "Reachable and valuable: internet-facing or a payments/crown-jewel system."},
        {"name": "critical", "description": "Reachable, valuable, and already being hunted (KEV or public exploit)."},
    ],
}

ANALYST_REVIEW_AMBIGUITY = {
    "type": "noul",
    "instructions": (
        "Answer yes if the state alone cannot justify the score you just gave -- "
        "missing exposure data, contradictory asset role, or a description that "
        "does not say whether the vulnerable path is live."
    ),
}

BUSINESS_IMPACT = {
    "type": "score",
    "instructions": "If exploited, how much business damage would this asset take within a day?",
    "criteria": [
        {"name": "minor", "description": "Cosmetic or self-healing; no customer or money path."},
        {"name": "moderate", "description": "Degraded internal service; recoverable without customers noticing."},
        {"name": "major", "description": "Customer-visible outage or data exposure in non-payment systems."},
        {"name": "severe", "description": "Payment, PII or regulated data at risk; incident-level damage."},
    ],
}

TICKET_READY = {
    "type": "noul",
    "instructions": (
        "Answer yes if this triage could be handed straight to an on-call engineer "
        "as a ticket without any further questions (action, deadline and reason are "
        "all clear)."
    ),
}


def _set(set_id: str, name: str, description: str, questions: dict) -> dict:
    return {
        "id": set_id,
        "name": name,
        "description": description,
        "builtin": True,
        "questions": validate_wire_questions(questions, f"set {set_id}"),
    }


DEFAULT_SETS: tuple[dict, ...] = (
    _set(
        "baseline",
        "Baseline triage",
        "What the pipeline runs: action, exploit likelihood, analyst review.",
        wire_all(ALL_QUESTIONS),
    ),
    _set(
        "exposure-first",
        "Exposure first",
        "Same three questions, criteria rewritten so asset exposure outranks CVE text. "
        "Compare it against baseline to see how far the calibrated numbers move.",
        {
            "next_action": NEXT_ACTION_EXPOSURE_FIRST,
            "exploit_likelihood_30d": EXPLOIT_30D_EXPOSURE_FIRST,
            "needs_analyst_review": ANALYST_REVIEW_AMBIGUITY,
        },
    ),
    _set(
        "action-only",
        "Action only",
        "Single question: cheapest possible request when you only need routing.",
        {"next_action": wire(NEXT_ACTION)},
    ),
    _set(
        "wide",
        "Wide (5 questions)",
        "Baseline plus business impact and ticket-readiness -- one request still answers all five.",
        {
            **wire_all(ALL_QUESTIONS),
            "business_impact": BUSINESS_IMPACT,
            "ticket_ready": TICKET_READY,
        },
    ),
)


def load_classifier_sets(path: str) -> list[dict]:
    """Extra sets from --classifiers: a JSON array of sets, or {"sets": [...]}."""
    raw = json.loads(Path(path).read_text())
    entries = raw.get("sets") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise SystemExit(f"{path}: expected a JSON array of classifier sets (or {{'sets': [...]}})")
    loaded = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or not entry.get("questions"):
            raise SystemExit(f"{path}: set {i} needs at least a 'name' and a non-empty 'questions' object")
        loaded.append(
            _set(
                str(entry.get("id") or f"loaded-{i}"),
                str(entry.get("name") or f"Set {i}"),
                str(entry.get("description") or ""),
                entry["questions"],
            )
        )
    return loaded
