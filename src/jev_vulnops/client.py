"""System One client: adapter over the official `typesafe-sdk`.

Published API shape (launch post + docs): answers to ALL question types ride on
one request against a single encoding of the state; every answer comes back
typed (choice / scale position / yes-no probability) with probabilities and,
for Choice and Score, a confidence value.
"""

from __future__ import annotations

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


class TypeSafeLiveClient:
    """Thin adapter over `typesafe-sdk`; fails loudly if it is not installed.

Validated against typesafe-sdk 0.7.x: responses come back as
SystemOneResponse(model, usage, answers) with ChoiceAnswer/ScoreAnswer/NoulAnswer.
"""

    def __init__(self) -> None:
        try:
            from typesafe_sdk import Choice as SdkChoice  # noqa: PLC0415
            from typesafe_sdk import Noul as SdkNoul  # noqa: PLC0415
            from typesafe_sdk import Score as SdkScore  # noqa: PLC0415
            from typesafe_sdk import TypeSafeClient  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "Live mode needs typesafe-sdk: pip install 'jev-vulnops[live]'"
            ) from exc
        self._sdk_types = {"choice": SdkChoice, "score": SdkScore, "noul": SdkNoul}
        self._client = TypeSafeClient()
        self.calls: list[tuple[dict, dict]] = []

    def _to_sdk(self, q: Choice | Score | Noul):
        if isinstance(q, Choice):
            return self._sdk_types["choice"](instructions=q.instructions, criteria=dict(q.criteria))
        if isinstance(q, Score):
            return self._sdk_types["score"](instructions=q.instructions, criteria=dict(q.criteria))
        return self._sdk_types["noul"](instructions=q.instructions)

    def system_one(
        self, state: Mapping[str, Any], questions: Mapping[str, Choice | Score | Noul]
    ) -> SystemOneResponse:
        self.calls.append((dict(state), dict(questions)))
        sdk_questions = {name: self._to_sdk(q) for name, q in questions.items()}
        resp = self._client.system_one(state=dict(state), questions=sdk_questions)
        return self._map(resp, questions)

    def _map(self, resp, questions):
        choices: dict[str, ChoiceResult] = {}
        scores: dict[str, ScoreResult] = {}
        nouls: dict[str, NoulResult] = {}
        for name, q in questions.items():
            v = resp.answers.get(name)
            if isinstance(q, Noul):
                nouls[name] = NoulResult(probability=float(getattr(v, "noul", 0.0)))
            elif isinstance(q, Score):
                scores[name] = ScoreResult(
                    position=float(getattr(v, "score", 0.0)),
                    probabilities=dict(getattr(v, "probabilities", None) or {}),
                    confidence=float(getattr(v, "confidence", 0.0)),
                )
            else:
                choices[name] = ChoiceResult(
                    choice=getattr(v, "choice", None),
                    probabilities=dict(getattr(v, "probabilities", None) or {}),
                    confidence=float(getattr(v, "confidence", 0.0)),
                )
        return SystemOneResponse(choices=choices, scores=scores, nouls=nouls)
