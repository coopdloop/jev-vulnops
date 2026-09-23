"""CLI demo: vulnops triage over CVEs against the live Jev endpoint.

Requires `TYPESAFE_API_KEY` (and `pip install 'jev-vulnops[live]'`); reads `.env`
automatically. See `--help` for dataset/model/verbose/interactive options.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Sequence

from dotenv import load_dotenv

from .client import TypeSafeLiveClient
from .data import VULNS
from .pipeline import TriageDecision, triage, triage_all
from .questions import ALL_QUESTIONS

PRICE_PER_MTTOK = 0.042  # published $/Million input tokens; outputs are free


def provider_label() -> str:
    # TYPESAFE_BASE_URL -> OpenRouter or any compatible gateway; direct otherwise.
    base = os.environ.get("TYPESAFE_BASE_URL")
    if base and "openrouter" in base:
        return "OpenRouter"
    if base:
        return f"custom base ({base})"
    return "TypeSafe direct"


def load_vulns(path: str | None) -> list[dict[str, Any]]:
    """Dataset: built-in fixtures, or a JSON array of vuln objects (same shape)."""
    if not path:
        return VULNS
    data = json.loads(Path(path).read_text())
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a JSON array of vuln objects")
    for v in data:
        missing = {"cve_id", "description", "asset"} - set(v)
        if missing:
            raise SystemExit(f"{path}: vuln {v.get('cve_id', '?')} missing keys: {sorted(missing)}")
    return data


def _fmt_table(decisions: list[TriageDecision]) -> str:
    header = f"{'CVE':<16} {'ASSET':<17} {'NEXT ACTION':<15} {'CONF':>5} {'EXPLOIT(30d)':<19} {'ANALYST?':>9} {'DUE':>4} {'DISPOSITION':<10}"
    lines = [header, "-" * len(header)]
    for d in decisions:
        bucket = f"{d.exploit_bucket} · {d.exploit_position:.2f}"
        due = f"{d.due_days}d" if d.due_days is not None else "-"
        lines.append(
            f"{d.cve_id:<16} {d.asset_name:<17} {d.action:<15} {d.action_confidence:>5.2f} "
            f"{bucket:<19} {d.reviewer_probability:>9.2f} {due:>4} {d.disposition:<10}"
        )
    escalated = [d for d in decisions if d.disposition == "ESCALATE"]
    auto = [d for d in decisions if d.disposition == "AUTO"]
    lines.append("")
    for d in escalated:
        lines.append(f"  escalate {d.cve_id}: " + "; ".join(d.reasons))
    if escalated:
        lines.append("")
    lines.append(
        f"Totals: {len(auto)} auto-prioritized, {len(escalated)} escalated to analyst, "
        f"{len(decisions)} vulns, {len(ALL_QUESTIONS)} parallel questions per request"
    )
    return "\n".join(lines)


def _fmt_detail(d: TriageDecision) -> str:
    """Raw answer detail: full probability distributions, confidence, model, usage."""
    det = d.detail
    na = det.get("next_action", {})
    sc = det.get("exploit_likelihood_30d", {})
    nl = det.get("needs_analyst_review", {})
    na_probs = ", ".join(f"{k}={v:.2f}" for k, v in na.get("probabilities", {}).items())
    sc_probs = ", ".join(f"{k}={v:.2f}" for k, v in sc.get("probabilities", {}).items())
    lines = [
        f"{d.cve_id} ({d.asset_name}):",
        f"  next_action: {na.get('choice')} (conf {na.get('confidence', 0.0):.2f}) | {na_probs}",
        f"  exploit_30d: {sc.get('position', 0.0):.2f} (conf {sc.get('confidence', 0.0):.2f}) | {sc_probs}",
        f"  analyst_review: {nl.get('probability', 0.0):.2f}",
    ]
    if det.get("model"):
        lines.append(f"  model: {det['model']} | usage: {det.get('usage')}")
    return "\n".join(lines)


def run_interactive(client: TypeSafeLiveClient, threshold: float, model: str | None) -> int:
    print("Interactive triage — describe a vuln, get the full decision detail. Ctrl-C to quit.\n")
    try:
        while True:
            vuln = {
                "cve_id": input("cve_id: ") or "CVE-0000-0000",
                "title": input("title: ") or "untitled",
                "description": input("description: "),
                "cvss": float(input("cvss 0-10 [5.0]: ") or 5.0),
                "epss": float(input("epss 0-1 [0.01]: ") or 0.01),
                "known_exploited": input("known exploited? (y/N): ").strip().lower() == "y",
                "asset": {
                    "name": input("asset name: ") or "asset",
                    "internet_exposed": input("internet exposed? (y/N): ").strip().lower() == "y",
                    "criticality_tier": input("criticality tier [tier-2]: ") or "tier-2",
                    "data_classification": input("data class [internal]: ") or "internal",
                },
            }
            d = triage(client, vuln, threshold, model=model)
            print()
            print(_fmt_detail(d))
            print(f"-> {d.action} | {d.disposition}\n")
            if input("another? (Y/n): ").strip().lower() == "n":
                break
    except (KeyboardInterrupt, EOFError):
        print()
    return 0


def run_demo(args: argparse.Namespace) -> int:
    load_dotenv()  # auto-pick .env from cwd (or parents); explicit env vars win
    if not os.environ.get("TYPESAFE_API_KEY"):
        raise SystemExit(
            "Set TYPESAFE_API_KEY first (either a TypeSafe console key, or an "
            "OpenRouter key with TYPESAFE_BASE_URL=https://openrouter.ai/api)"
        )
    client = TypeSafeLiveClient()

    if args.web_ui:
        from .web import run_web

        return run_web(client, load_vulns(args.data), port=args.port)

    if args.interactive:
        return run_interactive(client, args.threshold, args.model)

    vulns = load_vulns(args.data)
    decisions = triage_all(client, vulns, args.threshold, model=args.model)

    model_tag = args.model or "default"
    print(f"jev-vulnops triage (live {model_tag} via {provider_label()}) — {len(decisions)} vulns\n")
    print(_fmt_table(decisions))
    if args.verbose:
        print()
        for d in decisions:
            print(_fmt_detail(d))

    total_tokens = sum(d.input_tokens for d in decisions)
    cost_usd = total_tokens / 1_000_000 * PRICE_PER_MTTOK
    provider = provider_label()
    print()
    if provider == "OpenRouter":
        print("Billing is on your OpenRouter account; responses carry usage.cost.")
    else:
        print(
            f"Estimated input tokens: {total_tokens:,} → est. cost ${cost_usd:.6f} "
            "(outputs are free)"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="jev-vulnops", description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.75, help="next-action confidence gate (default 0.75)")
    parser.add_argument("--data", help="JSON file with vuln objects (default: built-in fixtures)")
    parser.add_argument("--model", help="model id, e.g. jev-1.13 / jev-latest / jev-preview")
    parser.add_argument("--verbose", action="store_true", help="print full probability distributions, model id and usage per vuln")
    parser.add_argument("--interactive", action="store_true", help="REPL: describe a vuln, see the decision detail")
    parser.add_argument("--web-ui", action="store_true", help="open the live dashboard (SSE stream of triage decisions)")
    parser.add_argument("--port", type=int, default=8765, help="web UI port (default 8765)")
    return run_demo(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
