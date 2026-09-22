"""CLI demo: vulnops triage over fixture CVEs against the live Jev endpoint.

Requires `TYPESAFE_API_KEY` (and `pip install 'jev-vulnops[live]'`).
"""

from __future__ import annotations

import argparse
import os
from typing import Sequence

from .client import TypeSafeLiveClient
from .data import VULNS
from .pipeline import triage_all
from .questions import ALL_QUESTIONS

PRICE_PER_MTTOK = 0.042  # published $/Million input tokens; outputs are free


def _fmt_table(decisions) -> str:
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


def provider_label() -> str:
    # TYPESAFE_BASE_URL -> OpenRouter or any compatible gateway; direct otherwise.
    base = os.environ.get("TYPESAFE_BASE_URL")
    if base and "openrouter" in base:
        return "OpenRouter"
    if base:
        return f"custom base ({base})"
    return "TypeSafe direct"


def run_demo(args: argparse.Namespace) -> int:
    if not os.environ.get("TYPESAFE_API_KEY"):
        raise SystemExit(
            "Set TYPESAFE_API_KEY first (either a TypeSafe console key, or an "
            "OpenRouter key with TYPESAFE_BASE_URL=https://openrouter.ai/api)"
        )
    client = TypeSafeLiveClient()
    decisions = triage_all(client, VULNS, args.threshold)

    print(f"jev-vulnops triage (live jev-1.13 via {provider_label()}) — {len(decisions)} vulns\n")
    print(_fmt_table(decisions))

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
    return run_demo(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
