"""CLI demo: vulnops triage over fixture CVEs with a System One client.

Modes:
  offline (default)  -- deterministic heuristic mock, no API key needed
  --live             -- adapter over typesafe-sdk (needs TYPESAFE_API_KEY set)
"""

from __future__ import annotations

import argparse
import os
import time
from typing import Sequence

from .client import MockSystemOneClient, SystemOneClient, TypeSafeLiveClient
from .data import VULNS
from .pipeline import triage
from .questions import ALL_QUESTIONS

PRICE_PER_MTTOK = 0.042  # published $/Million input tokens; outputs are free


def make_client(live: bool) -> tuple[SystemOneClient, str]:
    if live:
        if not os.environ.get("TYPESAFE_API_KEY"):
            raise SystemExit("--live requires TYPESAFE_API_KEY in the environment")
        return TypeSafeLiveClient(), "live"
    return MockSystemOneClient(), "mock"


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


def run_demo(args: argparse.Namespace) -> int:
    client, mode = make_client(args.live)
    states = [v for v in VULNS]
    t0 = time.perf_counter()
    decisions = [triage(client, v, args.threshold) for v in states]
    wall_ms = (time.perf_counter() - t0) * 1000

    print(f"jev-vulnops triage ({mode} client) — {len(decisions)} vulns\n")
    print(_fmt_table(decisions))

    total_tokens = sum(d.input_tokens for d in decisions)
    cost_usd = total_tokens / 1_000_000 * PRICE_PER_MTTOK
    print()
    print(f"Total estimated input tokens: {total_tokens:,} → est. cost ${cost_usd:.6f} (outputs are free)")
    if mode == "mock":
        n = args.benchmark
        t0 = time.perf_counter()
        for i in range(n):
            triage(client, states[i % len(states)], args.threshold)
        wall_us = (time.perf_counter() - t0) * 1e6 / n
        print(
            f"Benchmark (mock): {n} decisions avg {wall_us:.0f} µs/decision in-process; "
            "expect ~70–500ms/decision against the live endpoint."
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="jev-vulnops", description=__doc__)
    parser.add_argument("--live", action="store_true", help="use typesafe-sdk (needs TYPESAFE_API_KEY)")
    parser.add_argument("--threshold", type=float, default=0.75, help="next-action confidence gate (default 0.75)")
    parser.add_argument("--benchmark", type=int, default=200, help="mock benchmark iterations (default 200)")
    return run_demo(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
