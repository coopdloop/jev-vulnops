# jev-vulnops

Vulnerability triage powered by a **System One model** — not an LLM.
Unstructured vuln + asset context in, typed probabilistic decisions out,
in one request, in ~100 ms, for ~$0.00002 per decision.

## Why Jev is different

LLMs are superhuman at chat — but chat is the wrong interface for automation.
Every LLM call in a pipeline returns a *string*: it must be parsed, validated,
retried when malformed, and it always carries some risk of going off the
rails. Even when you ask for a confidence score, LLMs are overconfident and
inconsistent — and a model that can't say *when* it's wrong can't automate
anything unattended.

**System One models** (named for Kahneman's fast, intuitive System 1 thinking)
are built for the opposite job: fast, structured decisions that software can
use directly. TypeSafe's first System One model, **Jev**, differs from an LLM
in five fundamental ways:

| | LLMs | Jev (System One) |
|---|---|---|
| **Output** | Strings — anything, including hallucinations and type errors | Typed values from options *you* define. Type errors are mathematically impossible |
| **Sampling** | Sequential, token by token | Parallel — all answers in a single forward pass |
| **Confidence** | Ask for it, get overconfident guesses | Calibrated probabilities on every answer, always |
| **Latency** | 3–300 s end-to-end | 70–500 ms end-to-end |
| **Cost** | $0.20–$10 / Mtok in, ~5× more out | $0.042 / Mtok in, outputs free |

The training method mirrors the philosophy: instead of RLHF (optimize for
text humans prefer), Jev is trained with **RLCD — Reinforcement Learning for
Calibrated Decisions** — optimizing for *epistemically honest probabilities*.
When Jev says 0.95, it should be right ~95% of the time. That's what makes
confidence thresholds meaningful, and confidence thresholds are what make
unattended automation safe.

What you give up is text generation. Jev cannot write — no summaries, no
patches, no prose. The intended architecture is a division of labor:
**Jev decides, an LLM writes, code does the math.**

## What this repo is

A live, end-to-end demo of that philosophy applied to **vulnerability
operations triage** — the canonical "smart if-statement" use case. For each
CVE + asset context, one Jev request answers three questions in parallel:

- `Choice` — best next action: `remediate-now` / `sla-remediate` / `accept-risk` / `needs-intel`
- `Score` — exploit likelihood in the next 30 days (low → critical)
- `Noul` — should a human analyst review this? (yes/no probability)

Then **code** — not the model — gates on confidence: high-confidence triage
is auto-prioritized with SLA due dates; anything ambiguous is escalated to an
analyst with the full probability distributions attached. Real run on known
CVEs:

```text
CVE-2021-44228   payment-gateway   remediate-now    1.00  critical · 1.00    0.26  14d  AUTO
CVE-2023-22515   confluence-internal sla-remediate   0.40  elevated · 0.49    0.43  30d  ESCALATE
  escalate CVE-2023-22515: next-action confidence 0.40 < 0.75
```

Note the second row: KEV-listed and CVSS 10.0, but on an *internal-only*
asset — Jev weighs the exposure context and declines to auto-triage. That is
the calibration philosophy working as intended.

## Index

- [Why Jev is different](#why-jev-is-different) — System One philosophy, LLM comparison
- [What this repo is](#what-this-repo-is) — the demo in one paragraph
- [The pipeline](#the-pipeline) — state → questions → gate → SLA
- [Seeing the decision "logic"](#seeing-the-decision-logic) — probabilities as the explanation surface
- [What Jev sees (and what you control)](#what-jev-sees-and-what-you-control)
- [Architecture](#architecture) — end-to-end vuln management diagrams
- [Web UI](#web-ui) — live dashboard with real-time triage stream
- [Your own dataset](#your-own-dataset) — input format
- [Get a key](#get-a-key-two-routes) — TypeSafe direct or OpenRouter
- [Run it](#run-it) — install, flags, interactive mode
- [Limits](#limits)

## The pipeline

For each vulnerability:

1. **Build the state** — CVE description, CVSS/EPSS/KEV flags, and the asset
   context (exposure, criticality tier, data class).
2. **Ask 3 questions in one request** (`src/jev_vulnops/questions.py`) —
   answered in parallel against a single encoding of the state.
3. **Gate on confidence in code** (`src/jev_vulnops/pipeline.py`):
   next-action confidence ≥ threshold (default 0.75) **and** analyst-review
   probability < 0.5 → auto-prioritized; otherwise escalated with reasons.
4. **SLA math stays in code** — due windows (14/30/7/90 days) are computed
   locally. Jev is documented to be unreliable at arithmetic and dates, so
   numbers live in the surrounding code, not the model.

## Seeing the decision "logic"

There is no chain-of-thought to inspect — Jev answers in a single forward
pass, so the explanation surface is the **probability distribution over the
options you defined**, plus per-answer confidence. `--verbose` prints all of
it per vuln:

```text
CVE-2025-50002 (report-generator):
  next_action: accept-risk (conf 0.97) | needs-intel=0.00, accept-risk=0.98, sla-remediate=0.02, remediate-now=0.00
  exploit_30d: 0.01 (conf 0.97) | 0=0.97, 1=0.03, 2=0.00, 3=0.00
  analyst_review: 0.55
  model: typesafe/jev-1.13-20260917 | usage: input_tokens=884 output_tokens=100
```

`--interactive` is the best way to probe how wording changes move those
distributions — tweak a description or flip an asset flag and re-ask.

## What Jev sees (and what you control)

- **State**: built per vuln in `pipeline.build_state()` — vuln fields + asset
  context go in verbatim.
- **Questions**: `src/jev_vulnops/questions.py` — edit the criteria text to
  change what Jev is asked.
- **Model**: `--model jev-1.13` (or aliases `jev-latest` / `jev-preview`);
  the response's `model` field shows what actually served you.
- **Routing rule**: `pipeline.disposition()` — pure code; the confidence
  threshold is `--threshold`.

## Architecture

[`docs/end-to-end.md`](docs/end-to-end.md) has the full Mermaid diagrams:
detection (scanners) → normalization/enrichment → Jev triage → remediation
orchestration (Jira / GitHub / Slack tool calls) → verification & metrics —
and the per-request sequence diagram.

## Web UI

`uv run jev-vulnops --web-ui` opens a dashboard (stdlib server, no extra
dependencies) that mimics a traditional vuln management console. Nothing is
asked of Jev until you press **▶ Run triage** — each run is one billable request
per CVE — and the sidebar and detail pane are browsable beforehand:

- **Sidebar** — searchable/filterable vuln list; each row shows the inputs that
  drive the decision (severity dot for CVSS, EPSS, tier, KEV) plus its live
  disposition, and the three Jev classifier definitions with their criteria
- **KPI cards** — totals, auto vs. escalated, average confidence, average
  response time, and estimated cost **per decision**, priced from the real
  `usage.input_tokens` the API reports ($0.042/Mtok in, outputs free; billed
  cost is used directly when the route reports `usage.cost`)
- **Live analysis table** — one dense row per CVE, streamed over Server-Sent
  Events as Jev decides: next action, confidence / exploit-30d / analyst-review
  bars, response time, routing badge and the reason it escalated. Sortable
  (escalated first, least confident, exploit likelihood, CVSS), with a running
  `n/total analyzed` counter and a Stop button
- **Confidence gate, live** — the header slider re-routes every decision in the
  browser (`static/routing.js`, a mirror of `pipeline.disposition()`, checked
  against the Python rule by the test suite). Dragging it costs nothing: the
  probabilities are already in hand, so no new requests go out. Each confidence
  bar carries a tick marking where the gate sits
- **Run summary** — one line under the table: requests made, answers per
  request, average latency, input tokens, estimated cost
- **Payload dropdowns** — the exact request payload (state + questions) and the
  raw response Jev returned
- **Detail pane** — click any row: the state as facts (CVSS, EPSS, KEV, tier,
  exposure, data class, description), then the three full distributions, the
  arithmetic that produced the routing decision, and the model id / tokens /
  cost for that request
- **API playground tab** — edit the state JSON and the classifiers themselves
  (add/remove questions, rewrite criteria); JSON errors surface as you type and
  ⌘/Ctrl + ↵ sends. `Ask Jev` renders each answer as probability bars plus the
  request/response payload, and **Repeat ×3/×5** runs the same questions again
  and shows the mean probability with its spread across runs — the stability you
  cannot get out of a chat model

Threshold slider and model selector apply to the next run (the threshold also
re-routes the current one locally, for free). `--port` changes the port
(default 8765); `--data` swaps the dataset.

## Your own dataset

`--data file.json` expects a JSON array of vuln objects — the normalized
projection a scanner pipeline would produce (scanners don't emit this shape
natively; see `data/sample_scan.json` for a realistic example with known CVEs):

```json
[
  {
    "cve_id": "CVE-2025-12345",
    "title": "short label",
    "description": "what the vuln is, in words",
    "cvss": 9.8,
    "epss": 0.86,
    "known_exploited": true,
    "asset": {
      "name": "billing-db",
      "internet_exposed": true,
      "criticality_tier": "tier-0",
      "data_classification": "payments"
    }
  }
]
```

## Get a key (two routes)

1. **TypeSafe direct.** Create a key in the TypeSafe console and put it in
   `TYPESAFE_API_KEY`.
2. **OpenRouter.** OpenRouter routes System One models (`typesafe/jev-1.13`).
   Set `TYPESAFE_BASE_URL=https://openrouter.ai/api` and put your **OpenRouter**
   key in `TYPESAFE_API_KEY`. Usage bills to your OpenRouter account and
   responses carry `usage.cost`.

Copy `.env.example` to `.env` — the demo auto-loads it via python-dotenv
(explicitly set env vars override the file).

## Run it

```bash
uv venv
uv pip install -e '.[live,test]'
cp .env.example .env          # set values (direct or OpenRouter route)

uv run jev-vulnops            # live triage over the built-in fixtures
uv run pytest                 # pure-function tests only; no client doubles

# options:
uv run jev-vulnops --verbose                    # full probability distributions, model id, usage per vuln
uv run jev-vulnops --model jev-latest           # pick the model (jev-1.13 / jev-latest / jev-preview)
uv run jev-vulnops --data my_vulns.json         # your own dataset instead of the built-in fixtures
uv run jev-vulnops --interactive                # REPL: paste a vuln, see the decision detail
uv run jev-vulnops --web-ui                     # live dashboard with real-time triage stream
```

The adapter is `TypeSafeLiveClient` in `src/jev_vulnops/client.py`: it maps
plain question config objects to the SDK types and normalizes the SDK's
`SystemOneResponse(model, usage, answers)` into `ChoiceResult` / `ScoreResult`
/ `NoulResult` dataclasses. Validated against typesafe-sdk 0.7.x.

## Limits

- Fixture data is hand-written to exercise the routing rule; swap in your own
  CVE/asset exports to use it seriously.
- The token estimate is a strlen/4 heuristic — `usage` in the response (and
  `usage.cost` on OpenRouter) is the source of truth for billing.
- Without `TYPESAFE_API_KEY` the CLI fails fast by design; there is no offline
  fallback in this repo.
