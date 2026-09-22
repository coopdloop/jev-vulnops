# jev-vulnops

A demo of [TypeSafe's System One model **Jev**](https://typesafe.ai/blog/introducing-system-one-models-and-jev)
applied to **vulnerability operations triage**: unstructured vuln + asset context in,
typed probabilistic decisions out — in one request, with per-answer calibrated
probabilities used for routing.

## Why vulnops (and not "logging + metrics")?

Two applications were on the table:

- **Security logging & metrics.** Log/event classification fits Jev, but the
  *metrics* half (aggregation, anomaly math, date windows) is squarely in the
  model's documented weakness zone — Jev is unreliable at counting, arithmetic
  and date reasoning, and its docs say those jobs stay in code.
- **Vulnop triage.** Reachability/exploit judgements over CVE text + asset
  context with a bounded action space (fix now / SLA / accept risk / gather
  intel) is the canonical "smart if-statement" use case. Confidence thresholds
  route ambiguous cases to analysts. That's what this demo builds.

## The pipeline

For each vulnerability in `jev_vulnops/data.py`:

1. **Build the state** — CVE description, CVSS/EPSS/KEV flags, and the asset
   context (exposure, criticality tier, data class). All numbers are still
   carried as fields; the model reads them as context.
2. **Ask 3 questions in one request** (`jev_vulnops/questions.py`):
   - `Choice` — best next action: `remediate-now`, `sla-remediate`,
     `accept-risk`, `needs-intel`
   - `Score` — exploit likelihood in the next 30 days on an ordered
     low/elevated/high/critical scale (returns a probability-weighted position)
   - `Noul` — should an analyst review this? (one yes/no probability)
3. **Gate on confidence in code** (`jev_vulnops/pipeline.py`):
   - next-action confidence ≥ threshold (default 0.75) **and** analyst-review
     probability < 0.5 → auto-prioritized
   - otherwise → escalated to an analyst, with the deciding reasons listed
4. **SLA math stays in code** — due windows (14/30/7/90 days) are computed
   locally; the model weighs exposure and exploitability, the surrounding code
   does dates and thresholds. That's the intended integration pattern.

## Run it

```bash
uv venv
uv pip install -e '.[test]'

uv run jev-vulnops            # offline demo (deterministic mock client)
uv run jev-vulnops --live     # live via typesafe-sdk; needs TYPESAFE_API_KEY
uv run pytest                 # tests run against the mock
```

Offline mode uses `MockSystemOneClient` — a deterministic heuristic over the
same interface, clearly labeled as a mock. The live path
(`TypeSafeLiveClient`) imports `typesafe-sdk` and maps results into the same
dataclasses. **The live adapter has not been exercised against the real
endpoint** (there is no API key in this repo and the SDK's response accessor
shape across versions combines `response.choices`/`response.answers`); it is a
structurally faithful adapter, not a verified one.

Example output (mock mode):

```text
jev-vulnops triage (mock client) — 8 vulns

CVE              ASSET              NEXT ACTION     CONF  EXPLOIT(30d)         ANALYST?  DUE  DISPOSITION
---------------------------------------------------------------------------------------------------------
CVE-2025-31404   billing-db         remediate-now   0.93  critical · 0.86       0.06      14d  AUTO
CVE-2025-30333   customer-saas      needs-intel     0.44  elevated · 0.38       0.71      7d   ESCALATE
  escalate CVE-2025-30333: next-action confidence 0.44 < 0.75; analyst-review probability 0.71

Totals: 6 auto-prioritized, 2 escalated to analyst, 8 vulns, 3 parallel questions per request
Total estimated input tokens: 3,912 → est. cost $0.000164 (outputs are free)
```

## What it demonstrates

- **Parallel questions, one request** — next action + exploitation score +
  review gate resolved against a single encoding of the state.
- **Confidence-aware routing** — low-confidence triage is escalated rather than
  silently auto-applied.
- **Typed decisions as function calls** — nothing to parse, nothing generated;
  every answer is a member of a pre-defined option set with probabilities.
- **Seam design** — swapping between mock and live clients is a one-line change
  (`make_client`), so the demo remains runnable and testable without an API key.

## Limits

- Fixture data is hand-written; the mock's heuristics are keyword/flag based
  and not a substitute for the real model.
- Cost/latency figures in mock mode are estimates; the published rate card is
  $0.042 per million input tokens with free outputs, and ~70–500 ms per decision.
- The `--live` path may need accessor adjustments once exercised against the
  real SDK version you pin.
