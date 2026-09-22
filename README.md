# jev-vulnops

A live demo of [TypeSafe's System One model **Jev**](https://typesafe.ai/blog/introducing-system-one-models-and-jev)
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
   context (exposure, criticality tier, data class).
2. **Ask 3 questions in one request** (`jev_vulnops/questions.py`):
   - `Choice` — best next action: `remediate-now`, `sla-remediate`,
     `accept-risk`, `needs-intel`
   - `Score` — exploit likelihood in the next 30 days on an ordered
     low/elevated/high/critical scale (probability-weighted position)
   - `Noul` — should an analyst review this? (one yes/no probability)
3. **Gate on confidence in code** (`jev_vulnops/pipeline.py`):
   - next-action confidence ≥ threshold (default 0.75) **and** analyst-review
     probability < 0.5 → auto-prioritized
   - otherwise → escalated to an analyst, with the deciding reasons printed
4. **SLA math stays in code** — due windows (14/30/7/90 days) are computed
   locally; the model weighs exposure and exploitability, the surrounding code
   does dates and thresholds. That's the intended integration pattern.

## Get a key (two routes)

Either of these works:

1. **TypeSafe direct.** Create a key in the TypeSafe console and put it in
   `TYPESAFE_API_KEY`.
2. **OpenRouter.** OpenRouter routes System One models (`typesafe/jev-1.13`).
   Set `TYPESAFE_BASE_URL=https://openrouter.ai/api` and put your **OpenRouter**
   key in `TYPESAFE_API_KEY`. Usage then bills to your OpenRouter account and
   responses carry `usage.cost`. If you already use OpenRouter elsewhere, this
   keeps billing in one place.

The SDK reads both env vars on its own; the demo prints which route is active.
Copy `.env.example` to `.env` — `jev-vulnops` auto-loads it via python-dotenv
(explicitly set env vars override values from the file).

```bash
uv venv
uv pip install -e '.[live,test]'

# either:
cp .env.example .env          # set values (direct or OpenRouter route)

uv run jev-vulnops            # auto-loads .env; hits the live endpoint (jev-1.13)
uv run pytest                 # pure-function tests only; no client doubles
```

The adapter is `TypeSafeLiveClient` in `jev_vulnops/client.py`: it maps the
plain question config objects to the SDK types and normalizes the SDK's
`SystemOneResponse(model, usage, answers)` into `ChoiceResult` / `ScoreResult`
/ `NoulResult` dataclasses. Validated against typesafe-sdk 0.7.x offline; the
live endpoint itself still needs a key to exercise end-to-end.

## What it demonstrates

- **Parallel questions, one request** — next action + exploit score + review
  gate resolved against a single encoding of the state.
- **Confidence-aware routing** — low-confidence triage is escalated rather than
  silently auto-applied; escalation reasons are printed with probabilities.
- **Typed decisions as function calls** — nothing to parse; every answer is a
  member of a pre-defined option set with probabilities.
- **Cheap automation economics** — cost printouts at the published rate
  ($0.042/M input tokens, outputs free) so a run's spend is visible.

## Limits

- Fixture data is hand-written to exercise the routing rule; swap in your own
  CVE/asset exports to use it seriously.
- The `Estimate tokens` figure is a strlen/4 heuristic — the console/SDK is the
  source of truth for real billing.
- Without `TYPESAFE_API_KEY` the CLI fails fast by design; there is no offline
  fallback in this repo.
