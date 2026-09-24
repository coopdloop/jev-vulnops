# Example classifier sets

Eight ready-made sets for the [Classifier studio](../README.md#web-ui), in the
same JSON the studio exports and `--classifiers` reads:

```bash
uv run jev-vulnops --web-ui --classifiers examples/classifiers-calibration.json
# or: studio tab -> import -> pick a file. Multiple files can be imported; ids
# collide, they are re-keyed (pci-soc2-evidence-2) rather than overwrite.
```

Each file holds one or more sets; each set is a named bundle of questions in API
wire format.

## What Jev can actually see

A classifier can only reason about signals present in the state, so write against
this shape (the fixtures in `data/sample_scan.json` use exactly it):

```json
{
  "vulnerability": { "cve_id", "title", "description", "cvss", "epss", "known_exploited" },
  "asset": { "name", "internet_exposed", "criticality_tier", "data_classification" }
}
```

`tier-0` means crown jewels, `data_classification` is one of `payments`, `pii`,
`corporate`, `internal`. Anything you ask about that is *not* in the state —
backup topology, IAM permissions, namespaces — is a legitimate question, but the
honest answer is low confidence or a high `P(yes)` on an "unknown" noul. Several
sets below are built to show exactly that.

## The sets

| File | Set | Questions | What it is for |
|---|---|---|---|
| `classifiers-ransomware.json` | `ransomware-blast-radius` | 5 | Containment, encryption reach, suspected dwell time, restore-without-paying, extortion leverage |
| | `backup-posture` | 3 | Recovery rather than intrusion: restore confidence, the action it implies, and whether isolation is unknown |
| `classifiers-compliance.json` | `pci-soc2-evidence` | 6 | The auditor's framing: disposition, gap severity, CDE scope, compensating control, SLA clock, scope ambiguity |
| | `regulatory-notification` | 3 | Notification duty and the first communication step |
| `classifiers-cloud.json` | `cloud-identity-exposure` | 6 | IAM action, tenant blast radius, egress risk, reachability, privilege posture, crypto risk |
| | `container-workload` | 4 | Workload response, node-escape likelihood, shared-namespace risk, image provenance |
| `classifiers-calibration.json` | `steer-toward-urgent` | 3 | Same question names as the baseline set, rubric written so almost anything reads as urgent |
| | `steer-toward-accept` | 3 | Mirror image: rubric written to protect engineering time |
| | `ambiguous-by-design` | 3 | Criteria that deliberately overlap, so no option is cleanly right |

## Try the calibration probes

Check `baseline`, `steer-toward-urgent`, `steer-toward-accept` and
`ambiguous-by-design` in the studio, press **Test selected sets ▶** and read the
answer matrix. Measured on `jev-1.13`, same state per row:

**CVE-2021-44228 (Log4Shell) on `payment-gateway`** — internet-exposed, tier-0,
payments, CVSS 10.0, EPSS 0.94, KEV-listed

| set | next_action | exploit_30d | analyst review |
|---|---|---|---|
| baseline | remediate-now (1.00) | 3.00 (1.00) | P0.25 |
| steer-toward-urgent | remediate-now (1.00) | 3.00 (1.00) | P0.12 |
| steer-toward-accept | **sla-remediate (0.36)** | 2.02 (0.82) | **P0.51** |
| ambiguous-by-design | remediate-now (0.99) | 2.31 (**0.31**) | **P0.57** |

The urgent rubric cannot push past the ceiling — the state already justifies
urgent — so nothing moves. The accept rubric *does* move the answer, but it
cannot make the model confident about it: `sla-remediate` at 0.36 confidence and
an analyst-review probability above 0.5 both trip the gate, so the item
escalates. Ambiguous criteria collapse the score's confidence to 0.31.

**CVE-2023-29489 on `shared-hosting-panel`** — internal, CVSS 6.1, EPSS 0.02,
not KEV-listed

| set | next_action | exploit_30d | analyst review |
|---|---|---|---|
| baseline | sla-remediate (0.68) | 0.97 (0.93) | P0.36 |
| steer-toward-urgent | **remediate-now (0.99)** | **2.97 (0.97)** | P0.11 |
| steer-toward-accept | **accept-risk (0.61)** | **0.37 (0.63)** | **P0.70** |
| ambiguous-by-design | remediate-now (**0.51**) | 0.61 (**0.55**) | **P0.55** |

Same state, same question names, opposite rubrics: two full buckets apart, and
confidently so — because the rubric really does say so. That is the point of
writing the criteria deliberately, and the reason the ambiguous set is useful:
when the rubric cannot decide, the numbers say so instead of picking a side.

## Writing your own

`choice` criteria is an object of `option -> description` (≥2), `score` criteria
is an **ordered list** of `{name, description}` levels (≥2, low → high), `noul`
takes instructions only:

```json
{
  "sets": [
    {
      "id": "my-set",
      "name": "My set",
      "description": "What it probes and why you would run it.",
      "questions": {
        "next_action": { "type": "choice", "instructions": "…", "criteria": { "a": "…", "b": "…" } },
        "risk_30d": { "type": "score", "instructions": "…", "criteria": [ { "name": "low", "description": "…" }, { "name": "high", "description": "…" } ] },
        "escalate": { "type": "noul", "instructions": "…" }
      }
    }
  ]
}
```

Rules the loader enforces (the studio enforces the same ones while you edit):
question names non-empty without spaces, non-empty instructions, ≥2 criteria for
choice/score, every criterion labelled and described. `tests/test_pipeline.py`
loads every file in this folder, so a broken example fails the suite.
