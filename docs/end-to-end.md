# End-to-end vulnerability management with Jev

Where the System One model sits in a full detect → triage → remediate → verify
loop, and which parts are model decisions vs. plain code vs. other tools.

## 1 · Architecture

```mermaid
flowchart TB
    subgraph DETECT["1 · DETECTION & INGESTION"]
        direction LR
        SCANNERS["Vuln scanners<br/>Tenable · Qualys · Wiz"]
        CODE["Code scanning<br/>SARIF · Semgrep"]
        SBOM["SBOM scanning<br/>Grype · CycloneDX"]
        RAW[("Raw scanner exports")]
        SCANNERS --> RAW
        CODE --> RAW
        SBOM --> RAW
    end

    subgraph NORM["2 · NORMALIZATION & ENRICHMENT"]
        direction LR
        NORMF["Normalize to flat vuln records<br/>cve_id · description · cvss · epss · kev"]
        NVD["NVD API"]
        EPSS["FIRST EPSS API"]
        KEV["CISA KEV catalog"]
        ASSETS[("Asset inventory / CMDB<br/>exposure · tier · data class")]
        RAW --> NORMF
        NVD --> NORMF
        EPSS --> NORMF
        KEV --> NORMF
        ASSETS --> NORMF
    end

    subgraph JEV["3 · CATEGORIZATION & PRIORITIZATION — jev-vulnops"]
        STATE["build_state()<br/>vuln fields + asset context"]
        REQ["ONE Jev request<br/>3 questions answered in parallel"]
        Q1["Choice · next_action<br/>remediate-now / sla-remediate /<br/>accept-risk / needs-intel"]
        Q2["Score · exploit_likelihood_30d<br/>low · elevated · high · critical"]
        Q3["Noul · needs_analyst_review<br/>yes/no probability"]
        GATE{"Confidence gate<br/>— pure code —"}
        STATE --> REQ
        REQ --> Q1
        REQ --> Q2
        REQ --> Q3
        Q1 --> GATE
        Q2 --> GATE
        Q3 --> GATE
    end

    AUTO["AUTO path<br/>SLA due dates computed in code"]
    ESC["ESCALATE path<br/>analyst review queue"]
    ANALYST["Human analyst<br/>confirm / override"]

    GATE -->|"conf ≥ 0.75 AND review < 0.5"| AUTO
    GATE -->|"low conf OR review ≥ 0.5"| ESC
    ESC --> ANALYST
    ANALYST --> AUTO

    subgraph REMEDIATE["4 · REMEDIATION ORCHESTRATION — tool calls"]
        JIRA["Jira<br/>create ticket · set SLA field · transitions"]
        GH["GitHub<br/>issue · branch · fix PR · link commits"]
        LLM["LLM (Claude / GPT)<br/>drafts patch & writeup — Jev only decides"]
        SLACK["Slack / email<br/>notify owner · log commitments"]
    end

    AUTO --> JIRA
    AUTO --> GH
    GH --> LLM
    AUTO --> SLACK

    subgraph VERIFY["5 · VERIFICATION & METRICS"]
        RESCAN["Rescan after fix"]
        CLOSE["Close ticket · attestation"]
        METRICS["Dashboard<br/>MTTR · SLA % · backlog aging"]
        RESCAN --> CLOSE
        CLOSE --> METRICS
    end

    GH --> RESCAN
    JIRA --> CLOSE
    METRICS -. "tune thresholds & question criteria" .-> JEV

    classDef model fill:#e8f0fe,stroke:#3b82f6,stroke-width:2px
    classDef code fill:#fef3c7,stroke:#d97706
    classDef human fill:#fee2e2,stroke:#dc2626
    class REQ,Q1,Q2,Q3 model
    class GATE,AUTO code
    class ANALYST,ESC human
```

## 2 · One triage request, end to end

```mermaid
sequenceDiagram
    autonumber
    participant Scan as Scanner export
    participant Pipe as jev-vulnops pipeline
    participant Jev as Jev (System One)
    participant Code as Policy code
    participant Jira
    participant GitHub
    participant Slack

    Scan->>Pipe: normalized vuln + asset context
    Pipe->>Jev: system_one(state, {Choice, Score, Noul})
    Jev-->>Pipe: typed answers + probabilities + confidence<br/>(~70–500 ms, no text generation)
    Pipe->>Code: disposition(conf, review_p, threshold)
    alt AUTO (confident)
        Code->>Jira: create ticket, set SLA due date
        Code->>GitHub: open issue / draft fix PR
        Code->>Slack: notify owner, log commitment
    else ESCALATE (low confidence)
        Code->>Slack: analyst queue ping with reasons + probabilities
    end
    GitHub-->>Pipe: PR merged / commit linked
    Pipe->>Scan: trigger rescan
    Scan-->>Pipe: finding no longer detected
    Pipe->>Jira: transition to Done
```

## How to read it

**Phases 1–2 are plumbing, not AI.** Scanners emit heterogeneous exports; a
normalizer flattens them into the records this repo consumes
(`data/sample_scan.json` shape) and enriches them with EPSS scores, KEV
membership, and asset context from the CMDB. Asset context is the key input
Jev can't know on its own — the same CVE on an exposed tier-0 asset and an
internal tier-3 asset must come out differently.

**Phase 3 is where Jev lives.** One request per vuln carries all three
questions; answers come back typed with probabilities in ~70–500 ms. The
*gate is code, not model*: confidence thresholds, SLA day math, and the
escalate-vs-auto rule live in `pipeline.disposition()`. That's deliberate —
Jev is documented to be unreliable at arithmetic and dates, so numbers stay
out of the model and in the surrounding code.

**Phase 4 is tool calls.** Once the decision is made, ordinary integrations
do the work: Jira tickets with SLA fields, GitHub issues/PRs, Slack
notifications with logged commitments. Note the division of labor: **Jev
decides, an LLM writes.** Patch drafts and ticket prose need text generation,
which Jev explicitly doesn't do — so a Claude/GPT call handles that, while
Jev's calibrated probability decides *whether* it's worth doing at all.

**Phase 5 closes the loop.** A merged PR triggers a rescan; a clean rescan
closes the ticket; MTTR/SLA metrics feed back into threshold and question
tuning. Escalated items go to a human with the full probability distributions
attached (`--verbose` output), so the review is fast and auditable.

**Mapping to your existing projects:** this repo (`jev-vulnops`) is phase 3;
`vulngent` is phases 4–5 (outreach, commitments, GitHub/Jira linking, ledger,
dashboards). A natural integration is vulngent's triage agent calling this
pipeline instead of an LLM for the decision step.
