/* Confidence gate, mirrored from jev_vulnops.pipeline.disposition().

The UI re-routes locally while you drag the threshold: every probability needed
for the decision is already streamed, so re-gating is free arithmetic in code --
which is the whole division of labour this demo argues for (Jev answers, code
decides). tests/test_pipeline.py checks this mirror against the Python rule. */

const REVIEWER_ESCALATE_AT = 0.5;

function routeOf(decision, threshold) {
  const reasons = [];
  const conf = Number(decision.action_confidence);
  const reviewer = Number(decision.reviewer_probability);
  if (conf < threshold) {
    reasons.push(`next-action confidence ${conf.toFixed(2)} < ${Number(threshold).toFixed(2)}`);
  }
  if (reviewer >= REVIEWER_ESCALATE_AT) {
    reasons.push(`analyst-review probability ${reviewer.toFixed(2)}`);
  }
  return { disposition: reasons.length ? "ESCALATE" : "AUTO", reasons };
}

if (typeof module !== "undefined") module.exports = { REVIEWER_ESCALATE_AT, routeOf };
