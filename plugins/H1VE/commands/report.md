---
name: report
description: >
  Write a vulnerability report for submission to HackerOne.
  Runs the full VERIFY protocol (V8 + V9) before allowing submission.
  Usage: /report <vuln_type> <asset> <handle>
---

# Report Writing

## Pre-Report Checks

1. Confirm vulnerability is real (not false positive)
2. Run V8 Post-Finding Verification:
   - V8.1 Impact Chain Verification (with evidence)
   - V8.2 Severity Validation
   - V8.3 False Positive Checklist
   - V8.4 PoC Completeness

## Report Structure

Write the report following these rules:

- No filler. Every sentence states a fact or proves a claim.
- No dashes, em dashes, or decorative punctuation. Use periods.
- Include live proof URLs. Triagers click links.
- Show raw JSON responses, not summaries.
- Every impact claim names a victim and an action.
- Do not write "could potentially" or "may allow". Write what happened.
- CVSS vector and severity label must agree.

## Pre-Submission Gate (V9)

ALL must pass before submission is allowed:
1. `python3 scripts/tracker.py dupe-check <vuln_type> <asset>` (exit 2 = BLOCKED)
2. `h1_hacktivity <handle>` (search for similar vulns)
3. V8.1 Impact Chain verified
4. V8.2 Severity validated
5. V8.3 False Positive checklist clear
6. V8.4 PoC complete
7. CVSS auto-score matches claimed severity

ANY failure = DO NOT SUBMIT. Fix first.

## After Writing

Save report to `data/reports/` via tracker.py. Present to user for review before submission.
