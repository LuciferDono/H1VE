# VERIFY Protocol — Mandatory Post-Finding Verification

> **This protocol is LAW. After EVERY finding, EVERY confirmed vulnerability, EVERY report draft —
> run the applicable verification checks BEFORE claiming the work is done.
> No partial passes. No "probably works". No skipping.
> If a check fails, stop, fix, and rerun from the top of that section.**

---

## When This Protocol Triggers

This protocol runs AUTOMATICALLY after:
1. **Any vulnerability is confirmed** — before writing the report
2. **Any report draft is created** — before submission
3. **Any PoC is generated** — before attaching to report
4. **Any session ends** — system integrity check
5. **Any new target is added** — infrastructure check
6. **On session start** — full system health check

**No forward progress until verification passes 100%.**

---

## Failure Handling (STRICT)

If ANY step produces output that doesn't match expected:
1. Print the actual output verbatim
2. Print what was expected
3. Diagnose the delta
4. Fix the root cause
5. Rerun the ENTIRE verification section from the top — not just the failing step

---

## V1: Infrastructure Verification (Run on session start + after any file changes)

### V1.1 — Directory structure

```bash
find . -not -path './.git/*' -not -path './.claude/*' -not -path './node_modules/*' -type d | sort
```

ASSERT: These directories exist:
- `./data`, `./data/reports`, `./data/recon`, `./data/targets`
- `./docs`, `./docs/plans`
- `./poc`, `./scripts`

### V1.2 — .gitkeep files

```bash
find . -name ".gitkeep" | sort
```

ASSERT: All 4 present:
- `./data/recon/.gitkeep`
- `./data/reports/.gitkeep`
- `./data/targets/.gitkeep`
- `./poc/.gitkeep`

### V1.3 — .gitignore blocks sensitive files

```bash
cat .gitignore
```

ASSERT: Contains ALL of: `.env`, `*.env`, `data/recon/*/`, `poc/`

### V1.4 — No sensitive files committed

ASSERT: `.env` not tracked by git (`git ls-files .env` returns empty)

---

## V2: h1api.sh Verification (Run on session start)

### V2.1 — Syntax check
```bash
bash -n scripts/h1api.sh
```
ASSERT: Exit code 0, no output.

### V2.2 — All 8 functions defined
```bash
grep -E "^(h1api|h1api_batch|h1_programs|h1_my_reports|h1_report|h1_program|h1_scopes|h1_hacktivity)\(\)" scripts/h1api.sh | sort
```
ASSERT: All 8 present.

### V2.3 — Credential loading
ASSERT: `_h1_load_creds` defined AND called inside `h1api()`.
ASSERT: Both `HACKERONE_USERNAME` and `HACKERONE_API_TOKEN` referenced.

### V2.4 — Error codes handled
ASSERT: HTTP codes 401, 403, 404, 429 all handled.
ASSERT: 429 handler includes `sleep 60` and retry.

### V2.5 — Live API call
```bash
source scripts/h1api.sh && h1_programs 2 | python3 -c "import sys,json; json.load(sys.stdin); print('JSON_VALID')"
```
ASSERT: Last line is `JSON_VALID`. No `ERROR` lines.

---

## V3: CONTEXT.md Verification (Run on session start + session end)

### V3.1 — All required sections
```bash
grep -n "^##" CONTEXT.md
```
ASSERT: All 5 present in order:
- `## Active Targets`
- `## Open Threads`
- `## Known Dead Ends`
- `## Preferences`
- `## Session Log`

### V3.2 — Preferences complete
ASSERT: Contains: `poc_style`, `report_style`, `always_include_business_impact`, `escalation_thresholds`, `new_no_response: 14 days`, `triaged_no_resolution: 30 days`

### V3.3 — Session Log has entries
ASSERT: At least one line with `YYYY-MM-DD` format date.

---

## V4: tracker.py Verification (Run on session start + after any tracker operations)

### V4.1 — Syntax check
```bash
python3 -m py_compile scripts/tracker.py && echo "SYNTAX_OK"
```
ASSERT: Last line is `SYNTAX_OK`.

### V4.2 — All 11 commands implemented
ASSERT: Help shows: `report create`, `report get`, `report update`, `report list`, `target create`, `target get`, `target update`, `target list`, `dupe-check`, `escalation-check`, `sync-status`

### V4.3 — Dupe-check exit codes
- No match: exit code 0
- Match found: exit code 2 (HARD BLOCK)

### V4.4 — Escalation check
Reports with `status: new` and `submitted_at` older than 14 days MUST be flagged.
Reports with `status: triaged` and `submitted_at` older than 30 days MUST be flagged.

### V4.5 — sync-status idempotency
Syncing to same status MUST NOT create duplicate timeline entries.
Output: `UNCHANGED: h1-{id} still {status}`

---

## V5: session_init.sh Verification (Run on session start)

### V5.1 — Runs to completion
```bash
bash scripts/session_init.sh
```
ASSERT: All 4 phase markers present: `[1/4]`, `[2/4]`, `[3/4]`, `[4/4]`
ASSERT: `Session Init Complete` in output.
ASSERT: Exit code 0.
ASSERT: No Python tracebacks, no `command not found`.

### V5.2 — Handles missing .env
Script MUST NOT crash. Must output clear message about missing credentials.
Steps 1, 2, 4 MUST still complete even if step 3 fails.

---

## V6: CLAUDE.md Verification (Run on session start)

### V6.1 — All 10 behavior rules present
ASSERT: Rules contain keywords: "act, don't ask", "dupe-check", "escalation check", "checkpoint", "10 tool calls", "session log"

### V6.2 — All 6 workflow phases present
ASSERT: Phase 1 through Phase 6 headers exist.
ASSERT: Phase 4 contains `HARD GATE` and `exit code 2`.

### V6.3 — No hardcoded absolute paths
```bash
grep -n "/c/Users\|C:\\\\Users\|/home/prana" CLAUDE.md
```
ASSERT: Zero matches.

---

## V7: MEMORY.md Verification (Run on session start)

### V7.1 — File exists at correct path
Path: `C:/Users/prana/.claude/projects/C--Users-prana-Projekts-Workshop-BugBounty/memory/MEMORY.md`
ASSERT: Exists and non-zero.

### V7.2 — Required sections
ASSERT: Contains `## System Overview`, `## Session Start Checklist`, `## Key Commands`

### V7.3 — No credentials
```bash
grep -i "token\|password\|secret\|api_key" MEMORY.md
```
ASSERT: Zero matches.

---

## V8: Post-Finding Verification (MANDATORY after every confirmed vulnerability)

This is the CRITICAL gate. This is what prevents false positives like the updateUserType disaster.

### V8.1 — Impact Chain Verification

Before ANY report is written, answer ALL of these with EVIDENCE:

| Question | Required Evidence |
|----------|------------------|
| Does the field/state change GATE any authorization? | Show before/after capability comparison |
| Can the attacker DO something new after exploiting? | Show concrete action that works AFTER but not BEFORE |
| Is data exposed that was not accessible before? | Show query results before/after |
| Does the change persist across sessions? | Log out, log in, verify state |
| Is there FUNCTIONAL impact beyond cosmetic change? | Demonstrate business logic difference |

**HARD RULE: If you cannot answer YES with EVIDENCE to at least ONE of these questions, the finding is INFORMATIONAL at best. Do NOT write a report claiming higher severity.**

### V8.2 — Severity Validation

```
CRITICAL: Remote code execution, full database dump, admin takeover with evidence
HIGH: Privilege escalation WITH demonstrated new capabilities, mass data exposure
MEDIUM: Data leak of limited scope, CSRF with impact, stored XSS with session theft
LOW: Self-XSS, information disclosure of non-sensitive data, cosmetic changes
INFORMATIONAL: No functional impact, field changes without authorization implications
```

ASSERT: Claimed severity matches the impact chain evidence.
ASSERT: CVSS vector string produces a score within 1.0 of claimed severity range.

### V8.3 — False Positive Checklist

Before submitting, verify the finding is NOT:
- [ ] A field that changes but doesn't gate authorization (like updateUserType)
- [ ] An error message difference without functional impact
- [ ] A UI change that doesn't reflect backend capability change
- [ ] An API response that "succeeds" but doesn't grant new access
- [ ] A rate limit that resets or doesn't apply to the actual attack path

**If ANY checkbox is checked, STOP. Reassess severity downward or discard the finding.**

### V8.4 — PoC Completeness

ASSERT: PoC script exists in `poc/` directory.
ASSERT: PoC demonstrates the FULL impact chain, not just the trigger.
ASSERT: PoC includes before/after state comparison.
ASSERT: PoC is runnable (syntax check passes).

---

## V9: Pre-Submission Gate (HARD BLOCK)

ALL must pass before ANY report submission:

1. **Dupe check**: `python3 scripts/tracker.py dupe-check <vuln_type> <asset>` — exit 2 = BLOCKED
2. **Hacktivity check**: `h1_hacktivity <handle>` — search for similar vulns
3. **Impact chain verified**: V8.1 passed with evidence
4. **Severity validated**: V8.2 confirmed
5. **False positive checklist**: V8.3 all clear
6. **PoC complete**: V8.4 all assertions pass
7. **CVSS score matches**: Auto-calculated score within range

**ANY failure = report is NOT submitted. Fix first.**

---

## V10: End-to-End System Test (Run periodically or on demand)

### V10.1 — Cold start simulation
```bash
env -i HOME="$HOME" PATH="$PATH" bash scripts/session_init.sh
```
ASSERT: Exit code 0, all 4 phases complete, no errors.

### V10.2 — Full lifecycle test
Create target → create recon dir → create report → dupe-check blocks → sync-status → escalation fires → cleanup → verify empty state.

### V10.3 — Final filesystem state
```bash
find data/ poc/ -not -name ".gitkeep" -type f | sort
```
ASSERT: Only real data files present (no test artifacts left behind).

---

## Common Failure Modes

| Symptom | Cause | Fix |
|---|---|---|
| `h1api: command not found` | h1api.sh not sourced | `source scripts/h1api.sh` |
| `python3 -m json.tool` fails | Non-JSON API response | Check HTTP status (401/429) |
| `dupe-check` exits 0 on known dupe | Case mismatch in vuln_type | Normalize to lowercase |
| `escalation-check` misses old reports | Date parsing error | Ensure `YYYY-MM-DD` format |
| `session_init.sh` exits non-zero | `set -e` + failing command | Wrap API calls in `\|\| true` |
| Field change claimed as privesc | **No impact chain verified** | **Run V8 before reporting** |
| Report submitted as HIGH, actually LOW | **Skipped V8.2 severity check** | **NEVER skip V8** |
