---
name: bug-bounty-hunter
description: >
  Full-lifecycle, pentagon-grade bug bounty hunting assistant covering reconnaissance, vulnerability discovery,
  exploitation validation, report writing, and platform strategy. Use this skill when:
  (1) Planning or executing bug bounty hunting against authorized targets,
  (2) Performing web application security testing or penetration testing,
  (3) Searching for vulnerabilities including OWASP Top 10 2025, API security, injection, XSS, SSRF, IDOR, broken access control, authentication bypass, CSRF, business logic flaws, file upload, open redirect, race conditions,
  (4) Testing cloud security (AWS S3, Azure Blob, GCP, Kubernetes, containers, serverless),
  (5) Testing mobile application security (Android APK, iOS IPA, Frida, certificate pinning),
  (6) Performing advanced attacks: HTTP request smuggling, web cache poisoning, prototype pollution, DNS rebinding, CORS misconfiguration, WebSocket hijacking, deserialization, clickjacking,
  (7) Testing API security: REST, GraphQL, JWT, OAuth, mass assignment, rate limiting bypass,
  (8) Hunting AI/ML vulnerabilities: prompt injection, system prompt leakage, LLM security,
  (9) Auditing smart contracts, DeFi protocols, or Web3 security on Immunefi,
  (10) Writing vulnerability reports with CVSS scoring for HackerOne, Bugcrowd, Intigriti, or other platforms,
  (11) Building recon automation pipelines using ProjectDiscovery tools (subfinder, httpx, nuclei, katana),
  (12) Developing bug bounty career strategy, choosing targets, building platform reputation,
  (13) Any security research, ethical hacking, CTF challenges, or authorized penetration testing tasks,
  (14) Activating Swarm Mode for full autonomous multi-agent target assessment.
  Requires explicit authorization context for all testing activities.
version: 1.0.0
---

# Bug Bounty Hunter

Full-lifecycle bug bounty hunting skill with multi-stage methodology, from reconnaissance through exploitation validation to pentagon-grade report delivery. Includes Swarm Mode for multi-agent autonomous assessment.

## MANDATORY: VERIFY Protocol

**The [VERIFY Protocol](references/verify-protocol.md) is LAW. It runs automatically. It is not optional.**

The VERIFY protocol triggers after:
- **Every confirmed vulnerability** — run V8 (Post-Finding Verification) before writing any report
- **Every report draft** — run V9 (Pre-Submission Gate) before submission
- **Every PoC generated** — run V8.4 (PoC Completeness) before attaching
- **Every session start** — run V1-V7 (Infrastructure + System Health)
- **Every session end** — run V3 (CONTEXT.md updated with session log)
- **Every new target added** — run V1 (Infrastructure) + V4 (Tracker)

**HARD RULE: No finding is "confirmed" until V8 passes. No report is submitted until V9 passes. No exceptions.**

**THE updateUserType RULE**: A mutation that succeeds and changes a field is NOT a vulnerability unless the change GATES authorization. If you cannot demonstrate a concrete capability gain (new action, new data, new access), the severity is INFORMATIONAL. Run V8.1 Impact Chain Verification with EVIDENCE before claiming anything higher.

## Authorization Requirement

Before ANY testing activity, confirm:
1. Target is in scope of an authorized bug bounty program
2. Testing methods are within program policy
3. User has read and accepted the program's terms

## Multi-Stage Workflow

### Stage 1: Target Selection & Scope Analysis
1. Identify the bug bounty program and platform
2. Read program policy, scope, and exclusions
3. Note reward ranges and priority vulnerability types
4. Check for previous disclosures (Hacktivity, public reports)
5. See [platforms-strategy.md](references/platforms-strategy.md) for platform-specific guidance

### Stage 2: Reconnaissance
Execute systematic reconnaissance pipeline:

1. **Passive recon**: subdomain enum, DNS, cert transparency, Wayback, GitHub recon, Google dorking, Shodan
2. **Active recon**: HTTP probing, port scanning, web crawling, tech fingerprinting
3. **Content discovery**: directory fuzzing, parameter discovery, JavaScript analysis
4. **Attack surface mapping**: catalog all endpoints, parameters, technologies

See [recon.md](references/recon.md) for complete techniques and tool commands.

Quick pipeline:
```bash
subfinder -d TARGET -all | dnsx -silent | httpx -silent -td -sc | tee live_hosts.txt
cat live_hosts.txt | katana -d 3 -jc | tee crawled.txt
nuclei -l live_hosts.txt -severity critical,high -o critical_findings.txt
```

### Stage 3: Vulnerability Hunting
Systematically test for vulnerabilities by category:

| Category | Reference | Priority Targets |
|----------|-----------|-----------------|
| Injection (SQLi, SSTI, CMDi, XXE) | [web-vulns.md](references/web-vulns.md) | User inputs, search, forms |
| XSS (reflected, stored, DOM, blind) | [web-vulns.md](references/web-vulns.md) | All user-controlled fields |
| SSRF | [web-vulns.md](references/web-vulns.md) | URL parameters, webhooks, imports |
| IDOR / Broken Access Control | [web-vulns.md](references/web-vulns.md) | API endpoints with IDs |
| Authentication & Session | [web-vulns.md](references/web-vulns.md) | Login, reset, OAuth, JWT, MFA |
| API Security | [api-security.md](references/api-security.md) | REST, GraphQL, mass assignment |
| Business Logic | [web-vulns.md](references/web-vulns.md) | Payments, coupons, workflows |
| File Upload | [web-vulns.md](references/web-vulns.md) | Any upload functionality |
| Advanced Attacks | [advanced-attacks.md](references/advanced-attacks.md) | Smuggling, cache, prototype |
| Cloud/Mobile/IoT | [cloud-mobile-iot.md](references/cloud-mobile-iot.md) | S3, K8s, APK, IPA |
| AI/Web3 | [ai-web3-emerging.md](references/ai-web3-emerging.md) | LLM features, smart contracts |
| **H1 Master Checklist** | [h1-hunting-checklist.md](references/h1-hunting-checklist.md) | **Quick-ref by target type, top bounty patterns, anti-tunnel-vision** |

Use Burp Suite as primary proxy. Key extensions: Autorize, Param Miner, ActiveScan++, Turbo Intruder, JWT Editor.

**IMPORTANT**: When feeling stuck or only testing one attack vector, consult the [Anti-Tunnel-Vision Checklist](references/h1-hunting-checklist.md#anti-tunnel-vision-checklist) to diversify your approach.

### Stage 4: Exploitation Validation (VERIFY V8 REQUIRED)

**MANDATORY: Run [VERIFY V8](references/verify-protocol.md#v8-post-finding-verification-mandatory-after-every-confirmed-vulnerability) after EVERY finding.**

1. Confirm vulnerability is real (not false positive)
2. **Run V8.3 False Positive Checklist** — if ANY box is checked, STOP and reassess
3. Develop minimal proof-of-concept that demonstrates FULL impact chain
4. **Run V8.1 Impact Chain Verification** — answer ALL questions with EVIDENCE:
   - Does the change GATE authorization? (before/after capability comparison)
   - Can the attacker DO something new? (concrete action proof)
   - Is new data exposed? (query results before/after)
   - Does it persist across sessions? (logout/login verification)
   - Is there FUNCTIONAL impact beyond cosmetic? (business logic difference)
5. **If you cannot answer YES with evidence to at least ONE question above, severity is INFORMATIONAL. Do NOT write a HIGH/CRITICAL report.**
6. Calculate CVSS score — **Run V8.2** to validate severity matches evidence
7. Identify vulnerability chains for higher impact
8. **Run V8.4** — verify PoC is complete, runnable, shows before/after

### Stage 5: Report Writing
Write vulnerability reports. See [report-writing.md](references/report-writing.md).

Report structure: Summary, Severity (CVSS), Affected Asset, Vulnerability Details (root cause + attack vector), Steps to Reproduce, Proof of Concept (HTTP requests + responses + screenshots), Impact (business + technical + attack scenario), Remediation, References.

**Writing rules:**
- No filler. Every sentence states a fact or proves a claim.
- No dashes, em dashes, or decorative punctuation. Use periods.
- If a file was uploaded to a URL, include that URL in the report. Triagers click links.
- If an API returned a response, show the raw JSON. Not a summary of the JSON.
- Every impact claim must name a victim and an action. "Phishing" is not enough. "Staff sends GCS URL to store owner via internal messaging, owner enters credentials" is.
- Do not write "could potentially" or "may allow". Write what happened. "Staff uploaded HTML. File is public at [URL]. Content-Type is text/html."
- CVSS vector and severity label must agree. If you write Scope: Changed, the score goes up. If you write Medium, use Scope: Unchanged. Pick one and be consistent.
- Attach live proof URLs in the Impact section when available. A triager who can click a link and see the bug is a triager who triages fast.

### Stage 6: Submission & Follow-up (VERIFY V9 HARD BLOCK)

**MANDATORY: Run [VERIFY V9](references/verify-protocol.md#v9-pre-submission-gate-hard-block) before ANY submission. ALL must pass or submission is BLOCKED.**

Pre-submission gate (ALL must pass):
1. `python3 scripts/tracker.py dupe-check <vuln_type> <asset>` — exit 2 = BLOCKED
2. `h1_hacktivity <handle>` — search for similar vulns on same asset
3. V8.1 Impact Chain — verified with evidence
4. V8.2 Severity — validated against CVSS
5. V8.3 False Positive Checklist — all clear
6. V8.4 PoC — complete, runnable, shows before/after
7. CVSS auto-score — matches claimed severity

**ANY failure = DO NOT SUBMIT. Fix first.**

After submission:
1. Track report status via tracker
2. Respond promptly to triage questions
3. Provide additional PoC if requested
4. Learn from feedback — update `now_we_know/lessons.json`

## Swarm Mode

When user provides a target for full assessment, activate Swarm Mode. This launches a multi-agent mesh architecture with 5 specialized agents coordinated by the Supervisor (you).

### Activation

User says any of: "recon X", "test X", "hack X", "assess X", "full recon on X", "bug bounty X", "swarm X", or provides a domain/handle as the primary input.

### Architecture

5 specialized agents under Supervisor control, communicating via Shared Bus Protocol (SBP):

| Agent | Tools | Mission |
|-------|-------|---------|
| RECON | subfinder, httpx, dnsx, katana | Maximum attack surface discovery |
| SCAN | nuclei, naabu | Port enumeration + vulnerability template scanning |
| FUZZ | ffuf, katana | Directory bruting, parameter discovery, input fuzzing |
| EXPLOIT | curl, Python PoC | Confirm findings, build PoCs, chain vulns, calculate CVSS |
| REPORTER | tracker.py, H1 API | Draft reports, run pre-submission gate, track lifecycle |

### Supervisor Responsibilities (YOU are the Supervisor)
1. Read CONTEXT.md and data/targets/{handle}.json if it exists
2. Run `python3 scripts/bus.py init` to initialize bus
3. Run `python3 scripts/agent_state.py set all idle`
4. Begin Phase 1: RECON by executing recon commands directly
5. Every 10 tool calls: run `python3 scripts/supervisor.py tick` to drain inbox
6. Spawn next phase agent when current phase sends DONE
7. On any ALERT: pause current work, route to EXPLOIT immediately
8. On any inter-agent REQUEST: route the data and continue
9. Run `python3 scripts/supervisor.py correlate` after SCAN+FUZZ both DONE
10. Only activate REPORTER after EXPLOIT confirms at least one finding

### Phase Transitions
- RECON -> SCAN: when live_hosts.json exists AND has >0 results
- RECON -> FUZZ: when endpoints_full.json exists AND has >0 results (parallel with SCAN)
- SCAN + FUZZ -> EXPLOIT: when nuclei_results.json exists OR fuzz dirs_{host}.json exists
- EXPLOIT -> REPORTER: when any confirmed finding exists in poc/
- All phases complete -> REPORTER: final report assembly

### Stall Detection
If any phase produces no output after reasonable time:
- Run `python3 scripts/agent_state.py stall-check`
- Investigate why: rate limit? auth? network? scope restriction?
- Adjust tool flags and retry once
- If still stalled: log to CONTEXT.md, continue with what we have

### Anti-Loop Safeguards
- Never spawn a phase that is already in state "running" or "done"
- Never run dupe-check more than once per vuln+asset combination
- Never submit a report already in data/reports/ (check by title hash)
- FUZZ agent does not re-fuzz a host already in data/fuzz/{handle}/
- RECON agent does not re-enumerate a handle already in data/recon/{handle}/ unless user explicitly says "re-recon" or target file is >7 days old

### Mesh Requests
When acting as any agent and you need data from another agent:
1. Write request to data/bus/inbox/{target_agent}.jsonl via bus.py
2. Execute the next available task for current agent
3. On next supervisor tick: route the response back
4. You are both sender and router. Stay organized with msg_ids.

## Tool Reference

See [tools-arsenal.md](references/tools-arsenal.md) for complete tool installation and usage guide.

Core toolchain: subfinder, dnsx, httpx, katana, nuclei, ffuf, sqlmap, dalfox, Burp Suite

## Career Strategy

See [platforms-strategy.md](references/platforms-strategy.md) for:
- Platform comparison and payout structures
- Beginner to expert roadmap
- Earning strategies and revenue targets
- Reputation building mechanics
- Legal and ethical framework

## Reference Index

| Reference | When to use |
|-----------|-------------|
| [verify-protocol.md](references/verify-protocol.md) | **MANDATORY** — after every finding, every report, every session start/end |
| [recon.md](references/recon.md) | Reconnaissance techniques and tool commands |
| [web-vulns.md](references/web-vulns.md) | Web vulnerability testing (XSS, SQLi, SSRF, IDOR, etc.) |
| [api-security.md](references/api-security.md) | API security (REST, GraphQL, JWT, OAuth) |
| [advanced-attacks.md](references/advanced-attacks.md) | HTTP smuggling, cache poisoning, prototype pollution |
| [cloud-mobile-iot.md](references/cloud-mobile-iot.md) | Cloud, mobile, IoT security |
| [ai-web3-emerging.md](references/ai-web3-emerging.md) | AI/ML, Web3, smart contracts |
| [report-writing.md](references/report-writing.md) | Report structure and writing guide |
| [tools-arsenal.md](references/tools-arsenal.md) | Tool installation and usage |
| [platforms-strategy.md](references/platforms-strategy.md) | Platform strategy and career |
| [h1-hunting-checklist.md](references/h1-hunting-checklist.md) | H1-specific hunting checklist |
