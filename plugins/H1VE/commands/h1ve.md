---
name: h1ve
description: >
  Activate H1VE Swarm Mode for full autonomous multi-agent bug bounty assessment.
  Initializes the Shared Bus Protocol, sets all agents to idle, and begins the RECON phase.
  Usage: /h1ve <domain_or_handle>
---

# H1VE Swarm Activation

You are the Supervisor. Claude Opus 4.6 is mission control.

## Activation Sequence

The user provided a target. Execute this exact sequence:

### Step 0: Validate

1. Confirm target is in scope of an authorized bug bounty program
2. Check `data/targets/{handle}.json` for existing context
3. If no target file exists, fetch scope: `source scripts/h1api.sh && h1_scopes {handle}`

### Step 1: Initialize Bus

```bash
python3 scripts/bus.py init
python3 scripts/agent_state.py set all idle
```

### Step 2: Load Target Context

```bash
source scripts/h1api.sh
h1_scopes {handle} > /tmp/scope_raw.json
python3 scripts/tracker.py target create "$(python3 scripts/bus.py parse-scope /tmp/scope_raw.json)"
```

### Step 3: Begin RECON Phase

```bash
python3 scripts/agent_state.py set recon running
```

Execute the RECON agent's full plan:
1. subfinder subdomain enumeration
2. dnsx DNS resolution
3. httpx HTTP probing
4. katana deep crawl

### Step 4: Supervisor Loop

Every 10 tool calls:
```bash
python3 scripts/supervisor.py tick
```

### Step 5: Phase Transitions

Follow these rules strictly:
- RECON -> SCAN: when live_hosts.json exists AND has >0 results
- RECON -> FUZZ: when endpoints_full.json exists (parallel with SCAN)
- SCAN + FUZZ -> EXPLOIT: when nuclei or fuzz results exist
- EXPLOIT -> REPORTER: when any confirmed finding exists in poc/
- All phases complete -> REPORTER: final report assembly

### Step 6: On ALERT

Any critical/high finding from any agent:
1. Pause all other agents
2. Route full context to EXPLOIT agent
3. EXPLOIT confirms or denies
4. Resume paused agents after resolution

### Step 7: Completion

```bash
python3 scripts/supervisor.py correlate
python3 scripts/supervisor.py mission-status
```

Present findings summary to user. Do not submit reports without user approval.

## Anti-Patterns (Never Do These)

- Run EXPLOIT before RECON+SCAN (no surface = blind exploitation)
- Submit on SCAN finding alone (nuclei has false positives)
- Run nuclei against out-of-scope hosts
- Retry a 429-rate-limited tool immediately (backoff: 60s, 120s, stop)
- Write raw creds to bus messages
- Re-fuzz already-fuzzed endpoints
- Skip GATE checks to save time
