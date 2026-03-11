#!/usr/bin/env python3
"""
H1VE Supervisor Decision Engine.

Usage:
  python3 scripts/supervisor.py tick            # Read inbox, classify messages, return action list
  python3 scripts/supervisor.py correlate       # Cross-agent finding correlation
  python3 scripts/supervisor.py mission-status  # Print current agent states + finding count
"""

import json
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Resolve all paths relative to project root (parent of scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
BUS_DIR = PROJECT_ROOT / "data" / "bus"
INBOX_DIR = BUS_DIR / "inbox"
OUTBOX_DIR = BUS_DIR / "outbox"

AGENTS = ["recon", "scan", "fuzz", "exploit", "reporter"]


def drain_inbox():
    """Drain supervisor inbox and return messages."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "bus.py"), "drain", "--agent", "supervisor"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT)
    )
    if result.returncode != 0 and result.stderr:
        print(f"WARNING: bus.py drain stderr: {result.stderr[:200]}", file=sys.stderr)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def tick():
    """Process supervisor inbox. Classify and return action list."""
    messages = drain_inbox()

    if not messages:
        print("No pending messages.")
        print("\n--- JSON ---")
        print("[]")
        return []

    actions = []
    alerts = []
    errors = []
    findings = []
    done_agents = []
    requests = []

    for msg in messages:
        msg_type = msg.get("type", "")
        priority = msg.get("priority", "normal")
        from_agent = msg.get("from", "unknown")
        subject = msg.get("subject", "")
        payload = msg.get("payload", {})

        if msg_type == "ALERT":
            alerts.append(msg)
            actions.append({
                "action": "INVESTIGATE_ALERT",
                "priority": "critical" if priority == "critical" else "high",
                "from": from_agent,
                "subject": subject,
                "detail": "Route to EXPLOIT agent for confirmation",
                "payload": payload,
            })

        elif msg_type == "ERROR":
            errors.append(msg)
            actions.append({
                "action": "HANDLE_ERROR",
                "priority": "high",
                "from": from_agent,
                "subject": subject,
                "detail": "Investigate error, decide: retry, reassign, or abort",
                "payload": payload,
            })

        elif msg_type == "FINDING":
            findings.append(msg)
            actions.append({
                "action": "LOG_FINDING",
                "priority": priority,
                "from": from_agent,
                "subject": subject,
                "detail": "Correlate with existing findings, check for chains",
                "payload": payload,
            })

        elif msg_type == "DONE":
            done_agents.append(from_agent)
            actions.append({
                "action": "PHASE_COMPLETE",
                "priority": "normal",
                "from": from_agent,
                "subject": subject,
                "detail": f"Agent {from_agent} finished. Check phase transition rules.",
            })

        elif msg_type == "REQUEST":
            requests.append(msg)
            to_agent = payload.get("route_to", msg.get("to", "supervisor"))
            actions.append({
                "action": "ROUTE_REQUEST",
                "priority": priority,
                "from": from_agent,
                "to": to_agent,
                "subject": subject,
                "detail": f"Route request from {from_agent} to {to_agent}",
                "payload": payload,
            })

        elif msg_type == "STATUS":
            # Heartbeat. Log but no action needed.
            pass

    # Human-readable summary
    print("=" * 50)
    print(f"SUPERVISOR TICK @ {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")
    print(f"  Messages processed: {len(messages)}")
    print(f"  ALERTs: {len(alerts)}")
    print(f"  ERRORs: {len(errors)}")
    print(f"  FINDINGs: {len(findings)}")
    print(f"  Phases complete: {', '.join(done_agents) if done_agents else 'none'}")
    print(f"  Requests to route: {len(requests)}")
    print("=" * 50)

    if actions:
        print("\nACTION QUEUE:")
        for i, action in enumerate(actions, 1):
            print(f"  [{i}] {action['action']} ({action['priority']})")
            print(f"      From: {action.get('from', '?')} | {action.get('subject', '')}")
            if action.get("detail"):
                print(f"      -> {action['detail']}")

    # Machine-readable JSON (separated clearly)
    print("\n--- JSON ---")
    print(json.dumps(actions, indent=2))
    return actions


def correlate():
    """Cross-agent finding correlation. Look for vulnerability chains.

    Reads findings from the SUPERVISOR outbox (where all agent-to-supervisor
    FINDINGs end up after drain) and from inter-agent outboxes.
    """
    all_findings = []
    seen_ids = set()

    # Primary source: supervisor outbox (all agents send FINDINGs to supervisor)
    sup_outbox = OUTBOX_DIR / "supervisor.jsonl"
    if sup_outbox.exists():
        with open(sup_outbox) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("type") in ("FINDING", "ALERT"):
                        msg_id = msg.get("msg_id", "")
                        if msg_id not in seen_ids:
                            all_findings.append(msg)
                            seen_ids.add(msg_id)
                except json.JSONDecodeError:
                    continue

    # Secondary source: inter-agent findings (e.g., EXPLOIT -> REPORTER)
    for agent in AGENTS:
        outbox = OUTBOX_DIR / f"{agent}.jsonl"
        if not outbox.exists():
            continue
        with open(outbox) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("type") in ("FINDING", "ALERT"):
                        msg_id = msg.get("msg_id", "")
                        if msg_id not in seen_ids:
                            all_findings.append(msg)
                            seen_ids.add(msg_id)
                except json.JSONDecodeError:
                    continue

    print(f"Total findings to correlate: {len(all_findings)}")

    if len(all_findings) < 2:
        print("Not enough findings for correlation.")
        return

    # Chain patterns
    CHAIN_PATTERNS = [
        (["ssrf"], ["aws", "metadata", "cloud"], "SSRF to Cloud Credential Theft"),
        (["idor"], ["pii", "data", "user"], "IDOR to PII Access"),
        (["xss", "stored"], ["admin", "session"], "Stored XSS to Admin Session Theft"),
        (["path_traversal", "lfi"], ["source", "config"], "LFI to Source Code Read"),
        (["open_redirect"], ["oauth", "token"], "Open Redirect to OAuth Token Theft"),
        (["cors"], ["csrf", "cross"], "CORS Misconfiguration to CSRF"),
        (["403_bypass", "bypass"], ["privilege", "admin"], "403 Bypass to Privilege Escalation"),
        (["subdomain_takeover", "takeover"], ["cookie"], "Subdomain Takeover to Cookie Theft"),
    ]

    # Extract finding types
    finding_types = []
    for f in all_findings:
        payload = f.get("payload", {})
        vuln_type = (payload.get("vuln_type", "") or f.get("subject", "")).lower()
        finding_types.append(vuln_type)

    # Check for chain opportunities
    chains_found = []
    for pattern_a, pattern_b, chain_name in CHAIN_PATTERNS:
        has_a = any(any(p in ft for p in pattern_a) for ft in finding_types)
        has_b = any(any(p in ft for p in pattern_b) for ft in finding_types)
        if has_a and has_b:
            chains_found.append(chain_name)

    if chains_found:
        print("\nCHAIN OPPORTUNITIES DETECTED:")
        for chain in chains_found:
            print(f"  -> {chain}")
        print("\nRoute to EXPLOIT agent for chain validation.")
    else:
        print("\nNo chain opportunities detected from current findings.")

    # Print finding summary
    print("\nFinding Summary:")
    for i, f in enumerate(all_findings, 1):
        payload = f.get("payload", {})
        print(f"  [{i}] {f.get('from', '?')}: {f.get('subject', 'no subject')}")
        if payload.get("vuln_type"):
            print(f"      Type: {payload['vuln_type']} | Severity: {payload.get('severity', '?')}")
        if payload.get("asset"):
            print(f"      Asset: {payload['asset']}")


def mission_status():
    """Print current agent states and finding counts."""
    print("H1VE Mission Status")
    print("=" * 50)

    # Agent states
    for agent in AGENTS:
        state_result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "agent_state.py"), "get", agent],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT)
        )
        state = state_result.stdout.strip() or "unknown"
        print(f"  {agent:12s}  state: {state}")

    # Finding counts from outboxes
    total_findings = 0
    total_alerts = 0
    for agent in AGENTS + ["supervisor"]:
        outbox = OUTBOX_DIR / f"{agent}.jsonl"
        if not outbox.exists():
            continue
        with open(outbox) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("type") == "FINDING":
                        total_findings += 1
                    elif msg.get("type") == "ALERT":
                        total_alerts += 1
                except (json.JSONDecodeError, AttributeError):
                    continue

    print(f"\n  Total findings: {total_findings}")
    print(f"  Total alerts:   {total_alerts}")

    # Check for pending inbox messages
    print("\n  Pending messages:")
    has_pending = False
    for agent in AGENTS + ["supervisor"]:
        inbox = INBOX_DIR / f"{agent}.jsonl"
        if inbox.exists():
            with open(inbox) as f:
                count = sum(1 for line in f if line.strip())
            if count > 0:
                print(f"    {agent}: {count} pending")
                has_pending = True
    if not has_pending:
        print("    (none)")

    print("=" * 50)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "tick":
        tick()
    elif cmd == "correlate":
        correlate()
    elif cmd == "mission-status":
        mission_status()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
