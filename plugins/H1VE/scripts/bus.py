#!/usr/bin/env python3
"""
H1VE Shared Bus Protocol (SBP) — Inter-agent communication manager.

Usage:
  python3 scripts/bus.py init
  python3 scripts/bus.py send --from X --to Y --type T --subject S [--payload '{}'] [--priority normal] [--correlation-id ID]
  python3 scripts/bus.py drain --agent X
  python3 scripts/bus.py status
  python3 scripts/bus.py extract-urls <live_hosts_json>
  python3 scripts/bus.py get-tech <handle>
  python3 scripts/bus.py check-hacktivity <vuln_type> <asset>  (stdin: H1 hacktivity JSON)
  python3 scripts/bus.py tech-targeted-scan <handle>
  python3 scripts/bus.py parse-scope <scope_json_file>
"""

import argparse
import json
import os
import re
import sys
import uuid
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Resolve all paths relative to project root (parent of scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUS_DIR = PROJECT_ROOT / "data" / "bus"
INBOX_DIR = BUS_DIR / "inbox"
OUTBOX_DIR = BUS_DIR / "outbox"
LOCKS_DIR = BUS_DIR / "locks"
PROCESSED_FILE = BUS_DIR / "processed.txt"
DATA_DIR = PROJECT_ROOT / "data"

AGENTS = ["supervisor", "recon", "scan", "fuzz", "exploit", "reporter"]
MSG_TYPES = ["FINDING", "REQUEST", "RESPONSE", "STATUS", "ALERT", "DONE", "ERROR"]
PRIORITIES = ["critical", "high", "normal", "low"]

# Max processed IDs before rotation (prevents unbounded growth)
MAX_PROCESSED_IDS = 5000
# Max stdin bytes for check-hacktivity (10MB)
MAX_STDIN_BYTES = 10 * 1024 * 1024

# Handle sanitization pattern: alphanumeric, hyphens, underscores only
HANDLE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


def sanitize_handle(handle):
    """Validate handle contains no path traversal or special characters."""
    if not HANDLE_PATTERN.match(handle):
        print(f"ERROR: Invalid handle '{handle}'. Only alphanumeric, hyphens, underscores allowed.", file=sys.stderr)
        sys.exit(1)
    return handle


def init():
    """Create bus directory structure."""
    for d in [INBOX_DIR, OUTBOX_DIR, LOCKS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    for agent in AGENTS:
        inbox = INBOX_DIR / f"{agent}.jsonl"
        outbox = OUTBOX_DIR / f"{agent}.jsonl"
        if not inbox.exists():
            inbox.touch()
        if not outbox.exists():
            outbox.touch()

    if not PROCESSED_FILE.exists():
        PROCESSED_FILE.touch()

    print(f"Bus initialized at {BUS_DIR}")
    print(f"Agents: {', '.join(AGENTS)}")


def acquire_lock(agent):
    """Acquire file lock for agent. Blocks until available.

    Uses mkdir atomicity for locking. Writes PID+timestamp inside
    the lock directory for stale lock detection.
    """
    lock_dir = LOCKS_DIR / f"{agent}.lock"
    pid_file = lock_dir / "owner"
    attempts = 0
    while attempts < 100:
        try:
            lock_dir.mkdir()
            # Write PID and timestamp for stale detection
            pid_file.write_text(f"{os.getpid()}:{time.time()}")
            return True
        except FileExistsError:
            # Check for stale lock (owner process dead or lock older than 60s)
            try:
                if pid_file.exists():
                    content = pid_file.read_text().strip()
                    parts = content.split(":")
                    if len(parts) == 2:
                        owner_pid = int(parts[0])
                        lock_time = float(parts[1])
                        # Stale if older than 60s or owner process is dead
                        if time.time() - lock_time > 60:
                            _force_release_lock(agent)
                            continue
                        try:
                            os.kill(owner_pid, 0)  # Check if process exists
                        except OSError:
                            _force_release_lock(agent)
                            continue
            except (ValueError, OSError):
                # Corrupted lock file, force release
                _force_release_lock(agent)
                continue
            time.sleep(0.1)
            attempts += 1
    print(f"ERROR: Could not acquire lock for {agent} after 10s", file=sys.stderr)
    return False


def _force_release_lock(agent):
    """Force release a stale lock by removing the directory."""
    lock_dir = LOCKS_DIR / f"{agent}.lock"
    try:
        pid_file = lock_dir / "owner"
        if pid_file.exists():
            pid_file.unlink()
        lock_dir.rmdir()
    except (FileNotFoundError, OSError):
        pass


def release_lock(agent):
    """Release file lock for agent."""
    lock_dir = LOCKS_DIR / f"{agent}.lock"
    try:
        pid_file = lock_dir / "owner"
        if pid_file.exists():
            pid_file.unlink()
        lock_dir.rmdir()
    except FileNotFoundError:
        pass


def _rotate_processed():
    """Rotate processed.txt if it exceeds MAX_PROCESSED_IDS lines."""
    if not PROCESSED_FILE.exists():
        return
    try:
        lines = PROCESSED_FILE.read_text().strip().split("\n")
        if len(lines) > MAX_PROCESSED_IDS:
            # Keep only the most recent half
            keep = lines[len(lines) // 2:]
            PROCESSED_FILE.write_text("\n".join(keep) + "\n")
    except (OSError, ValueError):
        pass


def send(from_agent, to_agent, msg_type, subject, payload=None, priority="normal", correlation_id=None):
    """Send a message to an agent's inbox."""
    if from_agent not in AGENTS:
        print(f"ERROR: Unknown sender '{from_agent}'. Valid: {', '.join(AGENTS)}", file=sys.stderr)
        sys.exit(1)
    if to_agent not in AGENTS:
        print(f"ERROR: Unknown recipient '{to_agent}'. Valid: {', '.join(AGENTS)}", file=sys.stderr)
        sys.exit(1)
    if msg_type not in MSG_TYPES:
        print(f"ERROR: Unknown type '{msg_type}'. Valid: {', '.join(MSG_TYPES)}", file=sys.stderr)
        sys.exit(1)
    if priority not in PRIORITIES:
        print(f"ERROR: Unknown priority '{priority}'. Valid: {', '.join(PRIORITIES)}", file=sys.stderr)
        sys.exit(1)

    msg = {
        "msg_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "from": from_agent,
        "to": to_agent,
        "type": msg_type,
        "priority": priority,
        "subject": subject,
        "payload": payload or {},
        "requires_ack": msg_type in ("ALERT", "ERROR", "REQUEST"),
        "correlation_id": correlation_id,
    }

    inbox = INBOX_DIR / f"{to_agent}.jsonl"

    if not acquire_lock(to_agent):
        sys.exit(1)
    try:
        with open(inbox, "a") as f:
            f.write(json.dumps(msg) + "\n")
    finally:
        release_lock(to_agent)

    print(f"Sent {msg_type} from {from_agent} to {to_agent}: {subject}")
    print(f"  msg_id: {msg['msg_id']}")
    return msg["msg_id"]


def drain(agent):
    """Read and archive all inbox messages for an agent. Returns JSON array.

    Lock ordering: holds agent-specific lock for the entire read-archive-clear cycle.
    This guarantees no messages are lost because send() also acquires the same lock.
    """
    if agent not in AGENTS:
        print(f"ERROR: Unknown agent '{agent}'", file=sys.stderr)
        sys.exit(1)

    inbox = INBOX_DIR / f"{agent}.jsonl"
    outbox = OUTBOX_DIR / f"{agent}.jsonl"

    if not inbox.exists() or inbox.stat().st_size == 0:
        print("[]")
        return []

    # Load processed IDs (read outside lock since we only append inside)
    processed = set()
    if PROCESSED_FILE.exists():
        content = PROCESSED_FILE.read_text().strip()
        if content:
            processed = set(content.split("\n"))

    if not acquire_lock(agent):
        sys.exit(1)

    try:
        messages = []
        new_processed = []
        with open(inbox, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    msg_id = msg.get("msg_id", "")
                    if msg_id in processed:
                        continue
                    messages.append(msg)
                    new_processed.append(msg_id)
                except json.JSONDecodeError:
                    continue

        # Archive to outbox
        with open(outbox, "a") as f:
            for msg in messages:
                f.write(json.dumps(msg) + "\n")

        # Mark as processed
        with open(PROCESSED_FILE, "a") as f:
            for mid in new_processed:
                f.write(mid + "\n")

        # Clear inbox
        with open(inbox, "w") as f:
            pass

    finally:
        release_lock(agent)

    # Rotate processed.txt if too large
    _rotate_processed()

    print(json.dumps(messages, indent=2))
    return messages


def status():
    """Show all agent inboxes and message counts."""
    print("H1VE Bus Status")
    print("=" * 40)
    for agent in AGENTS:
        inbox = INBOX_DIR / f"{agent}.jsonl"
        count = 0
        if inbox.exists():
            # Acquire lock to get consistent read
            if acquire_lock(agent):
                try:
                    with open(inbox) as f:
                        count = sum(1 for line in f if line.strip())
                finally:
                    release_lock(agent)
        outbox = OUTBOX_DIR / f"{agent}.jsonl"
        archived = 0
        if outbox.exists():
            with open(outbox) as f:
                archived = sum(1 for line in f if line.strip())
        print(f"  {agent:12s}  inbox: {count:3d}  archived: {archived:3d}")
    print("=" * 40)


def extract_urls(live_hosts_json):
    """Extract URLs from httpx JSON output."""
    path = Path(live_hosts_json)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if not path.exists():
        print(f"ERROR: File not found: {live_hosts_json}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                host = json.loads(line)
                url = host.get("url", host.get("input", ""))
                if url:
                    print(url)
            except json.JSONDecodeError:
                continue


def get_tech(handle):
    """Get tech stack summary for a handle."""
    handle = sanitize_handle(handle)
    tech_file = DATA_DIR / "recon" / handle / "tech-stack.json"
    if tech_file.exists():
        print(tech_file.read_text())
        return

    live_hosts = DATA_DIR / "recon" / handle / "live_hosts.json"
    if not live_hosts.exists():
        print("ERROR: No tech data found", file=sys.stderr)
        sys.exit(1)

    techs = set()
    with open(live_hosts) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                host = json.loads(line)
                for tech in host.get("tech", []):
                    techs.add(tech)
            except json.JSONDecodeError:
                continue

    print("\n".join(sorted(techs)))


def check_hacktivity(vuln_type, asset):
    """Check H1 hacktivity for similar findings. Reads JSON from stdin (max 10MB)."""
    vuln_lower = vuln_type.lower()
    asset_lower = asset.lower()
    found = False

    # Read stdin with size limit
    raw = sys.stdin.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        print("ERROR: stdin exceeds 10MB limit", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON on stdin", file=sys.stderr)
        sys.exit(1)

    reports = data.get("data", [])
    for report in reports:
        attrs = report.get("attributes", {})
        title = (attrs.get("title", "") or "").lower()
        # Check structured_scope and weakness fields too
        scope = report.get("relationships", {}).get("structured_scope", {}).get("data", {}).get("attributes", {})
        scope_asset = (scope.get("asset_identifier", "") or "").lower()
        weakness = report.get("relationships", {}).get("weakness", {}).get("data", {}).get("attributes", {})
        weakness_name = (weakness.get("name", "") or "").lower()

        # Match if vuln type appears in title or weakness, AND asset appears in title or scope
        vuln_match = vuln_lower in title or vuln_lower in weakness_name
        asset_match = asset_lower in title or asset_lower in scope_asset
        if vuln_match and asset_match:
            print(f"MATCH: {attrs.get('title', '')} (id: {report.get('id', 'unknown')})")
            found = True
        elif vuln_lower in title:
            # Partial match on vuln type alone (warn but don't block)
            print(f"PARTIAL: {attrs.get('title', '')} (vuln type match, different asset)")

    if found:
        print("\nHACKTIVITY_DUPE_FOUND")
        sys.exit(2)
    else:
        print("No hacktivity matches found.")
        sys.exit(0)


def tech_targeted_scan(handle):
    """Run technology-specific nuclei templates based on detected tech."""
    handle = sanitize_handle(handle)
    tech_file = DATA_DIR / "recon" / handle / "tech-stack.json"
    live_urls = DATA_DIR / "recon" / handle / "live_urls.txt"
    output_dir = DATA_DIR / "scan" / handle

    if not live_urls.exists():
        print("ERROR: No live_urls.txt found", file=sys.stderr)
        sys.exit(1)

    # Create output directory if missing
    output_dir.mkdir(parents=True, exist_ok=True)

    tech_templates = {
        "wordpress": "technologies/wordpress/",
        "joomla": "technologies/joomla/",
        "drupal": "technologies/drupal/",
        "jenkins": "technologies/jenkins/",
        "nginx": "misconfiguration/nginx/",
        "apache": "misconfiguration/apache/",
        "iis": "misconfiguration/iis/",
        "rails": "technologies/ruby/",
        "django": "technologies/django/",
        "spring": "technologies/spring/",
        "node": "technologies/nodejs/",
        "express": "technologies/nodejs/",
        "php": "technologies/php/",
        "laravel": "technologies/laravel/",
        "graphql": "technologies/graphql/",
    }

    techs = set()
    if tech_file.exists():
        try:
            data = json.loads(tech_file.read_text())
            if isinstance(data, list):
                for entry in data:
                    for t in entry.get("tech", []):
                        techs.add(t.lower())
            elif isinstance(data, dict):
                for t in data.get("tech", []):
                    techs.add(t.lower())
        except (json.JSONDecodeError, AttributeError):
            pass

    templates = []
    for tech_name, template_path in tech_templates.items():
        for detected in techs:
            if tech_name in detected:
                templates.append(template_path)
                break

    if not templates:
        print("No tech-specific templates matched. Running generic scan.")
        templates = ["technologies/"]

    cmd = ["nuclei", "-list", str(live_urls)]
    for t in templates:
        cmd.extend(["-t", t])
    output_file = output_dir / "tech_targeted.json"
    cmd.extend(["-severity", "critical,high,medium", "-json", "-o", str(output_file)])

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: nuclei exited with code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
        sys.exit(1)
    if result.stdout:
        print(result.stdout[:1000])


def parse_scope(scope_json_file):
    """Parse H1 API scope response into a target JSON object for tracker.py."""
    path = Path(scope_json_file)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if not path.exists():
        print(f"ERROR: File not found: {scope_json_file}", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON in scope file", file=sys.stderr)
        sys.exit(1)

    # Extract scope assets from H1 API response
    assets = []
    eligible_types = set()
    relationships = data.get("relationships", {})
    scopes = relationships.get("structured_scopes", {}).get("data", [])

    # Handle both wrapped and direct formats
    if not scopes and "data" in data:
        items = data["data"]
        if isinstance(items, list):
            for item in items:
                rel = item.get("relationships", {})
                scopes.extend(rel.get("structured_scopes", {}).get("data", []))

    for scope in scopes:
        attrs = scope.get("attributes", {})
        asset_id = attrs.get("asset_identifier", "")
        asset_type = attrs.get("asset_type", "")
        eligible = attrs.get("eligible_for_bounty", False)
        eligible_for_submission = attrs.get("eligible_for_submission", True)

        if asset_id and eligible_for_submission:
            assets.append({
                "asset": asset_id,
                "type": asset_type,
                "bounty_eligible": eligible,
            })
            eligible_types.add(asset_type)

    target = {
        "assets": assets,
        "eligible_types": list(eligible_types),
        "total_in_scope": len(assets),
        "bounty_eligible": sum(1 for a in assets if a["bounty_eligible"]),
    }

    # Output as JSON string suitable for tracker.py target create
    print(json.dumps(target))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "init":
        init()

    elif cmd == "send":
        parser = argparse.ArgumentParser(prog="bus.py send")
        parser.add_argument("--from", dest="from_agent", required=True)
        parser.add_argument("--to", required=True)
        parser.add_argument("--type", required=True)
        parser.add_argument("--subject", required=True)
        parser.add_argument("--payload", default="{}")
        parser.add_argument("--priority", default="normal")
        parser.add_argument("--correlation-id", default=None)
        args = parser.parse_args(sys.argv[2:])
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            payload = {"raw": args.payload}
        send(args.from_agent, args.to, args.type, args.subject, payload, args.priority, args.correlation_id)

    elif cmd == "drain":
        if len(sys.argv) < 4 or sys.argv[2] != "--agent":
            print("Usage: bus.py drain --agent <agent_name>", file=sys.stderr)
            sys.exit(1)
        drain(sys.argv[3])

    elif cmd == "status":
        status()

    elif cmd == "extract-urls":
        if len(sys.argv) < 3:
            print("Usage: bus.py extract-urls <live_hosts_json>", file=sys.stderr)
            sys.exit(1)
        extract_urls(sys.argv[2])

    elif cmd == "get-tech":
        if len(sys.argv) < 3:
            print("Usage: bus.py get-tech <handle>", file=sys.stderr)
            sys.exit(1)
        get_tech(sys.argv[2])

    elif cmd == "check-hacktivity":
        if len(sys.argv) < 4:
            print("Usage: bus.py check-hacktivity <vuln_type> <asset> (stdin: H1 JSON)", file=sys.stderr)
            sys.exit(1)
        check_hacktivity(sys.argv[2], sys.argv[3])

    elif cmd == "tech-targeted-scan":
        if len(sys.argv) < 3:
            print("Usage: bus.py tech-targeted-scan <handle>", file=sys.stderr)
            sys.exit(1)
        tech_targeted_scan(sys.argv[2])

    elif cmd == "parse-scope":
        if len(sys.argv) < 3:
            print("Usage: bus.py parse-scope <scope_json_file>", file=sys.stderr)
            sys.exit(1)
        parse_scope(sys.argv[2])

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
