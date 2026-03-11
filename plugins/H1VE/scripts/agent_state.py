#!/usr/bin/env python3
"""
H1VE Agent State Manager. Tracks agent lifecycle, prevents loops, detects stalls.

Usage:
  python3 scripts/agent_state.py set <agent|all> <state>    # running|paused|done|error|idle
  python3 scripts/agent_state.py get <agent>
  python3 scripts/agent_state.py list
  python3 scripts/agent_state.py stall-check                # Flag agents with no heartbeat in 5min
  python3 scripts/agent_state.py heartbeat <agent>           # Update last heartbeat timestamp
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Resolve all paths relative to project root (parent of scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUS_DIR = PROJECT_ROOT / "data" / "bus"
STATE_FILE = BUS_DIR / "agent_states.json"
LOCKS_DIR = BUS_DIR / "locks"

AGENTS = ["recon", "scan", "fuzz", "exploit", "reporter"]
VALID_STATES = ["idle", "running", "paused", "done", "error"]


def _acquire_state_lock():
    """Acquire lock for state file to prevent concurrent read-modify-write."""
    lock_dir = LOCKS_DIR / "state.lock"
    pid_file = lock_dir / "owner"
    LOCKS_DIR.mkdir(parents=True, exist_ok=True)
    attempts = 0
    while attempts < 100:
        try:
            lock_dir.mkdir()
            pid_file.write_text(f"{os.getpid()}:{time.time()}")
            return True
        except FileExistsError:
            # Check for stale lock
            try:
                if pid_file.exists():
                    content = pid_file.read_text().strip()
                    parts = content.split(":")
                    if len(parts) == 2:
                        owner_pid = int(parts[0])
                        lock_time = float(parts[1])
                        if time.time() - lock_time > 60:
                            _force_release_state_lock()
                            continue
                        try:
                            os.kill(owner_pid, 0)
                        except OSError:
                            _force_release_state_lock()
                            continue
            except (ValueError, OSError):
                _force_release_state_lock()
                continue
            time.sleep(0.1)
            attempts += 1
    print("ERROR: Could not acquire state lock after 10s", file=sys.stderr)
    return False


def _force_release_state_lock():
    """Force release a stale state lock."""
    lock_dir = LOCKS_DIR / "state.lock"
    try:
        pid_file = lock_dir / "owner"
        if pid_file.exists():
            pid_file.unlink()
        lock_dir.rmdir()
    except (FileNotFoundError, OSError):
        pass


def _release_state_lock():
    """Release state file lock."""
    lock_dir = LOCKS_DIR / "state.lock"
    try:
        pid_file = lock_dir / "owner"
        if pid_file.exists():
            pid_file.unlink()
        lock_dir.rmdir()
    except FileNotFoundError:
        pass


def load_states():
    """Load agent states from file."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def save_states(states):
    """Save agent states to file (atomic write via tmp+rename)."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(states, indent=2))
    tmp.replace(STATE_FILE)


def set_state(agent, state):
    """Set agent state. Uses file locking to prevent concurrent clobbering."""
    if state not in VALID_STATES:
        print(f"ERROR: Invalid state '{state}'. Valid: {', '.join(VALID_STATES)}", file=sys.stderr)
        sys.exit(1)

    if not _acquire_state_lock():
        sys.exit(1)

    try:
        states = load_states()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if agent == "all":
            for a in AGENTS:
                states[a] = {
                    "state": state,
                    "updated_at": now,
                    "last_heartbeat": now,
                }
            save_states(states)
            print(f"All agents set to: {state}")
        elif agent in AGENTS:
            old_state = states.get(agent, {}).get("state", "unknown")

            # Anti-loop: done agent cannot be re-spawned without explicit reset
            if old_state == "done" and state == "running":
                print(f"WARNING: Agent '{agent}' is in 'done' state. Cannot re-spawn without explicit reset to 'idle' first.", file=sys.stderr)
                print(f"Use: python3 scripts/agent_state.py set {agent} idle", file=sys.stderr)
                sys.exit(1)

            states[agent] = {
                "state": state,
                "updated_at": now,
                "last_heartbeat": now,
                "previous_state": old_state,
            }
            save_states(states)
            print(f"{agent}: {old_state} -> {state}")
        else:
            print(f"ERROR: Unknown agent '{agent}'. Valid: {', '.join(AGENTS)} or 'all'", file=sys.stderr)
            sys.exit(1)
    finally:
        _release_state_lock()


def get_state(agent):
    """Get agent state."""
    if agent not in AGENTS:
        print(f"ERROR: Unknown agent '{agent}'", file=sys.stderr)
        sys.exit(1)

    states = load_states()
    info = states.get(agent, {"state": "unknown"})
    print(info.get("state", "unknown"))


def list_states():
    """List all agent states."""
    states = load_states()
    print("H1VE Agent States")
    print("=" * 50)
    for agent in AGENTS:
        info = states.get(agent, {"state": "unknown", "updated_at": "never"})
        state = info.get("state", "unknown")
        updated = info.get("updated_at", "never")
        marker = ""
        if state == "running":
            marker = " [ACTIVE]"
        elif state == "done":
            marker = " [COMPLETE]"
        elif state == "error":
            marker = " [ERROR]"
        elif state == "paused":
            marker = " [PAUSED]"
        print(f"  {agent:12s}  {state:8s}  updated: {updated}{marker}")
    print("=" * 50)


def stall_check():
    """Flag agents that are 'running' but have no heartbeat in 5 minutes.

    Exit codes:
      0 = stalls detected (informational, printed to stdout)
      0 = no stalls detected
    Always exits 0. Stall info is in stdout for the supervisor to parse.
    """
    states = load_states()
    now = time.time()
    stalled = []

    for agent in AGENTS:
        info = states.get(agent, {})
        if info.get("state") != "running":
            continue

        last_hb = info.get("last_heartbeat", "")
        if not last_hb:
            stalled.append((agent, "no heartbeat recorded"))
            continue

        try:
            hb_time = datetime.fromisoformat(last_hb.replace("Z", "+00:00")).timestamp()
            elapsed = now - hb_time
            if elapsed > 300:  # 5 minutes
                stalled.append((agent, f"last heartbeat {int(elapsed)}s ago"))
        except (ValueError, TypeError):
            stalled.append((agent, "invalid heartbeat timestamp"))

    if stalled:
        print("STALLED AGENTS DETECTED:")
        for agent, reason in stalled:
            print(f"  {agent}: {reason}")
        print("\nInvestigate: rate limit? auth? network? scope restriction?")
        print("Options: adjust tool flags, retry once, or log and continue.")
    else:
        print("No stalled agents. All running agents have recent heartbeats.")


def heartbeat(agent):
    """Update last heartbeat timestamp for an agent."""
    if agent not in AGENTS:
        print(f"ERROR: Unknown agent '{agent}'", file=sys.stderr)
        sys.exit(1)

    if not _acquire_state_lock():
        sys.exit(1)

    try:
        states = load_states()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if agent in states:
            states[agent]["last_heartbeat"] = now
        else:
            states[agent] = {
                "state": "running",
                "updated_at": now,
                "last_heartbeat": now,
            }

        save_states(states)
        print(f"{agent}: heartbeat updated")
    finally:
        _release_state_lock()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "set":
        if len(sys.argv) < 4:
            print("Usage: agent_state.py set <agent|all> <state>", file=sys.stderr)
            sys.exit(1)
        set_state(sys.argv[2], sys.argv[3])

    elif cmd == "get":
        if len(sys.argv) < 3:
            print("Usage: agent_state.py get <agent>", file=sys.stderr)
            sys.exit(1)
        get_state(sys.argv[2])

    elif cmd == "list":
        list_states()

    elif cmd == "stall-check":
        stall_check()

    elif cmd == "heartbeat":
        if len(sys.argv) < 3:
            print("Usage: agent_state.py heartbeat <agent>", file=sys.stderr)
            sys.exit(1)
        heartbeat(sys.argv[2])

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
