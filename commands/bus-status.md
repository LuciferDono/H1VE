---
name: bus-status
description: >
  Show H1VE swarm status. Displays agent states, bus message counts, and mission progress.
  Usage: /bus-status
---

# Bus Status

Run these commands and present a summary:

```bash
python3 scripts/bus.py status
python3 scripts/agent_state.py list
python3 scripts/supervisor.py mission-status
```

Present the output in a clear format showing:
- Which agents are active, idle, done, or stalled
- Pending messages in each inbox
- Total findings and alerts
- Phase completion status
