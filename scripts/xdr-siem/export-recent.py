import json
from collections import deque

SOURCE = "/var/ossec/logs/alerts/alerts.json"
recent = deque(maxlen=100)

with open(SOURCE, "rb") as f:
    for line in f:
        try:
            event = json.loads(line)
            if isinstance(event, dict):
                recent.append(event)
        except (UnicodeDecodeError, ValueError):
            continue

results = []

for event in recent:
    rule = event.get("rule") or {}
    agent = event.get("agent") or {}
    decoder = event.get("decoder") or {}

    mitre = rule.get("mitre") or {}
    if isinstance(mitre, dict):
        mitre = mitre.get("id", [])
    if not isinstance(mitre, list):
        mitre = []

    win = (event.get("data") or {}).get("win") or {}
    system = win.get("system") or {}

    results.append({
        "source": "wazuh",
        "id": str(event.get("id", "")),
        "timestamp": event.get("timestamp"),
        "agent": {
            "id": str(agent.get("id", "")),
            "name": str(agent.get("name", ""))
        },
        "rule": {
            "id": str(rule.get("id", "")),
            "level": rule.get("level", 0),
            "description": str(rule.get("description", ""))[:500],
            "mitre": mitre
        },
        "decoder": {
            "name": decoder.get("name", "")
        },
        "data": {
            "eventID": system.get("eventID"),
            "providerName": system.get("providerName"),
            "channel": system.get("channel")
        }
    })

print(json.dumps({
    "schema": "shinseokgi.wazuh.alerts.v1",
    "count": len(results),
    "alerts": results
}, ensure_ascii=False))
