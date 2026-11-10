import json
import sys

source = "/var/ossec/logs/alerts/alerts.json"
event = None
with open(source, "rb") as f:
    for line in f:
        if b'"100777"' not in line:
            continue
        try:
            a = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if str(a.get("rule", {}).get("id")) == "100777" and str(a.get("agent", {}).get("id")) == "002":
            event = a

if event is None:
    sys.exit("NO_MATCH")

win = event.get("data", {}).get("win", {}).get("system", {})
result = {
    "source": "wazuh",
    "id": event["id"],
    "timestamp": event["timestamp"],
    "agent": {"id": event["agent"]["id"], "name": event["agent"]["name"]},
    "rule": {
        "id": event["rule"]["id"],
        "level": event["rule"]["level"],
        "description": event["rule"]["description"],
        "mitre": []
    },
    "data": {
        "eventID": win.get("eventID"),
        "providerName": win.get("providerName"),
        "channel": win.get("channel")
    }
}

print(json.dumps(result, ensure_ascii=False))
