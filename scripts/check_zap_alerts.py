#!/usr/bin/env python3
import json
import sys
from pathlib import Path

zap_file = Path("zap-reports/zap_report.json")
if not zap_file.exists():
    print(f"ERROR: {zap_file} not found")
    sys.exit(2)

with zap_file.open() as f:
    data = json.load(f)

alerts = []
for site in data.get("site", []):
    for a in site.get("alerts", []):
        severity = a.get("riskdesc", "").split("(")[0].strip()
        if severity in ("High", "Critical"):
            alerts.append(a)

count = len(alerts)
print(f"High/Critical alerts: {count}")

if count > 0:
    sys.exit(1)
