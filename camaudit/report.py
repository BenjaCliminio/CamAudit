"""Generación de reportes de auditoría en JSON o CSV."""

import json
import csv
from datetime import datetime, timezone


def build_report(network: str, findings: list) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network_scanned": network,
        "total_devices_checked": len(findings),
        "vulnerable_devices": [f for f in findings if f and f.get("vulnerable")],
    }


def save_report(report: dict, path: str):
    if path.endswith(".csv"):
        rows = report["vulnerable_devices"]
        with open(path, "w", newline="") as f:
            if not rows:
                f.write("ip,port,protocol,user,password\n")
                return
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    else:
        with open(path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)