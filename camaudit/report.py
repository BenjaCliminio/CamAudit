"""Generación de reportes de auditoría en JSON o CSV."""

import json
import csv
from datetime import datetime, timezone
 
 
def build_report(network: str, findings: list) -> dict:
    vulnerable = [f for f in findings if f and f.get("vulnerable")]
    confirmed = [f for f in vulnerable if f.get("confidence") == "confirmed"]
    unconfirmed = [f for f in vulnerable if f.get("confidence") != "confirmed"]
 
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network_scanned": network,
        "total_devices_checked": len(findings),
        "camaras_confirmadas_vulnerables": confirmed,
        "otros_dispositivos_vulnerables": unconfirmed,
    }
 
 
def _write_csv_rows(path: str, rows: list):
    with open(path, "w", newline="") as f:
        if not rows:
            f.write("ip,port,protocol,user,password,confidence\n")
            return
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
 
 
def save_report(report: dict, path: str):
    if path.endswith(".csv"):
        # En CSV se combinan ambos grupos, distinguibles por la columna
        # "confidence" (confirmed / unconfirmed).
        rows = (
            report["camaras_confirmadas_vulnerables"]
            + report["otros_dispositivos_vulnerables"]
        )
        _write_csv_rows(path, rows)
    else:
        with open(path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)