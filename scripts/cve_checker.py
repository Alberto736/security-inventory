#!/usr/bin/env python3
"""
CVE Checker - Lee todos los yamls del inventario y consulta NVD
"""

import os
import glob
import time
import requests
import yaml
from datetime import datetime, timedelta, timezone

NOTIFY_SEVERITIES = {"CRITICAL", "HIGH"}
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def load_all_inventories(inventario_path):
    """Lee todos los yamls de la carpeta inventario"""
    technologies = []
    for filepath in glob.glob(f"{inventario_path}/*.yaml"):
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
            if not data:
                continue
            repo = data.get("repo", "unknown")
            for dep in data.get("dependencias", []):
                dep["repo"] = repo
                technologies.append(dep)
    return technologies

def query_nvd(keyword, version=None, api_key=None):
    """Consulta NVD API"""
   pub_start = (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "keywordSearch": f"{keyword} {version}".strip() if version else keyword,
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": 50,
    }

    headers = {"apiKey": api_key} if api_key else {}

    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"  [WARNING] NVD error para '{keyword}': {e}")
        return []

def parse_severity(vuln):
    """Extrae severidad y score CVSS"""
    metrics = vuln.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return data.get("baseSeverity", "UNKNOWN").upper(), data.get("baseScore", 0.0)
    return "UNKNOWN", 0.0

def send_to_teams(webhook_url, alerts):
    """Manda las alertas a Teams"""
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in alerts if a["severity"] == "HIGH")

    facts = []
    for a in alerts[:15]:
        emoji = "🔴" if a["severity"] == "CRITICAL" else "🟠"
        facts.append({
            "type": "FactSet",
            "separator": True,
            "facts": [
                {"title": "CVE", "value": a["cve_id"]},
                {"title": "Repositorio", "value": a["repo"]},
                {"title": "Tecnología", "value": f"{a['name']} {a['version']}"},
                {"title": "Severidad", "value": f"{emoji} {a['severity']} (CVSS {a['score']})"},
            ]
        })

    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "Container",
                        "style": "attention" if critical > 0 else "warning",
                        "items": [
                            {"type": "TextBlock", "text": "🔐 Nuevas Vulnerabilidades Detectadas",
                             "weight": "Bolder", "size": "Large", "color": "Light"},
                            {"type": "TextBlock", "color": "Light", "isSubtle": True,
                             "text": f"{critical} Críticas · {high} Altas · {datetime.now().strftime('%Y-%m-%d %H:%M')}"}
                        ]
                    },
                    *facts
                ],
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "Ver en NVD",
                    "url": "https://nvd.nist.gov/vuln/search"
                }]
            }
        }]
    }

    requests.post(webhook_url, json=payload, timeout=15)

def main():
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL")
    api_key = os.environ.get("NVD_API_KEY")
    inventario_path = os.environ.get("INVENTARIO_PATH", "inventario")

    print(f"[INFO] Leyendo inventarios de: {inventario_path}")
    technologies = load_all_inventories(inventario_path)
    print(f"[INFO] {len(technologies)} dependencias encontradas en todos los repositorios")

    alerts = []
    for tech in technologies:
        name = tech.get("name", "")
        version = tech.get("version", "")
        repo = tech.get("repo", "unknown")
        print(f"  Checking: {name} {version} ({repo})...")

        vulns = query_nvd(name, version, api_key)
        for v in vulns:
            severity, score = parse_severity(v)
            if severity not in NOTIFY_SEVERITIES:
                continue
            cve = v.get("cve", {})
            alerts.append({
                "repo": repo,
                "name": name,
                "version": version,
                "cve_id": cve.get("id", "UNKNOWN"),
                "severity": severity,
                "score": score,
            })

        time.sleep(2)

    print(f"\n[INFO] {len(alerts)} alertas encontradas")

    if alerts and webhook_url:
        alerts.sort(key=lambda x: x["score"], reverse=True)
        send_to_teams(webhook_url, alerts)
        print("[INFO] ✅ Alertas enviadas a Teams")
    elif not alerts:
        print("[INFO] ✅ Sin vulnerabilidades nuevas")

if __name__ == "__main__":
    main()
