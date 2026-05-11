"""
Display helpers, ANSI color printing, and JSONL persistence.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

_USE_COLOR = sys.stdout.isatty()
_R   = "\033[0m"  if _USE_COLOR else ""
_B   = "\033[1m"  if _USE_COLOR else ""
_RED = "\033[31m" if _USE_COLOR else ""
_GRN = "\033[32m" if _USE_COLOR else ""
_YLW = "\033[33m" if _USE_COLOR else ""
_BLU = "\033[34m" if _USE_COLOR else ""
_CYN = "\033[36m" if _USE_COLOR else ""
_DIM = "\033[2m"  if _USE_COLOR else ""


def print_info(msg: str)    -> None: print(f"{_CYN}[i]{_R} {msg}")
def print_success(msg: str) -> None: print(f"{_GRN}[+]{_R} {msg}")
def print_warn(msg: str)    -> None: print(f"{_YLW}[!]{_R} {msg}")
def print_error(msg: str)   -> None: print(f"{_RED}[x]{_R} {msg}")


def print_header(msg: str) -> None:
    bar = "═" * len(msg)
    print(f"\n{_B}{_BLU}{bar}\n{msg}\n{bar}{_R}")


_DEFAULTS: Dict[str, Any] = {
    "table_name":    "DeviceLogonEvents",
    "fields":        [],
    "lookback_hours": 24,
    "device_name":   "",
    "user_name":     "",
    "max_rows":      5_000,
    "summary":       "",
}


def sanitize_query_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Merge model output with safe defaults; coerce types."""
    out = dict(_DEFAULTS)
    if isinstance(ctx, dict):
        for k, v in ctx.items():
            if k in out and v is not None:
                out[k] = v
    try:
        out["lookback_hours"] = int(out["lookback_hours"])
    except (TypeError, ValueError):
        out["lookback_hours"] = 24
    try:
        out["max_rows"] = int(out["max_rows"])
    except (TypeError, ValueError):
        out["max_rows"] = 5_000
    if not isinstance(out["fields"], list):
        out["fields"] = []
    out["device_name"] = str(out["device_name"] or "")
    out["user_name"]   = str(out["user_name"]   or "")
    return out


def display_query_context(ctx: Dict[str, Any]) -> None:
    print_header("Query context")
    print(f"  table    : {ctx['table_name']}")
    print(f"  lookback : {ctx['lookback_hours']}h   max rows: {ctx['max_rows']}")
    print(f"  device   : {ctx['device_name'] or '(any)'}")
    print(f"  user     : {ctx['user_name']   or '(any)'}")
    print(f"  summary  : {ctx['summary']}")


def display_findings(findings: List[Dict[str, Any]]) -> None:
    print_header("Findings")
    if not findings:
        print_success("No suspicious patterns detected.")
        return

    sev_color = {
        "Critical": _RED,
        "High":     _RED,
        "Medium":   _YLW,
        "Low":      _DIM,
    }

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "Low")
        c   = sev_color.get(sev, "")
        print(f"\n{_B}[{i}] {f.get('title', '(no title)')}{_R}")
        print(f"    severity   : {c}{sev}{_R}   confidence: {f.get('confidence', '')}")
        print(f"    {f.get('summary', '')}")

        if f.get("mitre"):
            print(f"    MITRE      : {', '.join(f['mitre'])}")

        iocs = f.get("iocs") or {}
        for ioc_type, vals in iocs.items():
            if vals:
                print(f"    {ioc_type:<12}: {', '.join(str(v) for v in vals)}")

        for action in f.get("recommended_actions") or []:
            print(f"        → {action}")


def persist_findings(
    findings: List[Dict[str, Any]],
    path: str = "threats.jsonl",
) -> None:
    if not findings:
        return
    now = datetime.now(timezone.utc).isoformat()
    with Path(path).open("a") as fh:
        for finding in findings:
            fh.write(
                json.dumps({**finding, "_detected_at": now}, default=str) + "\n"
            )
    print_info(f"Persisted {len(findings)} finding(s) to {path}")
