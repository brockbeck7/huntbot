"""
Agentic remediation executor.

Actions:
  isolate_device   — calls Microsoft Defender for Endpoint (MDE) isolate API
  block_ip         — stub (extend to your firewall/EDR of choice)
  disable_account  — stub (extend to Azure AD / on-prem AD)

All actions are DRY-RUN when AAD env vars are absent (safe default).
The --autonomous flag skips confirmation prompts.
"""

import json
from typing import Any, Dict, List

import requests

from . import keys, utilities


# ── MDE helpers ──────────────────────────────────────────────────────────────

def _get_bearer_token() -> str:
    url = (
        f"https://login.microsoftonline.com/{keys.AAD_TENANT_ID}"
        "/oauth2/v2.0/token"
    )
    r = requests.post(
        url,
        data={
            "grant_type":    "client_credentials",
            "client_id":     keys.AAD_CLIENT_ID,
            "client_secret": keys.AAD_CLIENT_SECRET,
            "scope":         "https://api.securitycenter.microsoft.com/.default",
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _get_mde_machine_id(hostname: str, token: str) -> str:
    r = requests.get(
        "https://api.securitycenter.microsoft.com/api/machines",
        params={
            "$filter":  f"computerDnsName eq '{hostname}'",
            "$orderby": "lastSeen desc",
            "$top":     1,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    r.raise_for_status()
    values = r.json().get("value", [])
    if not values:
        raise RuntimeError(f"No MDE machine record found for '{hostname}'")
    return values[0]["id"]


# ── Remediation actions ───────────────────────────────────────────────────────

def isolate_device(hostname: str, reason: str) -> Dict[str, Any]:
    """Full network isolation via MDE API. Dry-runs if AAD creds are absent."""
    if not keys.remediation_enabled():
        return {"dry_run": True, "would_isolate": hostname, "reason": reason}
    token      = _get_bearer_token()
    machine_id = _get_mde_machine_id(hostname, token)
    r = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        },
        data=json.dumps({"Comment": reason, "IsolationType": "Full"}),
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def block_ip(ip: str, reason: str) -> Dict[str, Any]:
    """Stub — wire to your firewall, NSG, or EDR block-list."""
    return {"dry_run": True, "would_block_ip": ip, "reason": reason}


def disable_account(upn: str, reason: str) -> Dict[str, Any]:
    """Stub — wire to Azure AD or on-prem AD disable logic."""
    return {"dry_run": True, "would_disable_account": upn, "reason": reason}


def notify(message: str) -> Dict[str, Any]:
    utilities.print_info(f"NOTIFY: {message}")
    return {"notified": True}


# ── Orchestration ─────────────────────────────────────────────────────────────

def consider_remediation(
    findings: List[Dict[str, Any]], autonomous: bool = False
) -> None:
    """
    For each High/Critical finding with Medium/High confidence,
    offer (or automatically apply) remediation actions.
    """
    actioned = False
    for finding in findings:
        if finding.get("severity") not in ("High", "Critical"):
            continue
        if finding.get("confidence") not in ("Medium", "High"):
            continue

        title  = finding.get("title", "Unknown finding")
        reason = f"HuntBot auto-remediation: {title}"
        iocs   = finding.get("iocs") or {}

        for host in iocs.get("hosts") or []:
            if _confirm(f"Isolate host '{host}'?", autonomous):
                result = isolate_device(host, reason)
                utilities.print_success(f"isolate_device({host}) → {result}")
                actioned = True

        for ip in iocs.get("ips") or []:
            if _confirm(f"Block IP '{ip}'?", autonomous):
                result = block_ip(ip, reason)
                utilities.print_success(f"block_ip({ip}) → {result}")
                actioned = True

        for upn in iocs.get("users") or []:
            if "@" not in upn:
                continue
            if _confirm(f"Disable account '{upn}'?", autonomous):
                result = disable_account(upn, reason)
                utilities.print_success(f"disable_account({upn}) → {result}")
                actioned = True

    if not actioned:
        utilities.print_info("No remediation actions taken.")


def _confirm(prompt: str, autonomous: bool) -> bool:
    if autonomous:
        return True
    return input(f"\n{prompt} [y/N]: ").strip().lower() == "y"
