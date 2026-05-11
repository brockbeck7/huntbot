"""
Input validation and guardrails.

Enforces table/field allowlists, time window caps, row caps,
model allowlist, and context-window safety margins.
"""

from typing import List, Tuple
from . import model_management

# ── Allowed tables and their permitted fields ────────────────────────────────

ALLOWED_TABLES: dict[str, set[str]] = {
    "DeviceLogonEvents": {
        "TimeGenerated", "DeviceName", "AccountName", "AccountDomain",
        "ActionType", "LogonType", "RemoteIP", "RemoteIPType",
        "InitiatingProcessFileName", "InitiatingProcessAccountName",
    },
    "DeviceProcessEvents": {
        "TimeGenerated", "DeviceName", "AccountName", "FileName",
        "FolderPath", "ProcessCommandLine", "InitiatingProcessFileName",
        "InitiatingProcessCommandLine", "SHA256",
    },
    "DeviceNetworkEvents": {
        "TimeGenerated", "DeviceName", "ActionType", "RemoteIP",
        "RemotePort", "RemoteUrl", "LocalPort",
        "InitiatingProcessFileName", "InitiatingProcessCommandLine",
    },
    "DeviceFileEvents": {
        "TimeGenerated", "DeviceName", "ActionType", "FileName",
        "FolderPath", "SHA256", "InitiatingProcessFileName",
        "InitiatingProcessAccountName",
    },
    "SigninLogs": {
        "TimeGenerated", "UserPrincipalName", "AppDisplayName",
        "IPAddress", "Location", "ResultType", "ResultDescription",
        "ClientAppUsed", "ConditionalAccessStatus",
    },
    "EmailEvents": {
        "Timestamp", "NetworkMessageId", "SenderFromAddress",
        "RecipientEmailAddress", "Subject", "DeliveryAction",
        "EmailDirection", "AuthenticationDetails", "ThreatTypes",
    },
}

ALLOWED_MODELS   = set(model_management.MODELS.keys())
MAX_LOOKBACK_HOURS = 336       # 14 days
MAX_ROWS_TO_LLM    = 50_000


def validate_table_and_fields(
    table: str, fields: List[str]
) -> Tuple[str, List[str]]:
    if table not in ALLOWED_TABLES:
        raise ValueError(
            f"Table '{table}' is not allowed. "
            f"Allowed tables: {sorted(ALLOWED_TABLES)}"
        )
    allowed = ALLOWED_TABLES[table]
    if not fields:
        return table, sorted(allowed)
    kept = [f for f in fields if f in allowed]
    return table, kept if kept else sorted(allowed)


def validate_model(model: str) -> str:
    if model not in ALLOWED_MODELS:
        raise ValueError(
            f"Model '{model}' is not in the allowed model list. "
            f"Edit modules/model_management.py to add it."
        )
    return model


def validate_time_window(hours: int) -> int:
    if hours is None or hours < 1:
        return 24
    if hours > MAX_LOOKBACK_HOURS:
        return MAX_LOOKBACK_HOURS
    return int(hours)


def validate_row_count(n: int) -> int:
    if n is None or n < 1:
        return 5_000
    if n > MAX_ROWS_TO_LLM:
        return MAX_ROWS_TO_LLM
    return int(n)


def validate_token_count(estimated_tokens: int, model: str) -> bool:
    """Return True if the prompt fits within 75% of the model's context window."""
    ctx = model_management.MODELS[model]["context_window"]
    return estimated_tokens < ctx * 0.75
