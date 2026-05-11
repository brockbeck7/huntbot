"""
All prompts, tool schemas, and per-table threat-hunt guidance.

Round 1 — tool selection : translate NL → structured query context.
Round 2 — threat hunt    : system prompt + table guidance + JSON schema + logs.
"""

# ── Round 1: Tool-selection system prompt ────────────────────────────────────

SYSTEM_PROMPT_TOOL_SELECTION = """\
You are a SOC analyst's assistant. Your only job is to translate the analyst's
natural-language request into a structured query context by calling the
`build_query_context` tool exactly once.

Rules:
- ALWAYS call the tool. Never reply in plain text.
- If the analyst didn't specify a value, infer a sensible default.
- Time windows are in hours. "last week" = 168 hours.
- Tables you may pick from:
    DeviceLogonEvents, DeviceProcessEvents, DeviceNetworkEvents,
    DeviceFileEvents, SigninLogs, EmailEvents
- Hostname → device_name. User/UPN → user_name. Otherwise leave empty string.
"""

TOOLS_QUERY_CONTEXT = [
    {
        "type": "function",
        "function": {
            "name": "build_query_context",
            "description": "Translate analyst's NL request into a structured query context.",
            "parameters": {
                "type": "object",
                "properties": {
                    "table_name":     {
                        "type": "string",
                        "enum": [
                            "DeviceLogonEvents", "DeviceProcessEvents",
                            "DeviceNetworkEvents", "DeviceFileEvents",
                            "SigninLogs", "EmailEvents",
                        ],
                    },
                    "fields":         {"type": "array", "items": {"type": "string"}},
                    "lookback_hours": {"type": "integer", "minimum": 1, "maximum": 336},
                    "device_name":    {"type": "string"},
                    "user_name":      {"type": "string"},
                    "max_rows":       {"type": "integer", "minimum": 1, "maximum": 50000},
                    "summary":        {"type": "string"},
                },
                "required": [
                    "table_name", "fields", "lookback_hours",
                    "device_name", "user_name", "max_rows", "summary",
                ],
            },
        },
    }
]

# ── Round 2: Threat-hunt system prompt ───────────────────────────────────────

SYSTEM_PROMPT_THREAT_HUNT = """\
You are a senior SOC analyst performing a threat hunt. You will be given:
  1. The analyst's original question.
  2. Hunting heuristics specific to the log table involved.
  3. A required output schema (strict JSON).
  4. A batch of log rows in JSON.

Identify suspicious patterns, map findings to MITRE ATT&CK, extract IOCs,
and produce findings in the exact schema below.
Do NOT hallucinate IOCs that are not present in the provided logs.
An empty findings array is a valid and acceptable answer.
"""

# ── Per-table hunting heuristics ─────────────────────────────────────────────

THREAT_HUNT_PROMPTS: dict[str, str] = {
    "DeviceLogonEvents": """\
Hunt for:
- Bursts of LogonFailed against one account followed by LogonSuccess from the same IP
  (brute force that succeeded).
- Successful logons from new or rare source IPs for that account.
- Off-hours logons for service accounts.
- Logon type 10 (RemoteInteractive / RDP) to servers that should not be accessed via RDP.
""",
    "DeviceProcessEvents": """\
Hunt for:
- LOLBins: certutil.exe, bitsadmin.exe, mshta.exe, rundll32.exe with unusual args,
  regsvr32.exe /i:http.
- powershell.exe with -enc / -EncodedCommand, or DownloadString/IEX chained together.
- Office applications (winword.exe, excel.exe) spawning cmd.exe or powershell.exe.
- Post-access discovery commands: whoami, net user, net group, nltest.
""",
    "DeviceNetworkEvents": """\
Hunt for:
- Beaconing: same RemoteIP/Port contacted at consistent intervals.
- Connections to raw IPs on non-standard ports with no DNS resolution path.
- Large outbound data transfers outside business hours.
- DNS queries to high-abuse TLDs (.tk, .xyz dynamic, dyndns variants).
""",
    "DeviceFileEvents": """\
Hunt for:
- Mass file rename or extension change (ransomware staging).
- Writes to startup folders, Run registry keys, or scheduled-task paths.
- Files dropped to %TEMP% or %APPDATA% and executed within seconds.
- Suspicious double extensions (e.g. invoice.pdf.exe).
""",
    "SigninLogs": """\
Hunt for:
- Impossible travel: two successful sign-ins from geographically distant locations
  within too short a time window to be physically plausible.
- Password spray: many authentication failures across multiple accounts from one IP.
- Successful logins from anonymous proxies, hosting ASNs, or VPN exit nodes
  for normally corporate-only accounts.
- MFA fatigue: repeated MFA prompts followed by a successful authentication.
""",
    "EmailEvents": """\
Hunt for:
- Inbound messages from newly registered domains carrying attachments or URLs.
- Senders that fail SPF, DKIM, or DMARC but were delivered to the inbox.
- Phishing subject-line patterns: invoice, payment, urgent, password reset.
- Internal user replies to lookalike external domains (business email compromise).
""",
}

# ── Output format contract ────────────────────────────────────────────────────

FORMATTING_INSTRUCTIONS = """\
Respond with a JSON object matching EXACTLY this schema.
No prose. No markdown fences. No additional keys.

{
  "findings": [
    {
      "title": "short headline",
      "severity": "Low|Medium|High|Critical",
      "confidence": "Low|Medium|High",
      "summary": "2-3 sentence explanation of why this is suspicious",
      "mitre": ["T1110.001"],
      "iocs": {
        "ips": [],
        "hosts": [],
        "users": [],
        "processes": [],
        "files": [],
        "hashes": []
      },
      "evidence_row_ids": [12, 47],
      "recommended_actions": ["isolate the host", "reset the account"]
    }
  ]
}

If nothing suspicious was found: {"findings": []}
"""


def build_threat_hunt_prompt(
    analyst_question: str, table_name: str, logs_json: str
) -> str:
    """Assemble the full Round-2 user prompt."""
    table_guidance = THREAT_HUNT_PROMPTS.get(
        table_name, "Hunt for any anomalous or suspicious patterns in these logs."
    )
    return (
        f"# Analyst question\n{analyst_question}\n\n"
        f"# Hunting guidance for {table_name}\n{table_guidance}\n\n"
        f"# Output schema\n{FORMATTING_INSTRUCTIONS}\n\n"
        f"# Log rows\n{logs_json}\n"
    )
