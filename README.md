# HuntBot — Agentic SOC AI Analyst

> A fully local, agentic threat-hunting pipeline that translates natural-language questions into structured SIEM queries, runs AI-powered analysis against real or mock log data, surfaces MITRE ATT&CK-mapped findings, and offers automated remediation — all without sending data to a third-party API.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![LLM: Any OpenAI-compatible](https://img.shields.io/badge/LLM-OpenAI--compatible-orange)](https://ollama.com/)

---

## Overview

HuntBot is an agentic SOC analyst built in Python. Feed it a plain-English threat-hunt question; it autonomously builds a query context, retrieves relevant log data, selects an appropriate local LLM, runs a structured threat hunt, and outputs actionable findings — complete with IOCs, MITRE technique mappings, and optional remediation actions against Microsoft Defender for Endpoint.

No OpenAI account required. No log data leaves your environment.

### How it works

```
Analyst question (natural language)
        │
        ▼
┌──────────────────┐
│  Round 1 LLM     │  Small, fast model translates NL → structured query context
│  (tool call)     │  (table, fields, time window, device/user filters)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Guardrails     │  Validates table, fields, lookback, row count, model
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Log Source     │  mock (built-in IOCs) | file (JSONL export) | azure (live KQL)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Round 2 LLM     │  Larger model hunts for anomalies, maps MITRE, extracts IOCs
│  (threat hunt)   │  Returns strict JSON findings schema
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Remediation     │  Isolate device, block IP, disable account (MDE API or dry-run)
└──────────────────┘
```

---

## Features

- **100% local** — connects to Ollama, LM Studio, vLLM, or any OpenAI-compatible server
- **Two-round agentic pipeline** — dedicated models for query-building vs. deep analysis
- **Dual tool-call strategy** — native `tool_choice="required"` with JSON-fallback for models that don't support it
- **Three log backends** — built-in mock data with real IOCs, JSONL file export, or live Azure Monitor / Microsoft Sentinel via KQL
- **Six log table schemas** — DeviceLogonEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, SigninLogs, EmailEvents
- **MITRE ATT&CK mapping** — findings include technique IDs from the ATT&CK framework
- **Guardrails** — table/field allowlists, 14-day lookback cap, 50K row cap, context-window safety check
- **Agentic remediation** — MDE isolate, IP block, account disable (dry-run by default; live when Azure AD credentials are configured)
- **Persistence** — findings appended to `threats.jsonl` with UTC timestamps
- **`--autonomous` mode** — skip confirmation prompts for automated pipelines

---

## Quick Start

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/) (or LM Studio / vLLM)

### 1. Clone and install

```bash
git clone https://github.com/<your-username>/huntbot.git
cd huntbot
pip install -r requirements.txt
```

### 2. Pull models

```bash
ollama pull llama3.1:8b    # Round 1 — query context (fast)
ollama pull qwen2.5:14b    # Round 2 — threat hunt (default)
ollama serve
```

### 3. Run a hunt

```bash
# Interactive prompt
python main.py

# Inline question
python main.py "Any brute force attempts on WIN-DC-01 in the last 12 hours?"

# Skip remediation confirmations
python main.py "Lateral movement from WORKSTATION-07?" --autonomous
```

The default `LOG_BACKEND=mock` mode runs against synthetic log data with planted IOCs so the pipeline works immediately — no SIEM connection required.

---

## Configuration

Copy `.env.example` to `.env` and set the variables you need:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `LOCAL_LLM_BASE_URL` | `http://localhost:11434/v1` | LLM server endpoint |
| `LOCAL_LLM_API_KEY` | `not-needed` | API key (Ollama doesn't require one) |
| `LOG_BACKEND` | `mock` | `mock` \| `file` \| `azure` |
| `LOCAL_LOG_DIR` | `./logs` | Directory for JSONL log files (file backend) |
| `AZURE_WORKSPACE_ID` | — | Azure Log Analytics workspace ID |
| `AAD_TENANT_ID` | — | Azure AD tenant ID (Sentinel + MDE remediation) |
| `AAD_CLIENT_ID` | — | Azure AD app registration client ID |
| `AAD_CLIENT_SECRET` | — | Azure AD app registration secret |

---

## Log Backends

### Mock (default)

No setup required. Generates synthetic log rows with realistic planted IOCs:

| Table | Planted threat |
|---|---|
| DeviceLogonEvents | Brute force (15 failures → success) from `203.0.113.77` |
| DeviceProcessEvents | `winword.exe` → `powershell -enc` → `certutil` download chain |
| DeviceNetworkEvents | C2 beacon every 60s to `203.0.113.77:8443` |
| DeviceFileEvents | Mass `.locked` file renames (ransomware) |
| SigninLogs | Impossible travel: New York → Kazakhstan in 5 minutes |
| EmailEvents | Phishing from `micros0ft-support.com` failing SPF/DKIM/DMARC |

### File

Export logs from any SIEM as JSON Lines and drop them in `./logs/`:

```
logs/
  DeviceLogonEvents.jsonl
  DeviceProcessEvents.jsonl
  SigninLogs.jsonl
  ...
```

Each line must be a valid JSON object. Field names should match the schemas defined in `modules/guardrails.py`.

```bash
export LOG_BACKEND=file
export LOCAL_LOG_DIR=./logs
python main.py "Any suspicious logon activity in the last 24 hours?"
```

### Azure Monitor / Microsoft Sentinel (live)

Uncomment the Azure packages in `requirements.txt`, install them, and configure the Azure env vars:

```bash
pip install azure-identity azure-monitor-query
export LOG_BACKEND=azure
export AZURE_WORKSPACE_ID=<your-workspace-id>
export AAD_TENANT_ID=<tenant-id>
export AAD_CLIENT_ID=<client-id>
export AAD_CLIENT_SECRET=<client-secret>
python main.py "Password spray against any account in the last 6 hours?"
```

The Azure backend constructs and runs a KQL query against your live workspace on every invocation.

---

## Model Configuration

Models are configured in `modules/model_management.py`. Add any model available in your local server:

```python
MODELS = {
    "llama3.1:8b":      {"context_window": 128_000, "good_for": "fast tool-calling"},
    "qwen2.5:14b":      {"context_window":  32_000, "good_for": "balanced reasoning (default)"},
    "mistral-nemo:12b": {"context_window": 128_000, "good_for": "long-context fallback"},
    # Add your own:
    "deepseek-r1:14b":  {"context_window":  64_000, "good_for": "strong reasoning"},
}

TOOL_CALL_MODEL    = "llama3.1:8b"   # Round 1
DEFAULT_HUNT_MODEL = "qwen2.5:14b"   # Round 2
```

HuntBot auto-selects the hunt model based on estimated prompt tokens, falling back to the large-context model when the default's context window is too small.

---

## Findings Schema

Every finding produced by the Round 2 LLM follows this schema:

```json
{
  "title": "Brute Force Success — svc_backup from 203.0.113.77",
  "severity": "High",
  "confidence": "High",
  "summary": "15 failed logon attempts followed by a successful authentication ...",
  "mitre": ["T1110.001"],
  "iocs": {
    "ips":       ["203.0.113.77"],
    "hosts":     ["WIN-DC-01"],
    "users":     ["svc_backup"],
    "processes": [],
    "files":     [],
    "hashes":    []
  },
  "evidence_row_ids": [0, 1, 2, 15],
  "recommended_actions": [
    "Reset the svc_backup credential immediately",
    "Block 203.0.113.77 at the perimeter firewall",
    "Review all sessions authenticated as svc_backup in the last 24h"
  ]
}
```

All findings are appended to `threats.jsonl` with a UTC `_detected_at` timestamp.

---

## Remediation

For findings with severity `High` or `Critical` and confidence `Medium` or `High`, HuntBot offers remediation actions:

| Action | Implementation | Requires |
|---|---|---|
| Isolate device | MDE API `/machines/{id}/isolate` | AAD credentials |
| Block IP | Stub (extend to your firewall) | — |
| Disable account | Stub (extend to Azure AD / AD) | — |

Without AAD credentials configured, all actions run in **dry-run mode** and log what they _would_ do.

Use `--autonomous` to skip interactive confirmation prompts:

```bash
python main.py "Active C2 beaconing?" --autonomous
```

---

## Project Structure

```
huntbot/
├── main.py                    # 9-step orchestrator (entry point)
├── requirements.txt
├── .env.example               # Environment variable template
├── .gitignore
└── modules/
    ├── __init__.py
    ├── keys.py                # Environment-driven configuration
    ├── model_management.py    # Model catalog + auto-selection
    ├── prompt_management.py   # All prompts, tool schemas, table guidance
    ├── guardrails.py          # Input validation and safety limits
    ├── log_source.py          # Mock / file / Azure log backends
    ├── llm_client.py          # OpenAI-compatible client (tool-call + JSON fallback)
    ├── executor.py            # Remediation actions (MDE, stubs)
    └── utilities.py           # ANSI output, display helpers, JSONL persistence
```

---

## Extending HuntBot

**Add a new log table** — add the table name and allowed fields to `guardrails.py`, add hunting guidance to `prompt_management.py`, add a mock generator to `log_source.py`.

**Add a new log backend** — add a new branch in `log_source.query_logs()` and a corresponding env value for `LOG_BACKEND`.

**Add a new remediation action** — add a function to `executor.py` and call it from `consider_remediation()`.

**Use a different LLM provider** — change `LOCAL_LLM_BASE_URL` to any OpenAI-compatible endpoint. Works with LM Studio, vLLM, llama.cpp server, Groq, and others.

---

## Inspiration

Built following the architecture from Josh Madakor's [Agentic Cybersecurity AI SOC Analyst course](https://www.youtube.com/), re-engineered to run entirely on local LLMs via any OpenAI-compatible server.

---

## License

MIT — see [LICENSE](LICENSE) for details.


