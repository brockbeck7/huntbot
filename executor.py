"""
OpenAI-compatible LLM client.

Supports any server that speaks the OpenAI chat completions API:
Ollama, LM Studio, vLLM, llama.cpp server, etc.

Strategy:
  Round 1 — attempts native tool_choice="required" first; falls back to
             JSON-schema-in-prompt if the model doesn't support tool calling.
  Round 2 — plain chat completion; strips markdown fences and parses JSON.
"""

import json
import re
from typing import Any, Dict, List

from openai import OpenAI

from . import keys
from . import prompt_management as pm

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _client() -> OpenAI:
    return OpenAI(
        base_url=keys.LOCAL_LLM_BASE_URL,
        api_key=keys.LOCAL_LLM_API_KEY,
    )


def _parse_json(text: str) -> Dict[str, Any]:
    """Parse JSON from model output, tolerating markdown fences and leading prose."""
    if not text:
        raise ValueError("Empty model response.")
    stripped = _FENCE_RE.sub("", text).strip()
    # Try a clean parse first
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    # Fall back: find the outermost { } block
    start = stripped.find("{")
    if start == -1:
        raise ValueError(f"No JSON object found in response: {text[:300]}")
    depth = 0
    for i in range(start, len(stripped)):
        if stripped[i] == "{":
            depth += 1
        elif stripped[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(stripped[start : i + 1])
    raise ValueError(f"Unbalanced JSON braces in response: {text[:300]}")


def get_query_context(analyst_question: str, model: str) -> Dict[str, Any]:
    """
    Round 1: translate natural-language question → structured query context.

    Tries native tool calling first; falls back to JSON-in-prompt if the model
    doesn't support tool_choice="required".
    """
    client = _client()

    # Attempt 1: native tool calling
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.0,
            messages=[
                {"role": "system", "content": pm.SYSTEM_PROMPT_TOOL_SELECTION},
                {"role": "user",   "content": analyst_question},
            ],
            tools=pm.TOOLS_QUERY_CONTEXT,
            tool_choice="required",
        )
        msg = resp.choices[0].message
        if getattr(msg, "tool_calls", None):
            args = msg.tool_calls[0].function.arguments
            return json.loads(args) if isinstance(args, str) else args
    except Exception:
        pass  # Fall through to JSON-in-prompt

    # Attempt 2: JSON-schema-in-prompt fallback
    schema_hint = (
        "Return ONLY a JSON object with keys: table_name (string), fields (string[]), "
        "lookback_hours (int), device_name (string), user_name (string), "
        "max_rows (int, default 5000), summary (string). "
        "No prose. No markdown fences. "
        "table_name must be one of: DeviceLogonEvents, DeviceProcessEvents, "
        "DeviceNetworkEvents, DeviceFileEvents, SigninLogs, EmailEvents."
    )
    resp = client.chat.completions.create(
        model=model,
        temperature=0.0,
        messages=[
            {
                "role": "system",
                "content": pm.SYSTEM_PROMPT_TOOL_SELECTION + "\n\n" + schema_hint,
            },
            {"role": "user", "content": analyst_question},
        ],
    )
    return _parse_json(resp.choices[0].message.content or "")


def run_threat_hunt(
    analyst_question: str,
    table_name: str,
    logs: List[Dict[str, Any]],
    model: str,
) -> Dict[str, Any]:
    """Round 2: run the full threat hunt and return parsed findings JSON."""
    client = _client()
    user_prompt = pm.build_threat_hunt_prompt(
        analyst_question, table_name, json.dumps(logs, default=str)
    )
    resp = client.chat.completions.create(
        model=model,
        temperature=0.1,
        messages=[
            {"role": "system", "content": pm.SYSTEM_PROMPT_THREAT_HUNT},
            {"role": "user",   "content": user_prompt},
        ],
    )
    return _parse_json(resp.choices[0].message.content or "")


def estimate_tokens(text: str) -> int:
    """
    Conservative token estimate: 1 token ≈ 4 characters.
    tiktoken is calibrated for OpenAI tokenizers and gives wrong results for
    Llama/Qwen/Mistral, so a safe heuristic beats a precise but wrong number.
    """
    return max(1, len(text) // 4) if text else 0
