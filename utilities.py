"""
Local model catalog and auto-selection logic.

Add or remove models here to match what you have pulled in Ollama / LM Studio.
context_window values are conservative — real limits may be higher.
"""

MODELS: dict[str, dict] = {
    "llama3.1:8b":      {"context_window": 128_000, "good_for": "fast tool-calling"},
    "qwen2.5:7b":       {"context_window":  32_000, "good_for": "fast, follows JSON schemas"},
    "qwen2.5:14b":      {"context_window":  32_000, "good_for": "balanced reasoning (default)"},
    "qwen2.5:32b":      {"context_window":  32_000, "good_for": "deeper reasoning"},
    "llama3.1:70b":     {"context_window": 128_000, "good_for": "largest hunts, slowest"},
    "mistral-nemo:12b": {"context_window": 128_000, "good_for": "long-context fallback"},
}

# Round-1: translate NL → structured query context (tool call)
TOOL_CALL_MODEL    = "llama3.1:8b"

# Round-2: run the actual threat hunt against log rows
DEFAULT_HUNT_MODEL  = "qwen2.5:14b"
LARGE_CONTEXT_MODEL = "mistral-nemo:12b"


def pick_hunt_model(estimated_tokens: int) -> str:
    """
    Select the smallest model whose context window fits the prompt.
    Falls back to LARGE_CONTEXT_MODEL if the default is too tight.
    """
    default_ctx = MODELS[DEFAULT_HUNT_MODEL]["context_window"]
    if estimated_tokens < default_ctx * 0.75:
        return DEFAULT_HUNT_MODEL
    return LARGE_CONTEXT_MODEL
