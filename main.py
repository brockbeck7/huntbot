"""
HuntBot -- Agentic SOC AI Analyst
Main orchestrator (9-step pipeline).

Pipeline:
  1. Read analyst's natural-language question.
  2. Round-1 LLM: build a structured query context (tool call).
  3. Validate the query context through guardrails.
  4. Query the log source (mock / file / Azure).
  5. Assemble the threat-hunt prompt with table-specific guidance.
  6. Estimate tokens, pick a model with the right context window.
  7. Round-2 LLM: run the threat hunt, return strict JSON findings.
  8. Display + persist findings.
  9. Offer agentic remediation on high-severity / high-confidence findings.
"""

import argparse
import json
import sys

from modules import guardrails, llm_client, log_source, model_management, utilities
from modules import executor
from modules import prompt_management as pm


def run_once(question: str, autonomous: bool = False) -> int:
    utilities.print_header("HuntBot — Agentic SOC AI")
    utilities.print_info(f"Analyst question: {question}")

    utilities.print_info(f"Asking {model_management.TOOL_CALL_MODEL} to build query context...")
    try:
        raw_ctx = llm_client.get_query_context(question, model_management.TOOL_CALL_MODEL)
    except Exception as e:
        utilities.print_error(f"Round-1 LLM call failed: {e}")
        return 2

    ctx = utilities.sanitize_query_context(raw_ctx)

    try:
        ctx["table_name"], ctx["fields"] = guardrails.validate_table_and_fields(
            ctx["table_name"], ctx["fields"]
        )
        ctx["lookback_hours"] = guardrails.validate_time_window(ctx["lookback_hours"])
        ctx["max_rows"] = guardrails.validate_row_count(ctx["max_rows"])
    except ValueError as e:
        utilities.print_error(f"Guardrails rejected the query: {e}")
        return 3

    utilities.display_query_context(ctx)

    utilities.print_info("Querying log source...")
    try:
        logs = log_source.query_logs(
            table_name=ctx["table_name"],
            fields=ctx["fields"],
            lookback_hours=ctx["lookback_hours"],
            device_name=ctx["device_name"],
            user_name=ctx["user_name"],
            max_rows=ctx["max_rows"],
        )
    except Exception as e:
        utilities.print_error(f"Log query failed: {e}")
        return 4

    utilities.print_success(f"Retrieved {len(logs)} log rows.")
    if not logs:
        utilities.print_warn("No rows returned — nothing to hunt in. Exiting.")
        return 0

    logs_json = json.dumps(logs, default=str)
    hunt_prompt = pm.build_threat_hunt_prompt(question, ctx["table_name"], logs_json)

    est_tokens = llm_client.estimate_tokens(hunt_prompt)
    hunt_model = model_management.pick_hunt_model(est_tokens)
    utilities.print_info(
        f"Estimated prompt tokens: ~{est_tokens}.  Hunt model: {hunt_model}"
    )

    try:
        hunt_model = guardrails.validate_model(hunt_model)
    except ValueError as e:
        utilities.print_error(str(e))
        return 5

    if not guardrails.validate_token_count(est_tokens, hunt_model):
        utilities.print_error(
            f"Prompt is too big for {hunt_model}'s context window. "
            f"Re-run with a tighter time window or smaller max_rows."
        )
        return 6

    utilities.print_info("Running threat hunt...")
    try:
        result = llm_client.run_threat_hunt(question, ctx["table_name"], logs, hunt_model)
    except Exception as e:
        utilities.print_error(f"Round-2 LLM call failed: {e}")
        return 7

    findings = result.get("findings", []) if isinstance(result, dict) else []

    utilities.display_findings(findings)
    utilities.persist_findings(findings)

    if findings:
        utilities.print_header("Remediation")
        executor.consider_remediation(findings, autonomous=autonomous)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HuntBot — Agentic SOC AI threat hunter (local LLM)"
    )
    parser.add_argument(
        "question",
        nargs="?",
        help="Threat-hunt question. If omitted, you will be prompted.",
    )
    parser.add_argument(
        "--autonomous",
        action="store_true",
        help="Skip confirmation prompts for remediation actions. Use carefully.",
    )
    args = parser.parse_args()

    question = args.question
    if not question:
        try:
            question = input("Threat hunt question: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
    if not question:
        utilities.print_error("No question provided.")
        return 1

    return run_once(question, autonomous=args.autonomous)


if __name__ == "__main__":
    sys.exit(main())
