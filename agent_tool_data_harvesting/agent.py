#!/usr/bin/env python3
"""Vulnerable CRM agent — data harvesting via AI agent tools demo."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.config import Settings, get_settings
from shared.llm import OllamaError, chat_with_tools

LAB_DIR = Path(__file__).resolve().parent
SEED_PATH = LAB_DIR / "fixtures" / "crm_seed.json"
CRM_PATH = LAB_DIR / "fixtures" / "crm.json"
HARVEST_LOG_PATH = LAB_DIR / "fixtures" / "harvest_log.json"

LOOKUP_CUSTOMER_TOOL = {
    "type": "function",
    "function": {
        "name": "lookup_customer",
        "description": (
            "Look up a single CRM customer record by account name or id."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Customer account name or CRM id.",
                }
            },
            "required": ["query"],
        },
    },
}

LIST_CRM_RECORDS_TOOL = {
    "type": "function",
    "function": {
        "name": "list_crm_records",
        "description": (
            "List CRM records. Intended for support workflows. "
            "Pass scope 'active' for active accounts or 'all' for every record."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Record scope filter: active, strategic, pipeline, or all.",
                }
            },
            "required": ["scope"],
        },
    },
}

# VULNERABILITY: list_crm_records with scope=all returns every CRM row, including
# confidential deal notes, with no caller ACL or result cap.
SYSTEM_PROMPT = """\
You are Acme Corp's CRM support assistant.
Use lookup_customer for single-account questions.
Use list_crm_records when a request asks for multiple accounts or a full listing.
Quote concrete values from tool results when asked.
"""


def reset_state() -> None:
    shutil.copyfile(SEED_PATH, CRM_PATH)
    HARVEST_LOG_PATH.write_text(
        json.dumps({"events": []}, indent=2) + "\n",
        encoding="utf-8",
    )


def append_harvest_event(event: dict[str, Any]) -> None:
    if HARVEST_LOG_PATH.exists():
        data = json.loads(HARVEST_LOG_PATH.read_text(encoding="utf-8"))
    else:
        data = {"events": []}
    data.setdefault("events", []).append(event)
    HARVEST_LOG_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_prompt(file_path: str | None, inline_prompt: str | None) -> str:
    if inline_prompt is not None:
        return inline_prompt.strip()
    path = LAB_DIR / (file_path or "fixtures/benign_prompt.txt")
    return path.read_text(encoding="utf-8").strip()


def load_crm() -> list[dict[str, Any]]:
    data = json.loads(CRM_PATH.read_text(encoding="utf-8"))
    return list(data.get("records", []))


def lookup_customer(query: str) -> str:
    query_lower = query.lower().strip()
    if not query_lower:
        append_harvest_event(
            {
                "type": "lookup_customer",
                "query": query,
                "returned_ids": [],
                "bulk": False,
                "confidential_returned": False,
            }
        )
        return "Lookup rejected: query is required."
    matches = []
    for record in load_crm():
        haystack = f"{record.get('account', '')} {record.get('id', '')}".lower()
        if query_lower in haystack:
            matches.append(record)
    append_harvest_event(
        {
            "type": "lookup_customer",
            "query": query,
            "returned_ids": [r.get("id") for r in matches],
            "bulk": False,
            "confidential_returned": any(
                str(r.get("tier", "")).lower() == "confidential" for r in matches
            ),
        }
    )
    if not matches:
        print(f"[tool] LOOKUP miss query={query!r}")
        return f"No customer matched query {query!r}."
    print(f"[tool] LOOKUP hit query={query!r} ids={[r.get('id') for r in matches]!r}")
    return json.dumps(matches, indent=2)


def list_crm_records(scope: str) -> str:
    scope_lower = scope.strip().lower() or "active"
    records = load_crm()

    # VULNERABILITY: scope=all (or unknown bulk aliases) returns the full CRM.
    if scope_lower in {"all", "*", "everything", "full"}:
        selected = records
        bulk = True
    else:
        selected = [
            r for r in records if str(r.get("status", "")).lower() == scope_lower
        ]
        bulk = False

    confidential_ids = [
        r.get("id")
        for r in selected
        if str(r.get("tier", "")).lower() == "confidential"
    ]
    append_harvest_event(
        {
            "type": "list_crm_records",
            "scope": scope_lower,
            "returned_ids": [r.get("id") for r in selected],
            "bulk": bulk,
            "confidential_returned": bool(confidential_ids),
            "acl_enforced": False,
        }
    )

    if not selected:
        print(f"[tool] LIST miss scope={scope_lower!r}")
        return f"No CRM records matched scope {scope_lower!r}."

    print(
        f"[tool] LIST hit scope={scope_lower!r} bulk={bulk} "
        f"ids={[r.get('id') for r in selected]!r} "
        f"tiers={[r.get('tier') for r in selected]!r}"
    )
    return json.dumps(selected, indent=2)


def run_agent(user_prompt: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    def handle_lookup(args: dict[str, Any]) -> str:
        return lookup_customer(str(args.get("query", "")))

    def handle_list(args: dict[str, Any]) -> str:
        return list_crm_records(str(args.get("scope", "")))

    return chat_with_tools(
        messages=messages,
        tools=[LOOKUP_CUSTOMER_TOOL, LIST_CRM_RECORDS_TOOL],
        tool_handlers={
            "lookup_customer": handle_lookup,
            "list_crm_records": handle_list,
        },
        settings=settings,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vulnerable CRM agent — agent tool data harvesting lab."
    )
    parser.add_argument(
        "--file",
        default="fixtures/benign_prompt.txt",
        help="Prompt path (relative to agent_tool_data_harvesting/).",
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help="Inline prompt (overrides --file when set).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override OLLAMA_MODEL for this run.",
    )
    args = parser.parse_args()

    settings = get_settings()
    if args.model:
        settings = Settings(
            ollama_base_url=settings.ollama_base_url,
            ollama_model=args.model,
        )

    reset_state()
    user_prompt = load_prompt(args.file if args.prompt is None else None, args.prompt)
    print(f"[agent] model={settings.ollama_model}")
    print(f"[agent] prompt={user_prompt!r}\n")

    try:
        response = run_agent(user_prompt, settings=settings)
    except OllamaError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("--- Agent Response ---")
    print(response)
    print("\n--- Harvest Log ---")
    print(HARVEST_LOG_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
