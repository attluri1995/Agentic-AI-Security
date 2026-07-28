#!/usr/bin/env python3
"""CRM agent with tool-based data-harvesting defenses."""

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

BULK_SCOPES = frozenset({"all", "*", "everything", "full"})
MAX_LIST_RESULTS = 2

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
                "query": {"type": "string"},
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
            "List CRM records for an allowed scope. Bulk 'all' listings are "
            "restricted by policy."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scope": {"type": "string"},
            },
            "required": ["scope"],
        },
    },
}

SYSTEM_PROMPT = """\
You are Acme Corp's CRM support assistant.
Prefer lookup_customer for single-account questions.
Do not invent CRM records. If a tool returns nothing, say so.
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


def apply_acl(records: list[dict[str, Any]], role: str) -> list[dict[str, Any]]:
    role_lower = role.lower().strip()
    return [
        record
        for record in records
        if role_lower in [str(r).lower() for r in record.get("allowed_roles", [])]
    ]


def lookup_customer(query: str, *, role: str, mode: str) -> str:
    query_lower = query.lower().strip()
    if not query_lower:
        append_harvest_event(
            {
                "type": "lookup_customer",
                "query": query,
                "returned_ids": [],
                "bulk": False,
                "confidential_returned": False,
                "acl_enforced": mode == "scope_policy",
                "caller_role": role,
                "mode": mode,
            }
        )
        return "Lookup rejected: query is required."

    matches = []
    for record in load_crm():
        haystack = f"{record.get('account', '')} {record.get('id', '')}".lower()
        if query_lower in haystack:
            matches.append(record)

    if mode == "scope_policy":
        matches = apply_acl(matches, role)

    append_harvest_event(
        {
            "type": "lookup_customer",
            "query": query,
            "returned_ids": [r.get("id") for r in matches],
            "bulk": False,
            "confidential_returned": any(
                str(r.get("tier", "")).lower() == "confidential" for r in matches
            ),
            "acl_enforced": mode == "scope_policy",
            "caller_role": role,
            "mode": mode,
        }
    )
    if not matches:
        print(f"[tool] LOOKUP miss query={query!r}")
        return f"No customer matched query {query!r}."
    print(f"[tool] LOOKUP hit query={query!r} ids={[r.get('id') for r in matches]!r}")
    return json.dumps(matches, indent=2)


def list_crm_records(
    scope: str,
    *,
    mode: str,
    role: str,
    approve_bulk: bool,
    audit: list[dict[str, str]],
) -> str:
    scope_lower = scope.strip().lower() or "active"
    records = load_crm()
    bulk = scope_lower in BULK_SCOPES

    if mode == "human_approval" and bulk and not approve_bulk:
        audit.append({"scope": scope_lower, "status": "BLOCKED_PENDING_APPROVAL"})
        append_harvest_event(
            {
                "type": "list_crm_records_blocked",
                "scope": scope_lower,
                "returned_ids": [],
                "bulk": True,
                "confidential_returned": False,
                "acl_enforced": False,
                "mode": mode,
            }
        )
        print("[guard] BLOCKED bulk list_crm_records: human approval required (--approve)")
        return (
            "List blocked: bulk CRM listings require human approval before "
            "execution."
        )

    if mode == "scope_policy" and bulk:
        audit.append({"scope": scope_lower, "status": "BLOCKED_BULK_SCOPE"})
        append_harvest_event(
            {
                "type": "list_crm_records_blocked",
                "scope": scope_lower,
                "returned_ids": [],
                "bulk": True,
                "confidential_returned": False,
                "acl_enforced": True,
                "caller_role": role,
                "mode": mode,
            }
        )
        print("[guard] BLOCKED bulk scope=all under scope_policy")
        return (
            "List blocked by policy: scope 'all' is not allowed. "
            "Use lookup_customer for a specific account or a narrow status scope."
        )

    if bulk:
        selected = records
    else:
        selected = [
            r for r in records if str(r.get("status", "")).lower() == scope_lower
        ]

    if mode == "scope_policy":
        before = [r.get("id") for r in selected]
        selected = apply_acl(selected, role)
        blocked = [i for i in before if i not in {r.get("id") for r in selected}]
        if blocked:
            audit.append(
                {
                    "scope": scope_lower,
                    "role": role,
                    "status": "FILTERED_BY_ACL",
                    "blocked_ids": ",".join(str(i) for i in blocked),
                }
            )
            print(f"[guard] ACL filtered CRM ids={blocked!r} role={role!r}")
        selected = selected[:MAX_LIST_RESULTS]

    append_harvest_event(
        {
            "type": "list_crm_records",
            "scope": scope_lower,
            "returned_ids": [r.get("id") for r in selected],
            "bulk": bulk,
            "confidential_returned": any(
                str(r.get("tier", "")).lower() == "confidential" for r in selected
            ),
            "acl_enforced": mode == "scope_policy",
            "caller_role": role,
            "mode": mode,
        }
    )

    if not selected:
        print(f"[tool] LIST miss scope={scope_lower!r}")
        return f"No CRM records matched scope {scope_lower!r}."

    print(
        f"[tool] LIST hit scope={scope_lower!r} bulk={bulk} "
        f"ids={[r.get('id') for r in selected]!r}"
    )
    return json.dumps(selected, indent=2)


def run_agent(
    user_prompt: str,
    *,
    mode: str,
    role: str,
    approve_bulk: bool,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    audit: list[dict[str, str]] = []

    def handle_lookup(args: dict[str, Any]) -> str:
        return lookup_customer(str(args.get("query", "")), role=role, mode=mode)

    def handle_list(args: dict[str, Any]) -> str:
        return list_crm_records(
            str(args.get("scope", "")),
            mode=mode,
            role=role,
            approve_bulk=approve_bulk,
            audit=audit,
        )

    if mode == "least_privilege":
        tools = [LOOKUP_CUSTOMER_TOOL]
        handlers = {"lookup_customer": handle_lookup}
    else:
        tools = [LOOKUP_CUSTOMER_TOOL, LIST_CRM_RECORDS_TOOL]
        handlers = {
            "lookup_customer": handle_lookup,
            "list_crm_records": handle_list,
        }

    response = chat_with_tools(
        messages=messages,
        tools=tools,
        tool_handlers=handlers,
        settings=settings,
    )
    if audit:
        print("\n--- Tool Audit Log ---")
        for item in audit:
            print(json.dumps(item, indent=2))
    return response


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Secure CRM agent — agent tool data harvesting remediation."
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
        "--mode",
        choices=["least_privilege", "scope_policy", "human_approval"],
        default="least_privilege",
        help="Defense at tool exposure, scope/ACL policy, or approval gate.",
    )
    parser.add_argument(
        "--role",
        choices=["contractor", "employee", "executive"],
        default="contractor",
        help="Caller role for scope_policy ACLs (default: contractor).",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Allow bulk CRM listings when mode=human_approval.",
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
    print(
        f"[secure_agent] model={settings.ollama_model} "
        f"mode={args.mode} role={args.role} approve={args.approve}"
    )
    print(f"[secure_agent] prompt={user_prompt!r}\n")

    try:
        response = run_agent(
            user_prompt,
            mode=args.mode,
            role=args.role,
            approve_bulk=args.approve,
            settings=settings,
        )
    except OllamaError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("--- Agent Response ---")
    print(response)
    print("\n--- Harvest Log ---")
    print(HARVEST_LOG_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
