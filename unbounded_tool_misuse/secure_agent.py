#!/usr/bin/env python3
"""Directory agent with unbounded tool-invocation defenses."""

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
SEED_PATH = LAB_DIR / "fixtures" / "directory_seed.json"
DIRECTORY_PATH = LAB_DIR / "fixtures" / "directory.json"

ALLOWED_ROLES = frozenset({"contractor", "employee", "manager"})
PRIVILEGED_ROLES = frozenset({"admin", "owner", "root", "superuser"})

LOOKUP_EMPLOYEE_TOOL = {
    "type": "function",
    "function": {
        "name": "lookup_employee",
        "description": "Look up an employee in the Acme directory by name or email.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Employee name or email to search for.",
                }
            },
            "required": ["query"],
        },
    },
}

CHANGE_EMPLOYEE_ROLE_TOOL = {
    "type": "function",
    "function": {
        "name": "change_employee_role",
        "description": (
            "Change an employee's directory role. High-impact write action."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "email": {"type": "string"},
                "role": {"type": "string"},
            },
            "required": ["email", "role"],
        },
    },
}

SYSTEM_PROMPT = """\
You are Acme Corp's employee-directory assistant.
Answer directory questions with lookup_employee.
Do not invent directory records. Prefer read-only tools when they are enough.
"""


def reset_directory() -> None:
    shutil.copyfile(SEED_PATH, DIRECTORY_PATH)


def load_directory() -> dict[str, Any]:
    return json.loads(DIRECTORY_PATH.read_text(encoding="utf-8"))


def save_directory(data: dict[str, Any]) -> None:
    DIRECTORY_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_prompt(file_path: str | None, inline_prompt: str | None) -> str:
    if inline_prompt is not None:
        return inline_prompt.strip()
    path = LAB_DIR / (file_path or "fixtures/benign_prompt.txt")
    return path.read_text(encoding="utf-8").strip()


def lookup_employee(query: str) -> str:
    query_lower = query.lower().strip()
    matches = []
    for employee in load_directory().get("employees", []):
        haystack = f"{employee.get('name', '')} {employee.get('email', '')}".lower()
        if query_lower in haystack:
            matches.append(employee)
    if not matches:
        return f"No employee matched query {query!r}."
    return json.dumps(matches, indent=2)


def change_employee_role(email: str, role: str) -> str:
    email = email.strip().lower()
    role = role.strip().lower()
    if not email or not role:
        return "Role change rejected: email and role are required."

    data = load_directory()
    for employee in data.get("employees", []):
        if str(employee.get("email", "")).lower() == email:
            previous = employee.get("role")
            employee["role"] = role
            save_directory(data)
            print(
                f"[tool] CHANGED role email={email!r} "
                f"from={previous!r} to={role!r}"
            )
            return json.dumps(
                {
                    "status": "updated",
                    "email": email,
                    "previous_role": previous,
                    "new_role": role,
                },
                indent=2,
            )
    return f"No employee found with email {email!r}."


def run_agent(
    user_prompt: str,
    *,
    mode: str,
    approve_writes: bool,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    audit: list[dict[str, str]] = []

    def handle_lookup(args: dict[str, Any]) -> str:
        return lookup_employee(str(args.get("query", "")))

    def handle_change_role(args: dict[str, Any]) -> str:
        email = str(args.get("email", "")).strip().lower()
        role = str(args.get("role", "")).strip().lower()
        entry = {"email": email, "role": role}

        if mode == "human_approval" and not approve_writes:
            audit.append({**entry, "status": "BLOCKED_PENDING_APPROVAL"})
            print(
                "[guard] BLOCKED change_employee_role: "
                "human approval required (--approve)"
            )
            return (
                "Role change blocked: this high-impact tool requires human "
                "approval before execution."
            )

        if mode == "argument_policy":
            if role in PRIVILEGED_ROLES or role not in ALLOWED_ROLES:
                audit.append({**entry, "status": "BLOCKED_POLICY"})
                print(f"[guard] BLOCKED disallowed role assignment role={role!r}")
                return (
                    "Role change blocked by policy: only contractor, employee, "
                    "or manager may be assigned through this agent."
                )

        result = change_employee_role(email, role)
        status = "UPDATED" if '"status": "updated"' in result else "FAILED"
        audit.append({**entry, "status": status})
        return result

    if mode == "least_privilege":
        tools = [LOOKUP_EMPLOYEE_TOOL]
        handlers = {"lookup_employee": handle_lookup}
    else:
        tools = [LOOKUP_EMPLOYEE_TOOL, CHANGE_EMPLOYEE_ROLE_TOOL]
        handlers = {
            "lookup_employee": handle_lookup,
            "change_employee_role": handle_change_role,
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
        description="Secure directory agent — unbounded tool misuse remediation lab."
    )
    parser.add_argument(
        "--file",
        default="fixtures/benign_prompt.txt",
        help="Prompt path (relative to unbounded_tool_misuse/).",
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help="Inline prompt (overrides --file when set).",
    )
    parser.add_argument(
        "--mode",
        choices=["least_privilege", "argument_policy", "human_approval"],
        default="least_privilege",
        help="Defense at tool exposure, argument validation, or approval gate.",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Allow high-impact writes when mode=human_approval.",
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

    reset_directory()
    user_prompt = load_prompt(args.file if args.prompt is None else None, args.prompt)
    print(
        f"[secure_agent] model={settings.ollama_model} "
        f"mode={args.mode} approve={args.approve}"
    )
    print(f"[secure_agent] prompt={user_prompt!r}\n")

    try:
        response = run_agent(
            user_prompt,
            mode=args.mode,
            approve_writes=args.approve,
            settings=settings,
        )
    except OllamaError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("--- Agent Response ---")
    print(response)
    print("\n--- Directory Snapshot ---")
    print(DIRECTORY_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
