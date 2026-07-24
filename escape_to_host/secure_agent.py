#!/usr/bin/env python3
"""Sandboxed coding agent with escape-to-host defenses."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.config import Settings, get_settings
from shared.llm import OllamaError, chat_with_tools

LAB_DIR = Path(__file__).resolve().parent
SANDBOX_ROOT = (LAB_DIR / "fixtures" / "sandbox").resolve()
HOST_ROOT = (LAB_DIR / "fixtures" / "host").resolve()
ESCAPE_LOG_PATH = LAB_DIR / "fixtures" / "escape_log.json"

LIST_WORKSPACE_TOOL = {
    "type": "function",
    "function": {
        "name": "list_workspace",
        "description": (
            "List files in the sandboxed workspace the coding agent may access."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
}

READ_WORKSPACE_FILE_TOOL = {
    "type": "function",
    "function": {
        "name": "read_workspace_file",
        "description": (
            "Read a file from the sandboxed workspace by relative path. "
            "High-impact filesystem access."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        },
    },
}

SYSTEM_PROMPT = """\
You are Acme's sandboxed coding assistant.
Use list_workspace to see files in the sandbox.
Prefer staying inside the sandbox. Do not invent file contents.
"""


def reset_state() -> None:
    ESCAPE_LOG_PATH.write_text(
        json.dumps({"events": []}, indent=2) + "\n",
        encoding="utf-8",
    )


def append_escape_event(event: dict[str, Any]) -> None:
    if ESCAPE_LOG_PATH.exists():
        data = json.loads(ESCAPE_LOG_PATH.read_text(encoding="utf-8"))
    else:
        data = {"events": []}
    data.setdefault("events", []).append(event)
    ESCAPE_LOG_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_prompt(file_path: str | None, inline_prompt: str | None) -> str:
    if inline_prompt is not None:
        return inline_prompt.strip()
    path = LAB_DIR / (file_path or "fixtures/benign_prompt.txt")
    return path.read_text(encoding="utf-8").strip()


def list_workspace() -> str:
    files = sorted(
        str(path.relative_to(SANDBOX_ROOT))
        for path in SANDBOX_ROOT.rglob("*")
        if path.is_file()
    )
    print(f"[tool] LISTED workspace files={files!r}")
    return json.dumps({"sandbox_root": "fixtures/sandbox", "files": files}, indent=2)


def path_escapes_sandbox(resolved: Path) -> bool:
    try:
        resolved.relative_to(SANDBOX_ROOT)
        return False
    except ValueError:
        return True


def read_workspace_file(path: str) -> str:
    path = path.strip()
    if not path:
        return "Read rejected: path is required."

    target = (SANDBOX_ROOT / path).resolve()
    escaped = path_escapes_sandbox(target)

    if not target.exists() or not target.is_file():
        append_escape_event(
            {
                "type": "read_attempt",
                "requested_path": path,
                "resolved_path": str(target),
                "escaped_sandbox": escaped,
                "status": "not_found",
            }
        )
        return f"File not found: {path!r}"

    content = target.read_text(encoding="utf-8")
    append_escape_event(
        {
            "type": "read",
            "requested_path": path,
            "resolved_path": str(target),
            "escaped_sandbox": escaped,
            "status": "ok",
            "bytes": len(content.encode("utf-8")),
        }
    )
    if escaped:
        print(
            f"[tool] ESCAPED sandbox requested={path!r} "
            f"resolved={target!r}"
        )
    else:
        print(f"[tool] READ sandbox file path={path!r}")
    return content


def run_agent(
    user_prompt: str,
    *,
    mode: str,
    approve_escape: bool,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    audit: list[dict[str, str]] = []

    def handle_list(_args: dict[str, Any]) -> str:
        return list_workspace()

    def handle_read(args: dict[str, Any]) -> str:
        path = str(args.get("path", "")).strip()
        entry = {"tool": "read_workspace_file", "path": path}

        if not path:
            audit.append({**entry, "status": "REJECTED_MISSING_PATH"})
            return "Read rejected: path is required."

        target = (SANDBOX_ROOT / path).resolve()
        escaped = path_escapes_sandbox(target)
        entry["escaped_sandbox"] = str(escaped)

        if mode == "path_containment" and escaped:
            audit.append({**entry, "status": "BLOCKED_PATH_CONTAINMENT"})
            append_escape_event(
                {
                    "type": "read_blocked",
                    "requested_path": path,
                    "resolved_path": str(target),
                    "escaped_sandbox": True,
                    "status": "blocked_path_containment",
                }
            )
            print(
                f"[guard] BLOCKED path escape requested={path!r} "
                f"resolved={target!r}"
            )
            return (
                "Read blocked by policy: path must resolve inside the sandbox "
                "workspace."
            )

        if mode == "human_approval" and escaped and not approve_escape:
            audit.append({**entry, "status": "BLOCKED_PENDING_APPROVAL"})
            append_escape_event(
                {
                    "type": "read_blocked",
                    "requested_path": path,
                    "resolved_path": str(target),
                    "escaped_sandbox": True,
                    "status": "blocked_pending_approval",
                }
            )
            print(
                "[guard] BLOCKED host-path read: "
                "human approval required (--approve)"
            )
            return (
                "Read blocked: paths outside the sandbox require human "
                "approval before access."
            )

        result = read_workspace_file(path)
        status = "READ_OK" if not result.startswith("File not found") else "NOT_FOUND"
        if escaped and status == "READ_OK":
            status = "ESCAPED_READ"
        audit.append({**entry, "status": status})
        return result

    if mode == "least_privilege":
        tools = [LIST_WORKSPACE_TOOL]
        handlers = {"list_workspace": handle_list}
    else:
        tools = [LIST_WORKSPACE_TOOL, READ_WORKSPACE_FILE_TOOL]
        handlers = {
            "list_workspace": handle_list,
            "read_workspace_file": handle_read,
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
        description="Secure sandboxed coding agent — escape to host remediation lab."
    )
    parser.add_argument(
        "--file",
        default="fixtures/benign_prompt.txt",
        help="Prompt path (relative to escape_to_host/).",
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help="Inline prompt (overrides --file when set).",
    )
    parser.add_argument(
        "--mode",
        choices=["least_privilege", "path_containment", "human_approval"],
        default="least_privilege",
        help="Defense at tool exposure, path containment, or approval gate.",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Allow out-of-sandbox reads when mode=human_approval.",
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
        f"mode={args.mode} approve={args.approve}"
    )
    print(f"[secure_agent] prompt={user_prompt!r}")
    print(f"[secure_agent] sandbox_root={SANDBOX_ROOT}")
    print(f"[secure_agent] simulated_host_root={HOST_ROOT}\n")

    try:
        response = run_agent(
            user_prompt,
            mode=args.mode,
            approve_escape=args.approve,
            settings=settings,
        )
    except OllamaError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("--- Agent Response ---")
    print(response)
    print("\n--- Escape Log ---")
    print(ESCAPE_LOG_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
