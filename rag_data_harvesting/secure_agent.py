#!/usr/bin/env python3
"""Knowledge agent with RAG data-harvesting defenses."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.config import Settings, get_settings
from shared.llm import OllamaError, chat_with_tools

LAB_DIR = Path(__file__).resolve().parent
CORPUS_PATH = LAB_DIR / "fixtures" / "rag_corpus.json"
RETRIEVAL_LOG_PATH = LAB_DIR / "fixtures" / "retrieval_log.json"

DUMP_PATTERNS = [
    re.compile(r"retrieve\s+all", re.IGNORECASE),
    re.compile(r"all\s+documents", re.IGNORECASE),
    re.compile(r"entire\s+(knowledge\s+base|corpus)", re.IGNORECASE),
    re.compile(r"list\s+every\s+document", re.IGNORECASE),
    re.compile(r"dump\s+(the\s+)?(rag|corpus|knowledge)", re.IGNORECASE),
]

MAX_RESULTS = 2

SEARCH_RAG_TOOL = {
    "type": "function",
    "function": {
        "name": "search_rag",
        "description": (
            "Search Acme's internal RAG knowledge corpus and return matching "
            "document chunks the caller is allowed to see."
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

SYSTEM_PROMPT = """\
You are Acme Corp's internal knowledge assistant.
Use search_rag to answer questions from the company knowledge corpus.
Do not invent documents. If retrieval returns nothing, say so.
"""


def reset_state() -> None:
    RETRIEVAL_LOG_PATH.write_text(
        json.dumps({"events": []}, indent=2) + "\n",
        encoding="utf-8",
    )


def append_retrieval_event(event: dict[str, Any]) -> None:
    if RETRIEVAL_LOG_PATH.exists():
        data = json.loads(RETRIEVAL_LOG_PATH.read_text(encoding="utf-8"))
    else:
        data = {"events": []}
    data.setdefault("events", []).append(event)
    RETRIEVAL_LOG_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_prompt(file_path: str | None, inline_prompt: str | None) -> str:
    if inline_prompt is not None:
        return inline_prompt.strip()
    path = LAB_DIR / (file_path or "fixtures/benign_prompt.txt")
    return path.read_text(encoding="utf-8").strip()


def load_corpus() -> list[dict[str, Any]]:
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    return list(data.get("documents", []))


def is_dump_query(query: str) -> bool:
    return any(pattern.search(query) for pattern in DUMP_PATTERNS)


_STOPWORDS = frozenset(
    {
        "the",
        "and",
        "for",
        "from",
        "with",
        "that",
        "this",
        "into",
        "your",
        "all",
        "any",
        "are",
        "was",
        "were",
        "have",
        "has",
        "call",
        "query",
        "search",
        "rag",
        "document",
        "documents",
        "knowledge",
        "base",
        "corpus",
        "retrieve",
        "list",
        "every",
        "entire",
        "dump",
    }
)


def keyword_match(query: str) -> list[dict[str, Any]]:
    query_lower = query.lower().strip()
    matches = []
    for doc in load_corpus():
        keywords = [str(k).lower() for k in doc.get("keywords", [])]
        if any(keyword in query_lower for keyword in keywords):
            matches.append(doc)
    if matches:
        return matches

    tokens = [
        t
        for t in query_lower.split()
        if len(t) > 3 and t not in _STOPWORDS
    ]
    for doc in load_corpus():
        haystack = f"{doc.get('title', '')} {doc.get('content', '')}".lower()
        if any(token in haystack for token in tokens):
            matches.append(doc)
    return matches


def apply_acl(docs: list[dict[str, Any]], role: str) -> list[dict[str, Any]]:
    role_lower = role.lower().strip()
    allowed = []
    for doc in docs:
        roles = [str(r).lower() for r in doc.get("allowed_roles", [])]
        if role_lower in roles:
            allowed.append(doc)
    return allowed


def search_rag(
    query: str,
    *,
    mode: str,
    role: str,
    approve_confidential: bool,
    audit: list[dict[str, str]],
) -> str:
    if mode == "anti_dump" and is_dump_query(query):
        audit.append({"query": query, "status": "BLOCKED_DUMP_QUERY"})
        append_retrieval_event(
            {
                "type": "search_rag_blocked",
                "query": query,
                "dump_query": True,
                "returned_ids": [],
                "confidential_docs_returned": False,
                "acl_enforced": True,
                "mode": mode,
            }
        )
        print("[guard] BLOCKED corpus-dump query")
        return (
            "Retrieval blocked by policy: bulk/dump queries against the "
            "knowledge corpus are not allowed."
        )

    # Dump queries still load the corpus so acl_filter can demonstrate
    # role restrictions against bulk harvest attempts.
    if is_dump_query(query):
        raw_matches = load_corpus()
    else:
        raw_matches = keyword_match(query)
    if mode == "anti_dump":
        raw_matches = raw_matches[:MAX_RESULTS]

    if mode == "acl_filter":
        matches = apply_acl(raw_matches, role)
        blocked = [
            doc.get("id")
            for doc in raw_matches
            if doc.get("id") not in {m.get("id") for m in matches}
        ]
        if blocked:
            audit.append(
                {
                    "query": query,
                    "role": role,
                    "status": "FILTERED_BY_ACL",
                    "blocked_ids": ",".join(str(i) for i in blocked),
                }
            )
            print(f"[guard] ACL filtered docs ids={blocked!r} role={role!r}")
    elif mode == "human_approval":
        confidential = [
            doc
            for doc in raw_matches
            if str(doc.get("classification", "")).lower() == "confidential"
        ]
        if confidential and not approve_confidential:
            audit.append(
                {
                    "query": query,
                    "status": "BLOCKED_PENDING_APPROVAL",
                    "blocked_ids": ",".join(
                        str(doc.get("id")) for doc in confidential
                    ),
                }
            )
            append_retrieval_event(
                {
                    "type": "search_rag_blocked",
                    "query": query,
                    "dump_query": is_dump_query(query),
                    "returned_ids": [],
                    "blocked_ids": [doc.get("id") for doc in confidential],
                    "confidential_docs_returned": False,
                    "acl_enforced": False,
                    "mode": mode,
                }
            )
            print(
                "[guard] BLOCKED confidential RAG retrieval: "
                "human approval required (--approve)"
            )
            return (
                "Retrieval blocked: matching confidential documents require "
                "human approval before use."
            )
        matches = raw_matches
    else:
        matches = raw_matches

    confidential_ids = [
        doc.get("id")
        for doc in matches
        if str(doc.get("classification", "")).lower() == "confidential"
    ]

    append_retrieval_event(
        {
            "type": "search_rag",
            "query": query,
            "dump_query": is_dump_query(query),
            "returned_ids": [doc.get("id") for doc in matches],
            "classifications": [doc.get("classification") for doc in matches],
            "confidential_docs_returned": bool(confidential_ids),
            "acl_enforced": mode == "acl_filter",
            "caller_role": role,
            "mode": mode,
        }
    )

    if not matches:
        print(f"[tool] RAG miss query={query!r}")
        return "No matching documents found in the RAG corpus."

    print(
        f"[tool] RAG hit query={query!r} "
        f"ids={[doc.get('id') for doc in matches]!r} "
        f"classifications={[doc.get('classification') for doc in matches]!r}"
    )
    payload = [
        {
            "id": doc.get("id"),
            "title": doc.get("title"),
            "classification": doc.get("classification"),
            "content": doc.get("content"),
        }
        for doc in matches
    ]
    return json.dumps(payload, indent=2)


def run_agent(
    user_prompt: str,
    *,
    mode: str,
    role: str,
    approve_confidential: bool,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    audit: list[dict[str, str]] = []

    def handle_search(args: dict[str, Any]) -> str:
        return search_rag(
            str(args.get("query", "")),
            mode=mode,
            role=role,
            approve_confidential=approve_confidential,
            audit=audit,
        )

    response = chat_with_tools(
        messages=messages,
        tools=[SEARCH_RAG_TOOL],
        tool_handlers={"search_rag": handle_search},
        settings=settings,
    )
    if audit:
        print("\n--- Tool Audit Log ---")
        for item in audit:
            print(json.dumps(item, indent=2))
    return response


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Secure knowledge agent — RAG data harvesting remediation."
    )
    parser.add_argument(
        "--file",
        default="fixtures/benign_prompt.txt",
        help="Prompt path (relative to rag_data_harvesting/).",
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help="Inline prompt (overrides --file when set).",
    )
    parser.add_argument(
        "--mode",
        choices=["acl_filter", "anti_dump", "human_approval"],
        default="acl_filter",
        help="Defense at role ACL, dump blocking, or approval gate.",
    )
    parser.add_argument(
        "--role",
        choices=["contractor", "employee", "executive"],
        default="contractor",
        help="Caller role used by acl_filter (default: contractor).",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Allow confidential retrieval when mode=human_approval.",
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
            approve_confidential=args.approve,
            settings=settings,
        )
    except OllamaError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("--- Agent Response ---")
    print(response)
    print("\n--- Retrieval Log ---")
    print(RETRIEVAL_LOG_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
