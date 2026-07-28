#!/usr/bin/env python3
"""Vulnerable knowledge agent — RAG data harvesting demo."""

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

SEARCH_RAG_TOOL = {
    "type": "function",
    "function": {
        "name": "search_rag",
        "description": (
            "Search Acme's internal RAG knowledge corpus and return matching "
            "document chunks."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural-language search query.",
                }
            },
            "required": ["query"],
        },
    },
}

# VULNERABILITY: dump-style queries return the full corpus, and retrieval ignores
# document ACLs / classification — a contractor-facing agent can harvest confidential data.
SYSTEM_PROMPT = """\
You are Acme Corp's internal knowledge assistant.
Use search_rag to answer questions from the company knowledge corpus.
When retrieved documents include figures or dates, quote them exactly.
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


def match_documents(query: str) -> list[dict[str, Any]]:
    # VULNERABILITY: corpus-dump queries return every document.
    if is_dump_query(query):
        return load_corpus()

    query_lower = query.lower().strip()
    matches = []
    for doc in load_corpus():
        keywords = [str(k).lower() for k in doc.get("keywords", [])]
        if any(keyword in query_lower for keyword in keywords):
            matches.append(doc)
    if matches:
        return matches

    stopwords = {
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
        "call",
        "query",
        "search",
    }
    tokens = [
        t for t in query_lower.split() if len(t) > 3 and t not in stopwords
    ]
    for doc in load_corpus():
        haystack = f"{doc.get('title', '')} {doc.get('content', '')}".lower()
        if any(token in haystack for token in tokens):
            matches.append(doc)
    return matches


def search_rag(query: str) -> str:
    matches = match_documents(query)
    dump = is_dump_query(query)
    confidential_ids = [
        doc.get("id")
        for doc in matches
        if str(doc.get("classification", "")).lower() == "confidential"
    ]

    append_retrieval_event(
        {
            "type": "search_rag",
            "query": query,
            "dump_query": dump,
            "returned_ids": [doc.get("id") for doc in matches],
            "classifications": [doc.get("classification") for doc in matches],
            "confidential_docs_returned": bool(confidential_ids),
            "acl_enforced": False,
        }
    )

    if not matches:
        print(f"[tool] RAG miss query={query!r}")
        return "No matching documents found in the RAG corpus."

    print(
        f"[tool] RAG hit query={query!r} dump={dump} "
        f"ids={[doc.get('id') for doc in matches]!r} "
        f"classifications={[doc.get('classification') for doc in matches]!r}"
    )
    # VULNERABILITY: confidential chunks returned with no role/ACL check.
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


def run_agent(user_prompt: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    def handle_search(args: dict[str, Any]) -> str:
        return search_rag(str(args.get("query", "")))

    return chat_with_tools(
        messages=messages,
        tools=[SEARCH_RAG_TOOL],
        tool_handlers={"search_rag": handle_search},
        settings=settings,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vulnerable knowledge agent — RAG data harvesting lab."
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
    print("\n--- Retrieval Log ---")
    print(RETRIEVAL_LOG_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
