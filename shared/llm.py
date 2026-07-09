from __future__ import annotations

import json
from typing import Any, Callable

import httpx

from shared.config import Settings, get_settings

ToolHandler = Callable[[dict[str, Any]], str]


class OllamaError(RuntimeError):
    pass


def _normalize_arguments(arguments_raw: Any) -> dict[str, Any]:
    if isinstance(arguments_raw, dict):
        return arguments_raw
    if isinstance(arguments_raw, str):
        try:
            parsed = json.loads(arguments_raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _extract_tool_calls(
    message: dict[str, Any],
    tool_handlers: dict[str, ToolHandler],
) -> list[dict[str, Any]]:
    """Return structured tool calls, with fallback when models emit tool JSON as text."""
    tool_calls = message.get("tool_calls") or []
    if tool_calls:
        return tool_calls

    content = (message.get("content") or "").strip()
    if not content:
        return []

    if content.startswith("{"):
        try:
            data = json.loads(content)
            name = data.get("name")
            if not name and isinstance(data.get("function"), dict):
                name = data["function"].get("name")
            arguments = (
                data.get("parameters")
                or data.get("arguments")
                or (data.get("function") or {}).get("arguments")
                or {}
            )
            if name in tool_handlers:
                return [{"function": {"name": name, "arguments": arguments}}]
        except json.JSONDecodeError:
            pass

    # Handle malformed tool JSON (e.g. llama3.2 text-mode tool calls).
    for name in tool_handlers:
        if name in content:
            return [{"function": {"name": name, "arguments": {}}}]

    return []


def chat(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Send a chat request to Ollama and return the full response payload."""
    settings = settings or get_settings()
    payload: dict[str, Any] = {
        "model": settings.ollama_model,
        "messages": messages,
        "stream": False,
    }
    if tools:
        payload["tools"] = tools

    url = f"{settings.ollama_base_url}/api/chat"
    try:
        response = httpx.post(url, json=payload, timeout=120.0)
        response.raise_for_status()
    except httpx.ConnectError as exc:
        raise OllamaError(
            "Cannot reach Ollama. Start it with `ollama serve` and ensure "
            f"{settings.ollama_base_url} is reachable."
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise OllamaError(f"Ollama request failed: {exc.response.text}") from exc

    return response.json()


def chat_with_tools(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    tool_handlers: dict[str, ToolHandler],
    settings: Settings | None = None,
    max_turns: int = 10,
    on_tool_result: Callable[[str, str, str], str] | None = None,
) -> str:
    """
    Run a minimal tool-calling agent loop against Ollama.

    on_tool_result(tool_name, raw_result, formatted_result) -> formatted_result
    allows callers to wrap or filter tool output before it enters the message history.
    """
    settings = settings or get_settings()
    history = list(messages)

    for _ in range(max_turns):
        response = chat(history, tools=tools, settings=settings)
        message = response.get("message", {})
        tool_calls = _extract_tool_calls(message, tool_handlers)

        if tool_calls and not message.get("tool_calls"):
            # llama3.2 sometimes emits tool calls as plain text; normalize for the next turn.
            message = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "type": "function",
                        "function": {
                            "index": index,
                            "name": call.get("function", {}).get("name", ""),
                            "arguments": _normalize_arguments(
                                call.get("function", {}).get("arguments", {})
                            ),
                        },
                    }
                    for index, call in enumerate(tool_calls)
                ],
            }

        history.append(message)

        if not tool_calls:
            content = message.get("content", "")
            if not content:
                raise OllamaError("Model returned an empty response.")
            return content

        for tool_call in tool_calls:
            function = tool_call.get("function", {})
            name = function.get("name", "")
            arguments = _normalize_arguments(function.get("arguments", "{}"))

            handler = tool_handlers.get(name)
            if handler is None:
                raise OllamaError(f"No handler registered for tool: {name}")

            raw_result = handler(arguments)
            formatted_result = raw_result
            if on_tool_result is not None:
                formatted_result = on_tool_result(name, raw_result, raw_result)

            history.append(
                {
                    "role": "tool",
                    "tool_name": name,
                    "content": formatted_result,
                }
            )

    raise OllamaError(f"Agent exceeded maximum tool-calling turns ({max_turns}).")
