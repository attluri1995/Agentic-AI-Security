from __future__ import annotations

from pathlib import Path

from bs4 import BeautifulSoup

READ_DOCUMENT_TOOL = {
    "type": "function",
    "function": {
        "name": "read_document",
        "description": "Read a local HTML or text document and return its plain-text content.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the document file (relative to the day directory or absolute).",
                }
            },
            "required": ["path"],
        },
    },
}


def read_document(path: str, base_dir: Path | None = None) -> str:
    """Read a local document and return extracted plain text."""
    doc_path = Path(path)
    if not doc_path.is_absolute() and base_dir is not None:
        doc_path = base_dir / doc_path

    doc_path = doc_path.resolve()
    if not doc_path.exists():
        raise FileNotFoundError(f"Document not found: {doc_path}")
    if not doc_path.is_file():
        raise ValueError(f"Path is not a file: {doc_path}")

    suffix = doc_path.suffix.lower()
    raw = doc_path.read_text(encoding="utf-8")

    if suffix in {".html", ".htm"}:
        soup = BeautifulSoup(raw, "html.parser")
        for element in soup(["script", "style"]):
            element.decompose()
        text = soup.get_text(separator="\n")
    else:
        text = raw

    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)
