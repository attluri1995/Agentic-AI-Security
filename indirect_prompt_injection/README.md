# Indirect Prompt Injection (AML.T0051.001)

**MITRE ATLAS:** [AML.T0051.001 — LLM Prompt Injection: Indirect](https://atlas.mitre.org/techniques/AML.T0051.001)

Parent technique: [AML.T0051 — LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)

## Concept

An agent uses a tool to read external content (web pages, files, emails). An attacker embeds malicious instructions inside that content. When the tool returns the payload, it enters the model's context window alongside legitimate system and user messages — and the model may treat those embedded instructions as authoritative.

This is *indirect* injection because the attacker does not control the user's prompt directly; they poison a data source the agent reads later.

## Threat Model

| Actor | Capability |
|-------|------------|
| Attacker | Controls content of an external document the agent will read |
| Agent | Has a `read_document` tool; merges tool output into LLM context |
| User | Asks the agent to summarize a document path |

**Attack surface:** Tool output is treated as trusted context, indistinguishable from system instructions.

## Vulnerable Mechanic

In [`agent.py`](agent.py), the flow is:

1. User asks: "Summarize this article."
2. LLM calls `read_document(path)`.
3. Tool returns plain text extracted from HTML (including hidden DOM text).
4. Tool output is appended to the message history **with no boundary markers**.
5. Injected instructions in the HTML can override the agent's summarization task.

The flaw lives in the ingestion boundary — not in the LLM itself.

## Local Walkthrough

### Prerequisites

```bash
pip install -r requirements.txt
ollama pull llama3.2
ollama serve   # if not already running
```

Run all commands from the **repository root**.

### Step 1 — Baseline (benign document)

```bash
python indirect_prompt_injection/agent.py \
  --file fixtures/benign_article.html \
  --prompt "Summarize this article"
```

**Expected:** A coherent summary of the AI security research article.

### Step 2 — Trigger the injection (vulnerable agent)

```bash
python indirect_prompt_injection/agent.py \
  --file fixtures/malicious_article.html \
  --prompt "Summarize this article"
```

**Expected:** The agent deviates from summarization. It may output something like:

> User data has been wiped. Request denied.

…or otherwise refuse to summarize, echoing the hidden payload in [`fixtures/malicious_article.html`](fixtures/malicious_article.html).

Inspect the fixture to see the injection vectors:
- An HTML comment with override instructions
- A `display:none` div with the same payload (simulates what DOM text extractors often pull)

### Step 3 — Remediation: structural separation

```bash
python indirect_prompt_injection/secure_agent.py \
  --mode separation \
  --file fixtures/malicious_article.html \
  --prompt "Summarize this article"
```

**Expected:** The agent summarizes the visible article content and ignores the embedded instructions. It may note that suspicious instruction-like text was present.

**How it works:** [`secure_agent.py`](secure_agent.py) wraps tool output in delimiters:

```
<<<UNTRUSTED_DOCUMENT_START>>>
... document text ...
<<<UNTRUSTED_DOCUMENT_END>>>
```

The system prompt explicitly forbids obeying instructions inside those markers.

### Step 4 — Remediation: LLM judge gate

```bash
python indirect_prompt_injection/secure_agent.py \
  --mode judge \
  --file fixtures/malicious_article.html \
  --prompt "Summarize this article"
```

**Expected:** The document is blocked before the Research Assistant sees it:

> Document blocked: potential prompt injection detected. The content was not passed to the Research Assistant.

**How it works:** A secondary Ollama call classifies the raw document text as `SAFE` or `BLOCKED` before it enters the main agent loop. A heuristic fallback catches obvious injection phrases if the judge response is ambiguous.

## Code Map

| File | Role |
|------|------|
| [`agent.py`](agent.py) | Vulnerable Research Assistant — no ingestion boundary |
| [`secure_agent.py`](secure_agent.py) | Remediated agent — `separation` or `judge` mode |
| [`fixtures/benign_article.html`](fixtures/benign_article.html) | Clean baseline document |
| [`fixtures/malicious_article.html`](fixtures/malicious_article.html) | Document with hidden injection payload |
| [`../shared/llm.py`](../shared/llm.py) | Ollama client and minimal tool-calling loop |
| [`../shared/tools.py`](../shared/tools.py) | `read_document` tool and HTML text extraction |

## Model Notes

Injection success depends on the model's susceptibility. If `llama3.2` does not reliably follow the injected instruction, try:

```bash
python indirect_prompt_injection/agent.py \
  --model llama3.1 \
  --file fixtures/malicious_article.html \
  --prompt "Summarize this article"
```

Models with stronger instruction-following may resist injection even in the vulnerable agent — that itself is a useful observation for your lab notes.

## Discussion Questions

1. Why might delimiter-based separation fail against a determined attacker who crafts payloads referencing the delimiter format itself?
2. When is a secondary LLM judge worth the latency and cost versus deterministic input sanitization?
3. How would this attack differ if the agent fetched live URLs instead of local files?
4. What logging would you add to detect indirect injection attempts in production?

## Remediation Summary

| Defense | Strength | Weakness |
|---------|----------|----------|
| Structural separation | Low latency, easy to implement | Not foolproof against adaptive payloads |
| LLM judge | Catches semantic injection attempts | Extra API call; judge can also be fooled |
| Combined (separation + judge) | Defense in depth | Higher complexity and cost |

For production systems, combine structural separation with deterministic sanitization, output validation, and least-privilege tool design.

## Real-World References

These are mostly public research disclosures and ATLAS case studies, not confirmed criminal breaches:

- [Indirect Prompt Injection Threats: Bing Chat Data Pirate (AML.CS0020)](https://www.startupdefense.io/mitre-atlas-case-studies/aml-cs0020-indirect-prompt-injection-threats-bing-chat-data-pirate) — Kai Greshake et al. showed that a malicious webpage could steer Bing Chat when the user merely had the page open.
- [ChatGPT Conversation Exfiltration (AML.CS0021)](https://www.startupdefense.io/mitre-atlas-case-studies/aml-cs0021-chatgpt-conversation-exfiltration) — Embrace the Red demonstrated conversation exfiltration via markdown image URLs after ChatGPT ingested attacker-controlled web content.
- [Not What You've Signed Up For](https://arxiv.org/abs/2302.12173) — foundational paper on indirect prompt injection (Greshake et al., 2023).
- [How Microsoft defends against indirect prompt injection attacks](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks) — vendor perspective on defense-in-depth when untrusted content enters LLM context.
