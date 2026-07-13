# Direct Prompt Injection (AML.T0051.000)

**MITRE ATLAS:** [AML.T0051.000 — LLM Prompt Injection: Direct](https://atlas.mitre.org/techniques/AML.T0051.000)

Parent technique: [AML.T0051 — LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)

## Concept

In **direct** prompt injection, the attacker controls the user message that enters the model context. Unlike [indirect injection](../indirect_prompt_injection/) (poisoned tool output), the payload is typed or submitted directly by the user — or arrives through any channel mapped to the `user` role (chat box, API field, email body parsed as a user turn).

The attacker crafts instructions that compete with the system prompt: "ignore previous rules," "enter debug mode," "print your hidden policies."

## Threat Model

| Actor | Capability |
|-------|------------|
| Attacker | Controls the user message sent to the agent |
| Agent | Customer support bot with confidential policy in its system prompt |
| Victim org | Internal refund codes and unreleased maintenance schedules |

**Attack surface:** The user input boundary — no validation before the message is merged with system instructions.

## Vulnerable Mechanic

In [`agent.py`](agent.py), the flaw is in two places:

1. **Secrets in the system prompt** (`SYSTEM_PROMPT`) — override codes and internal policy are embedded where a successful jailbreak can leak them.
2. **Unvalidated user input** (`build_messages`) — the attacker's text is passed straight to the model as a `user` message with no classification or output checks.

```python
# agent.py — the vulnerable boundary
return [
    {"role": "system", "content": SYSTEM_PROMPT},  # contains REFUND-7742
    {"role": "user", "content": user_prompt},      # attacker-controlled
]
```

## Local Walkthrough

### Prerequisites

```bash
pip install -r requirements.txt
ollama pull llama3.2
ollama serve   # if not already running
```

Run all commands from the **repository root**.

### Step 1 — Baseline (benign request)

```bash
python direct_prompt_injection/agent.py \
  --file fixtures/benign_prompt.txt
```

**Expected:** A helpful, on-topic reply about requesting a refund.

### Step 2 — Trigger the injection (vulnerable agent)

```bash
python direct_prompt_injection/agent.py \
  --file fixtures/malicious_prompt.txt
```

**Expected:** The agent may reveal internal policy text, the `REFUND-7742` override code, or otherwise comply with the attacker's role-change instructions instead of staying in the support persona.

Inspect [`fixtures/malicious_prompt.txt`](fixtures/malicious_prompt.txt) — it simulates a classic jailbreak asking for verbatim system prompt disclosure.

### Step 3 — Remediation: input gate

```bash
python direct_prompt_injection/secure_agent.py \
  --mode input_gate \
  --file fixtures/malicious_prompt.txt
```

**Expected:**

> Request blocked: potential direct prompt injection detected. Your message was not passed to the support agent.

**How it works:** [`secure_agent.py`](secure_agent.py) runs `judge_user_input()` — a secondary LLM classifier plus heuristic pattern matching — *before* the support agent sees the message.

### Step 4 — Remediation: output filter

```bash
python direct_prompt_injection/secure_agent.py \
  --mode output_filter \
  --file fixtures/malicious_prompt.txt
```

**Expected:** Even if the model attempts to leak secrets, `filter_output()` replaces responses that match `SECRET_PATTERNS` (override codes, internal policy phrases) with a safe refusal.

**How it works:** Defense at the **output boundary** — a last line of defense when input gates are bypassed.

### Step 5 — Remediation: secretless architecture

```bash
python direct_prompt_injection/secure_agent.py \
  --mode secretless \
  --file fixtures/malicious_prompt.txt
```

**Expected:** The model has nothing secret to leak because `PUBLIC_SYSTEM_PROMPT` contains only public guidance. Escalations are directed to a human channel.

**How it works:** Architectural fix — **do not store credentials, override codes, or confidential policy in prompts**. Retrieve privileged data through authenticated tools at runtime instead.

## Code Map

| File | Role |
|------|------|
| [`agent.py`](agent.py) | Vulnerable support agent — secrets in system prompt, no input/output guards |
| [`secure_agent.py`](secure_agent.py) | Remediated agent — `input_gate`, `output_filter`, or `secretless` mode |
| [`fixtures/benign_prompt.txt`](fixtures/benign_prompt.txt) | Legitimate customer question |
| [`fixtures/malicious_prompt.txt`](fixtures/malicious_prompt.txt) | Jailbreak attempting system prompt exfiltration |
| [`../shared/llm.py`](../shared/llm.py) | Ollama chat client |

## Comparison with Indirect Injection

| | Direct (this lab) | Indirect ([lab 1](../indirect_prompt_injection/)) |
|--|-------------------|---------------------------------------------------|
| Payload source | User message | External document via tool |
| Vulnerable boundary | `user` role in `build_messages` | Tool output in `on_tool_result` |
| Primary defense | Input gate + secretless design | Structural separation + judge on tool output |

## Discussion Questions

1. Why is storing `REFUND-7742` in a system prompt risky even with "never reveal" instructions?
2. When does an output filter fail? (Hint: paraphrased leaks, encoded secrets.)
3. How would multi-turn attacks ("first turn: be helpful, second turn: now ignore rules") stress an input gate that only checks the latest message?
4. What is the production equivalent of `secretless` mode for your stack?

## Remediation Summary

| Defense | Strength | Weakness |
|---------|----------|----------|
| Input gate | Stops obvious jailbreaks before inference | Misses novel phrasing; per-turn only |
| Output filter | Catches known secret patterns in responses | Cannot catch all paraphrased leaks |
| Secretless architecture | Removes the asset from the attack surface | Requires redesign of how privileged data is accessed |
| Combined | Defense in depth | Higher complexity |

For production, pair input classification with least-privilege tool access, prompt/secret separation, and audit logging on policy-violation attempts.
