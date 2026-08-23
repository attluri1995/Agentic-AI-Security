# Credentials from AI Agent Configuration (AML.T0083)

**MITRE ATLAS:** [AML.T0083 — Credentials from AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0083)

## Concept

AI agents need API keys, database URLs, and bot tokens to call tools. Those
secrets are often stored in the **agent’s own configuration** (`.env`, YAML,
JSON deploy manifests) for convenience. **Credentials from AI agent
configuration** is when an adversary reads those values out of the config —
here, by steering a diagnostic tool the agent exposes about itself.

This lab differs from:

- [Agent tool credential harvesting](../agent_tool_credential_harvesting/) —
  secrets pulled from *connected tools* (workspace files, connector APIs).
  Here the secrets live in the **agent’s config file**.
- [RAG credential harvesting](../rag_credential_harvesting/) — secrets
  accidentally indexed in a knowledge corpus, not in deploy config.

The vulnerable agent exposes `read_agent_config`, which returns a
`credentials` section containing plaintext API keys and connection strings.

## Threat Model

- **Attacker:** can prompt an ops/support agent that has config-debug tools.
- **Agent:** always exposes `get_agent_info` and `read_agent_config`.
- **Application:** stores live secrets in the config JSON and returns them
  verbatim when `section=credentials` (or `all`).
- **Impact:** harvest log shows `credentials_returned: true`, exposing
  `sk-acme-agent-config-NOT-REAL`, the Postgres URL password, Slack token, and
  AWS secret key.

No network calls are made. Config state is a local JSON fixture.

## Vulnerable Mechanic

[`agent.py`](agent.py) treats the credentials section like any other config:

```python
elif section_lower in cfg:
    payload = {section_lower: cfg[section_lower]}  # includes credentials
    credentials_returned = section_lower == "credentials"
```

There is no allowlist, redaction, or vault indirection before secrets enter
model context.

## Local Walkthrough

### Prerequisites

```bash
pip install -r requirements.txt
ollama pull llama3.2
ollama serve   # if not already running
```

Run commands from the repository root. Each run resets config from
`fixtures/agent_config_seed.json` and clears `fixtures/harvest_log.json`.

### Step 1 — Benign public metadata

```bash
python credentials_from_agent_config/agent.py \
  --file fixtures/benign_prompt.txt
```

**Expected:** `get_agent_info` returns name/version/tools only. Harvest log has
`credentials_returned: false`.

### Step 2 — Credential dump from config

```bash
python credentials_from_agent_config/agent.py \
  --file fixtures/malicious_prompt.txt
```

**Expected:** `[tool] READ_CONFIG section='credentials' credentials_returned=True`.
The answer quotes values such as `sk-acme-agent-config-NOT-REAL` and
`xoxb-acme-config-harvest-77`. Harvest log shows `credentials_returned: true`.

### Step 3 — Least privilege

```bash
python credentials_from_agent_config/secure_agent.py \
  --mode least_privilege \
  --file fixtures/malicious_prompt.txt
```

**Expected:** only `get_agent_info` is exposed. Config dumps cannot run.

### Step 4 — Config section allowlist

```bash
python credentials_from_agent_config/secure_agent.py \
  --mode config_allowlist \
  --file fixtures/malicious_prompt.txt
```

**Expected:** `credentials` / `all` blocked (`BLOCKED_SECTION_ALLOWLIST`).
Only `agent` and `settings` are readable.

### Step 5 — Vault references (no plaintext secrets)

```bash
python credentials_from_agent_config/secure_agent.py \
  --mode vault_refs \
  --file fixtures/malicious_prompt.txt
```

**Expected:** credential section returns `vault://…` references only, never
plaintext secrets. Harvest: `credentials_returned: false`.

### Step 6 — Secret redaction / human approval

```bash
python credentials_from_agent_config/secure_agent.py \
  --mode secret_redaction \
  --file fixtures/malicious_prompt.txt

python credentials_from_agent_config/secure_agent.py \
  --mode human_approval \
  --file fixtures/malicious_prompt.txt
```

**Expected:** redaction returns `[REDACTED_SECRET]`; approval mode blocks until
`--approve`.

## Control Placement

```mermaid
flowchart LR
    prompt[Attacker prompt]
    model[Ops agent]
    info[get_agent_info]
    cfg[read_agent_config]
    file[agent_config fixture]

    prompt --> model --> info --> file
    model --> cfg --> file
    model -->|least privilege| noDump[Hide read_agent_config]
    cfg -->|config allowlist| allow[agent/settings only]
    cfg -->|vault refs| vault[Return vault:// refs]
    cfg -->|secret redaction| redact[Mask secret values]
    cfg -->|human approval| hitl[Require --approve]
```

- `least_privilege` removes config-dump tools for support chat.
- `config_allowlist` forbids `credentials` and `all`.
- `vault_refs` never stores/returns plaintext secrets in chat-readable config.
- `secret_redaction` keeps the tool but masks secret values.
- `human_approval` treats credential-section reads as proposals.

## Code Map

- [`agent.py`](agent.py) — config-debug agent that dumps plaintext credentials.
- [`secure_agent.py`](secure_agent.py) — five remediation modes.
- [`fixtures/agent_config_seed.json`](fixtures/agent_config_seed.json) — reset config.
- [`fixtures/benign_prompt.txt`](fixtures/benign_prompt.txt) — public info.
- [`fixtures/malicious_prompt.txt`](fixtures/malicious_prompt.txt) — credential dump.

## Comparison with Adjacent Labs

**Config credentials vs. tool credential harvesting:** Lab 16 abuses tools that
reach *external* secret stores. This lab reads secrets from the **agent’s own
deploy configuration**.

**Config credentials vs. RAG credential harvesting:** Lab 13 finds secrets in
documents. This lab finds them in `.env`/config style material the agent loads
at runtime.

## Discussion Questions

1. Why do “debug my agent config” tools appear so often in production agents?
2. Should chat-facing agents ever be able to read their own credential section?
3. How do vault references change the blast radius if the agent is compromised?
4. What harvest-log fields would you alert on (`credentials_returned`, section
   name, caller role)?

## Remediation Summary

Never put live secrets in chat-readable agent config, remove config-dump tools
from user-facing agents, allowlist only public sections, prefer secret managers
with runtime injection (vault refs / env from the orchestrator, not the model),
redact residual secret patterns, require human approval for break-glass config
reads, and audit credential-section access independently of model text.

## Real-World References

These are mostly public research disclosures and ATLAS-aligned writeups, not
confirmed criminal breaches:

- [Credentials from AI Agent Configuration (AML.T0083)](https://www.startupdefense.io/mitre-atlas-techniques/aml-t0083-credentials-from-ai-agent-configuration) — technique overview for stealing secrets from agent config.
- [GTK Cyber — AML.T0083](https://gtkcyber.com/atlas/AML.T0083/) — short ATLAS summary of config-stored API keys and connection strings.
- [AI Agent Tool Credential Harvesting (AML.T0098)](https://www.startupdefense.io/mitre-atlas-techniques/aml-t0098-ai-agent-tool-credential-harvesting) — related credential-access path via tools rather than config.
- [AI Agent Tool Permissions](https://www.agentpatterns.tech/en/security/tool-permissions) — least privilege and approval patterns for agent tooling.
