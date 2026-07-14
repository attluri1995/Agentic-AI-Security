# Hands-On AI Security Labs

Hands-on labs for learning AI security, mapped to vulnerabilities in the [MITRE ATLAS](https://atlas.mitre.org/) framework.

Each lab directory contains three artifacts:

- `agent.py` — intentionally vulnerable implementation
- `secure_agent.py` — remediated version with guardrails
- `README.md` — technique ID, exploit theory, and safe local walkthrough

## Prerequisites

Requires Python 3.9+ (3.11+ recommended).

- [Ollama](https://ollama.com/) installed and running locally

## Quick Start

```bash
# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Pull the default model (supports tool calling)
ollama pull llama3.2

# Copy env config (optional — defaults work out of the box)
cp .env.example .env

# Run lab — benign baseline
python indirect_prompt_injection/agent.py \
  --file fixtures/benign_article.html \
  --prompt "Summarize this article"

# Run lab — injection demo
python indirect_prompt_injection/agent.py \
  --file fixtures/malicious_article.html \
  --prompt "Summarize this article"

# Run the remediated agent
python indirect_prompt_injection/secure_agent.py \
  --mode judge \
  --file fixtures/malicious_article.html \
  --prompt "Summarize this article"

# Lab 2 — direct prompt injection
python direct_prompt_injection/agent.py \
  --file fixtures/malicious_prompt.txt

python direct_prompt_injection/secure_agent.py \
  --mode input_gate \
  --file fixtures/malicious_prompt.txt

# Lab 3 — triggered prompt injection
python triggered_prompt_injection/agent.py \
  --file fixtures/benign_query.txt

python triggered_prompt_injection/agent.py \
  --file fixtures/trigger_query.txt

python triggered_prompt_injection/secure_agent.py \
  --mode quarantine \
  --file fixtures/trigger_query.txt

# Lab 4 — prompt infiltration
python prompt_infiltration/agent.py \
  --file fixtures/malicious_ticket.txt \
  --run full

python prompt_infiltration/secure_agent.py \
  --mode ingest_judge \
  --file fixtures/malicious_ticket.txt \
  --run full

# Lab 5 — context poisoning: memory
python context_poisoning_memory/agent.py \
  --file fixtures/plant_prompt.txt \
  --run full

python context_poisoning_memory/secure_agent.py \
  --mode memory_write_judge \
  --file fixtures/plant_prompt.txt \
  --run full

# Lab 6 — context poisoning: thread
python context_poisoning_thread/agent.py \
  --file fixtures/poisoned_thread.json

python context_poisoning_thread/secure_agent.py \
  --mode history_judge \
  --file fixtures/poisoned_thread.json
```

## Lab Roadmap (Agent-Focused ATLAS Techniques)

This project targets **agent-specific** MITRE ATLAS techniques — attacks against tool invocation, memory, configuration, RAG, multi-turn context, and agent supply chains. Model-training attacks (e.g. poisoning training data, backdooring weights) are out of scope.

Each row is one planned lab folder. Folder names are stable slugs; build order follows **Priority** (lower = build first).

### Phase 1 — Prompt & Context (Initial Access / Persistence)

| Priority | Folder | Technique | ATLAS ID | Status |
|----------|--------|-----------|----------|--------|
| 1 | [`indirect_prompt_injection/`](indirect_prompt_injection/) | LLM Prompt Injection: Indirect | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | **Available** |
| 2 | [`direct_prompt_injection/`](direct_prompt_injection/) | LLM Prompt Injection: Direct | [AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000) | **Available** |
| 3 | [`triggered_prompt_injection/`](triggered_prompt_injection/) | LLM Prompt Injection: Triggered | [AML.T0051.002](https://atlas.mitre.org/techniques/AML.T0051.002) | **Available** |
| 4 | [`prompt_infiltration/`](prompt_infiltration/) | Prompt Infiltration via Public-Facing Application | [AML.T0093](https://atlas.mitre.org/techniques/AML.T0093) | **Available** |
| 5 | [`context_poisoning_memory/`](context_poisoning_memory/) | AI Agent Context Poisoning: Memory | [AML.T0080.000](https://atlas.mitre.org/techniques/AML.T0080.000) | **Available** |
| 6 | [`context_poisoning_thread/`](context_poisoning_thread/) | AI Agent Context Poisoning: Thread | [AML.T0080.001](https://atlas.mitre.org/techniques/AML.T0080.001) | **Available** |
| 7 | `delay_execution/` | Delay Execution of LLM Instructions | [AML.T0094](https://atlas.mitre.org/techniques/AML.T0094) | Planned |

### Phase 2 — Tool Abuse (Execution / Privilege Escalation / Impact)

| Priority | Folder | Technique | ATLAS ID | Status |
|----------|--------|-----------|----------|--------|
| 8 | `unbounded_tool_misuse/` | AI Agent Tool Invocation | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | Planned |
| 9 | `data_destruction_via_tools/` | Data Destruction via AI Agent Tool Invocation | [AML.T0101](https://atlas.mitre.org/techniques/AML.T0101) | Planned |
| 10 | `exfiltration_via_tools/` | Exfiltration via AI Agent Tool Invocation | [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) | Planned |
| 11 | `agent_clickbait/` | AI Agent Clickbait | [AML.T0100](https://atlas.mitre.org/techniques/AML.T0100) | Planned |
| 12 | `escape_to_host/` | Escape to Host | [AML.T0105](https://atlas.mitre.org/techniques/AML.T0105) | Planned |

### Phase 3 — Data & Credential Access (Collection / Credential Access)

| Priority | Folder | Technique | ATLAS ID | Status |
|----------|--------|-----------|----------|--------|
| 13 | `rag_credential_harvesting/` | RAG Credential Harvesting | [AML.T0082](https://atlas.mitre.org/techniques/AML.T0082) | Planned |
| 14 | `rag_data_harvesting/` | Data from AI Services: RAG Databases | [AML.T0085.000](https://atlas.mitre.org/techniques/AML.T0085.000) | Planned |
| 15 | `agent_tool_data_harvesting/` | Data from AI Services: AI Agent Tools | [AML.T0085.001](https://atlas.mitre.org/techniques/AML.T0085.001) | Planned |
| 16 | `agent_tool_credential_harvesting/` | AI Agent Tool Credential Harvesting | [AML.T0098](https://atlas.mitre.org/techniques/AML.T0098) | Planned |
| 17 | `credentials_from_agent_config/` | Credentials from AI Agent Configuration | [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083) | Planned |

### Phase 4 — Persistence & Supply Chain

| Priority | Folder | Technique | ATLAS ID | Status |
|----------|--------|-----------|----------|--------|
| 18 | `modify_agent_configuration/` | Modify AI Agent Configuration | [AML.T0081](https://atlas.mitre.org/techniques/AML.T0081) | Planned |
| 19 | `agent_tool_data_poisoning/` | AI Agent Tool Data Poisoning | [AML.T0099](https://atlas.mitre.org/techniques/AML.T0099) | Planned |
| 20 | `publish_poisoned_agent_tool/` | Publish Poisoned AI Agent Tool | [AML.T0104](https://atlas.mitre.org/techniques/AML.T0104) | Planned |
| 21 | `poisoned_agent_tool/` | User Execution: Poisoned AI Agent Tool | [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) | Planned |
| 22 | `deploy_ai_agent/` | Deploy AI Agent | [AML.T0103](https://atlas.mitre.org/techniques/AML.T0103) | Planned |

### Phase 5 — Discovery, Recon & Advanced Agent Patterns

| Priority | Folder | Technique | ATLAS ID | Status |
|----------|--------|-----------|----------|--------|
| 23 | `discover_agent_configuration/` | Discover AI Agent Configuration | [AML.T0084](https://atlas.mitre.org/techniques/AML.T0084) | Planned |
| 24 | `multi_agent_delegation_hijack/` | Multi-agent orchestrator / delegation abuse *(custom lab extension)* | Related: [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053), [AML.T0080.001](https://atlas.mitre.org/techniques/AML.T0080.001) | Planned |
| 25 | `ai_service_api_c2/` | AI Service API (agent as C2 channel) | [AML.T0096](https://atlas.mitre.org/techniques/AML.T0096) | Planned |

**Note:** `multi_agent_delegation_hijack/` covers orchestrator hijacking and credential relay across delegation chains — a pattern discussed in agentic gap analyses but not yet a standalone ATLAS technique. It will map to related official techniques in the lab README.

### Related ATLAS Techniques (Optional Future Labs)

These are agent-adjacent but lower priority for hands-on agent labs:

| Technique | ATLAS ID |
|-----------|----------|
| LLM Jailbreak | [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) |
| Extract LLM System Prompt | [AML.T0056](https://atlas.mitre.org/techniques/AML.T0056) |
| LLM Data Leakage | [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057) |
| Manipulate User LLM Chat History | [AML.T0092](https://atlas.mitre.org/techniques/AML.T0092) |

## Lab Template

Every vulnerability lab follows the same structure:

```
<vulnerability_slug>/
├── README.md           # ATLAS ID, threat model, walkthrough
├── agent.py            # Vulnerable agent
├── secure_agent.py     # Remediated agent
└── fixtures/           # Local mock data (safe, offline)
```

Shared utilities live in [`shared/`](shared/) (`config.py`, `llm.py`, `tools.py`). Extend this layer as new labs need databases, vector stores, or multi-agent orchestrators.

## Project Structure

```
├── shared/                       # Reusable Ollama client, config, tools
├── indirect_prompt_injection/    # Lab 1 (available)
├── direct_prompt_injection/      # Lab 2 (available)
├── triggered_prompt_injection/   # Lab 3 (available)
├── prompt_infiltration/          # Lab 4 (available)
├── context_poisoning_memory/     # Lab 5 (available)
├── context_poisoning_thread/     # Lab 6 (available)
└── <vulnerability_slug>/         # One folder per ATLAS technique
```

See [indirect_prompt_injection/README.md](indirect_prompt_injection/README.md), [direct_prompt_injection/README.md](direct_prompt_injection/README.md), [triggered_prompt_injection/README.md](triggered_prompt_injection/README.md), [prompt_infiltration/README.md](prompt_infiltration/README.md), [context_poisoning_memory/README.md](context_poisoning_memory/README.md), and [context_poisoning_thread/README.md](context_poisoning_thread/README.md) for complete walkthroughs.

## Safety Disclaimer

This project is for **local educational use only**. All exploits use local fixture files — never point agents at production systems, real user data, or live URLs you do not control.

## Contributing

When adding a lab:

1. Create a folder using the slug from the roadmap table above.
2. Implement `agent.py`, `secure_agent.py`, and `README.md` following the existing lab pattern.
3. Update the **Status** column in this README from `Planned` to **Available**.
