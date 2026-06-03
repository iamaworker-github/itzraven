# Itzraven — AI-Powered Autonomous Pentest Platform

```
     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
    ███████║██████╔╝██║  ███╗██║   ██║███████╗
    ██╔══██║██║══██╗██║   ██║██║   ██║╚════██║
    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

> **See Everything. Miss Nothing.**
> Itzraven is an AI-powered autonomous security testing platform with **60+ specialized agents**, **150+ hacking skills**, **swarm intelligence architecture**, and self-learning capabilities. It plans, executes, learns, and **thinks like a real penetration tester** — no manual configuration needed. **No paid API keys required** — uses OpenCode DeepSeek V4 Flash Free by default.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-Repo-181717.svg?logo=github)](https://github.com/iamaworker-github/itzraven)
[![Docker](https://img.shields.io/badge/Docker-iamaworker135%2Fitzraven-2496ED.svg?logo=docker)](https://hub.docker.com/r/iamaworker135/itzraven)
[![Agents](https://img.shields.io/badge/Agents-60%2B-8957e5)](https://github.com/iamaworker-github/itzraven)
[![AI](https://img.shields.io/badge/AI-Free%20Tier-10b981)](https://opencode.ai)

---

## Quick Install

### Prerequisites
- Python 3.11+
- [Optional] Docker for sandbox execution
- [Optional] Node.js for frontend development

### One-line (Linux/macOS)
```bash
curl -fsSL https://raw.githubusercontent.com/iamaworker-github/itzraven/main/install.sh | bash
```

### Manual Install
```bash
git clone https://github.com/iamaworker-github/itzraven.git
cd itzraven
pip install -e .
pip install openai  # for built-in LLM support

# Start web dashboard (free AI included)
OPENCODE_API_KEY="your-key" \
AI_MODEL="opencode/deepseek-v4-flash-free" \
USE_DOCKER=false \
DOCKER_MANDATORY=false \
itzraven web --port 8484
```

### Docker
```bash
# Pull & run (free AI included - no API key needed)
docker run -d --name itzraven -p 8484:8484 \
  -e OPENCODE_API_KEY="your-key" \
  -e AI_MODEL="opencode/deepseek-v4-flash-free" \
  iamaworker135/itzraven:latest
```

> Get a free OpenCode API key at [opencode.ai](https://opencode.ai)

---

## Architecture

Itzraven has **two parallel execution modes** that can be used independently or together:

### 1. 🐝 Swarm Mode (Stigmergic Blackboard)
```
TARGET_REGISTERED ──► recon agent wakes (pheromone: 0.8)
       │
       ▼ writes SUBDOMAIN (pheromone: 0.8, half-life: 600s)
SUBDOMAIN ──► tech_detect agent wakes (threshold: 0.3)
       │
       ▼ writes TECHNOLOGY (pheromone: 0.7)
TECHNOLOGY ──► nuclei/CVE agent wakes (threshold: 0.4)
       │
       ▼ writes VULNERABILITY (pheromone: 0.9)
VULNERABILITY ──► exploit agent wakes (threshold: 0.6)
       │
       ▼ writes EXPLOIT_RESULT
EXPLOIT_RESULT ──► chain agent wakes (threshold: 0.5)
       │
       ▼ writes CAMPAIGN_COMPLETE ──► report agent (threshold: 0.9)
```

- **No central planner** — agents coordinate via shared blackboard with pheromone weights
- **Pheromone decay** — `w(t) = base × 2^(-t/half_life)` — stale paths die naturally
- **Emergent attack chains** — order emerges from state, not from prescribed phases
- **Exploration bias** — `--bias high` = aggressive, `--bias low` = conservative

### 2. 🧠 Sequential Mode (LangGraph Orchestrator)
```
Phase 0: AI Planning ─── LLM analyzes target, selects optimal agents
Phase 1: Reconnaissance ─── Port scan (naabu→masscan→nmap), subdomain discovery, WAF detection
Phase 2: Enumeration ─── Technology fingerprinting, endpoint discovery, Nuclei scanning
Phase 3: Vulnerability ─── AI-selected agents run based on detected technologies
Phase 4: AI Analysis ─── Cross-target intelligence, chain discovery, PoC validation
Phase 5: Reporting ─── Executive summary with actionable findings
```

- **StateGraph** with durable SQLite checkpointing — crash recovery built-in
- **Conditional edges** — routes agents based on detected technologies
- **Human-in-the-loop** interrupts before analysis & reporting phases
- **Tool queue scanning** — naabu → masscan → nmap full → nmap stealth (auto-fallback)

---

## Features

### 🤖 Zero-Cost AI (Default)
| Feature | Description |
|---------|-------------|
| **OpenCode DeepSeek V4 Flash Free** | Default LLM — completely free, no API key required for basic use |
| **OpenCode API key** | Optional — register at opencode.ai for enhanced rate limits |
| **BlockRun Fallback** | Free DeepSeek V4 Flash via BlockRun — no key needed |
| **LiteLLM Compatible** | Any LiteLLM-supported provider works (OpenAI, Anthropic, Groq, etc.) |
| **AI Chat** | In-dashboard chat with scan context awareness |

### 🐝 Swarm Intelligence
| Feature | Description |
|---------|-------------|
| **Stigmergic Blackboard** | Shared knowledge store with pheromone weights + time decay |
| **Trigger Predicates** | Each agent has a trigger rule — wakes when relevant state appears |
| **Emergent Scheduler** | No central planner — dispatching emerges from blackboard state |
| **Exploration Bias** | `--bias low|med|high` — controls aggression vs thoroughness |
| **Playbook Engine** | YAML playbooks: bug-bounty, external-asm, ci-cd, ctf-solver |

### 🔧 Agent Arsenal (60+ Agents)
| Category | Agents |
|----------|--------|
| **Core Web** | SQLi, XSS, SSRF, IDOR, SSTI, XXE, CORS, Command Injection, Open Redirect, NoSQLi, Host Header, Rate Limit, LFI, Prototype Pollution |
| **Auth & Identity** | JWT Attack, Authentication, OAuth Hunter, SAML Attack, Session Management |
| **Cloud & Infra** | Cloud Security, Container Escape, Kubernetes, WAF Detection/Bypass, Nuclei |
| **Bug Bounty** | VDP Discovery, Android APK Hacker, Web3 Auditor, CVE Exploiter, JS Secrets, Function-Wise Hunter, Info Disclosure Hunter, LLM Recon Chain, Race Condition Hunter |
| **Bug Bounty Pipeline** | Pipeline Orchestrator (7-phase), Two-Eye Approach, Cache Poisoning, CRLF Injection, Exploit Chain Builder (A→B→C) |
| **CTF Solving** | CTF Solver, Advanced CTF Solver (11 categories, 100+ techniques), Racing CTF Agent (multi-model) |
| **OSINT** | OSINT Collector, Social Intel, Leak Intel, DNS Intel, Google Dork, Crypto OSINT |
| **Enterprise** | IoT Security, Mobile Pentest, API Pentest, LLM Red Team, AI Security |
| **Infrastructure** | Recon Agent, Smart Brute Force, Port Scanner, Medusa, PoC Validator, Remediation |

### 🎯 Skills Library (150+ Skills)
- **Vaidik Pandya Methodologies**: VDP hunter, Android APK, Web3 smart contract, JS secrets, function-wise hunting, CVE exploitation, info disclosure, LLM recon automation, race conditions, subfinder mastery
- **2026 Bug Bounty Pipeline**: Full 7-phase pipeline, Two-Eye Approach, cache poisoning, CRLF injection
- **Hunting Skills**: RCE (1,135 lines), IDOR (969 lines), XSS (968 lines), OAuth (770 lines), LLM/AI (930 lines)
- **CTF Skills**: 11 categories (pwn, rev, crypto, forensics, web, osint, stego, ai_ml, malware, blockchain, misc)
- **Pentesting**: Account takeover, SSRF, SQLi, XSS, JWT, CSRF, XXE, deserialization, file upload, business logic, GraphQL, race conditions, web3, mobile, cloud, AD, IoT
- **Methodology**: Recon methodology, hunting methodology, report writing, SAST methodology, triage validation, vulnerability classes

### 📊 Web Dashboard
Real-time scan monitoring with live WebSocket updates. Features:
- **Live port scanning** — progress shows each tool name (naabu, masscan, nmap)
- **AI Findings section** — Collapsible, shows AI/LLM-generated findings
- **Findings section** — Collapsible, shows all tool-generated findings (nuclei, port scans, recon)
- **Attack Graph** — Visual node/edge representation of scan targets
- **AI Chat** — Ask questions about scan progress in real-time
- **Left Panel** — CPU/MEM/Net usage, AI model + provider display
- **Conditional Stop Button** — Only visible while scan is running

---

## CLI Commands

```bash
# Traditional pentest
itzraven strix --target https://example.com -m deep

# Swarm mode
itzraven swarm --target example.com --playbook bug-bounty --bias high

# Bug bounty full pipeline (7-phase)
itzraven pipeline --target https://example.com

# Web dashboard
itzraven web --host 0.0.0.0 --port 8484

# MCP server for Claude/Cursor
itzraven mcp serve

# List playbooks
itzraven playbook list

# Run a specific playbook
itzraven playbook run bug-bounty --target example.com
```

### Swarm Playbooks
| Playbook | Description | Budget |
|----------|-------------|--------|
| `bug-bounty` | Fast recon → high-value vulns | 30 min |
| `external-asm` | Attack surface management | 60 min |
| `ci-cd` | Fast feedback for dev teams | 10 min |
| `ctf-solver` | Aggressive CTF scanning | 120 min |

---

## Scan Modes

| Mode | Duration | Description |
|------|----------|-------------|
| `quick` | 5-15 min | Surface scan — CI/CD gate, low-hanging fruit |
| `standard` | 30-60 min | Standard depth — bug bounty triage |
| `deep` | 1-4 hrs | Full coverage — pentest engagement |
| `whitebox` | varies | Source-sink analysis — code review |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENCODE_API_KEY` | Recommended | OpenCode API key (free at opencode.ai) |
| `AI_MODEL` | Optional | Default: `opencode/deepseek-v4-flash-free` |
| `OPENCODE_API_BASE` | Optional | OpenCode API base URL |
| `OPENAI_API_KEY` | Optional | OpenAI / Azure OpenAI |
| `ANTHROPIC_API_KEY` | Optional | Anthropic Claude |
| `GOOGLE_API_KEY` | Optional | Google Gemini |
| `GROQ_API_KEY` | Optional | Groq (fast inference) |
| `USE_DOCKER` | Optional | Set `false` to skip Docker sandbox |
| `DOCKER_MANDATORY` | Optional | Set `false` to make Docker optional |

Itzraven uses **OpenCode DeepSeek V4 Flash Free** by default — zero cost, no API key required for basic operation. For production workloads, get a free key at [opencode.ai](https://opencode.ai). LiteLLM is also supported for any provider.

---

## License

Apache 2.0 License — see [LICENSE](LICENSE).

---

*Built by [iamaworker-github](https://github.com/iamaworker-github) — See Everything. Miss Nothing.*
