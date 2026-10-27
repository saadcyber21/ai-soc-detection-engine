# 🧠 LogAgent-SOC

> **An Autonomous Cyber Threat Hunting & Explainable AI (XAI) Forensics Engine**
> A multi-agent pipeline built entirely on *local, open-weight* LLMs/SLMs — zero data egress, zero cloud APIs, fully auditable.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Local-LLM](https://img.shields.io/badge/Runtime-Ollama%20·%20vLLM%20·%20HF-blueviolet?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Grounded-orange?style=flat-square)
![XAI](https://img.shields.io/badge/XAI-Citation%20Enforced-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-informational?style=flat-square)

---

## 📖 Abstract

Traditional SIEM correlation is signature-bound: it fails on novel TTPs, cannot explain its verdicts, and buries analysts in untriaged alerts. **LogAgent-SOC** replaces the rule engine with an **autonomous multi-agent system**:

| Agent | Module | Innovation |
|---|---|---|
| **Parser Agent** | `src/parser` | Zero-shot heterogeneous ingestion — Linux syslog, Windows events, K8s audit, PCAP flows → unified JSON *without predefined schemas*, protected by verbatim source-span validation |
| **Hunting Brain** | `src/brain` | Bounded **ReAct** loop (Reason→Act→Observe) over a forensic log store; closed-set MITRE ATT&CK grounding; deterministic lateral-movement backtrace |
| **XAI Reporter** | `src/explainability` | Forensic Markdown reports with calibrated confidence, verbatim evidence citations, full chain-of-thought trace, and auto-generated Mermaid attack timelines |
| **Critic / Eval** | `src/eval` | CyberMetric benchmark: hallucination rate, Precision/Recall on zero-day slices, latency percentiles, Brier calibration — with a **self-correcting suggestion ledger** that gates CI |

### Research contributions
1. **Grounded ReAct for forensics** — every tool call is a *typed* query against a closed grammar; unparseable actions are rejected, so the agent cannot act on hallucinated tools.
2. **Falsifiable narratives** — the LLM's verdict is cross-checked against an independent deterministic reconstruction; unverifiable claims *reduce* the published confidence instead of silently shipping.
3. **Closed-set ATT&CK retrieval** — the model chooses techniques only from KB-grounded candidates, structurally eliminating fabricated technique IDs.
4. **Reproducible offline evaluation** — a "Shadow SLM" heuristic backend implements the same JSON contracts as real models, so benchmarks run deterministically in CI without GPUs.

---

## 🏗️ Repository Layout

```text
LogAgent-SOC/
├── run_pipeline.py                  # end-to-end entrypoint (CLI)
├── configs/
│   └── settings.yaml                # model, thresholds, paths
├── src/
│   ├── core/                        # shared spine
│   │   ├── schemas.py               # Pydantic v2 canonical data contracts
│   │   └── llm_backend.py           # Ollama / vLLM / HF / heuristic local backends
│   ├── parser/                      # ① Zero-Shot Heterogeneous Parser
│   │   └── zero_shot_parser.py      #    schema-on-read LLM extraction + span guard
│   ├── brain/                       # ② Chain-of-Thought Correlation Engine
│   │   ├── react_agent.py           #    ReAct loop, MITRE grounding, backtrace
│   │   ├── mitre_kb.py              #    compact grounded ATT&CK knowledge base
│   │   └── tools/
│   │       └── log_store_tool.py    #    forensic LogStore (typed query substrate)
│   ├── explainability/              # ③ XAI Forensics Generator
│   │   └── xai_reporter.py          #    Markdown reports + Mermaid timelines
│   ├── eval/                        # ④ Self-Correcting Evaluation Framework
│   │   └── cybermetric_bench.py     #    hallucination / P-R / latency / calibration
│   └── adapters/                    # optional SIEM/ticket sinks
├── data/
│   ├── raw_logs/mixed_attack.log    # heterogeneous demo corpus
│   └── golden/scenarios.json        # labelled CyberMetric scenarios (incl. zero-day)
├── docs/
│   ├── architecture.md              # deep-dive design document
│   ├── incident_playbooks/
│   └── xai_reports/                 # generated forensic reports land here
├── reports/                         # machine-readable benchmark output
├── tests/                           # pytest suites (parser, brain, xai, eval)
└── notebooks/                       # research experiments & prompt A/B tests
```

---

## ⚙️ Quickstart

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 0) No GPU? everything still runs via the deterministic Shadow-SLM backend.
#    With GPU/local weights:  ollama pull qwen2.5:3b  (or llama3.2, phi3)

# 1) Full pipeline: parse → hunt → explain
python run_pipeline.py --backend heuristic \
    --input data/raw_logs/mixed_attack.log --alert-contains "session opened"
# → docs/xai_reports/INC-XXXXXXXX_*.md

# 2) CyberMetric benchmark (exits non-zero on quality regression)
python src/eval/cybermetric_bench.py --backend heuristic

# 3) Tests
pytest -q
```

Switch to a real local model with no code change:

```bash
python run_pipeline.py --backend ollama --model qwen2.5:3b
```

---

## 🔬 Example finding (auto-generated report excerpt)

```text
CONFIDENCE  [██████████████████████░░░░░░░░]  0.73
T1110 Brute Force → T1078 Valid Accounts → T1021.004 SSH   (grounded, cited)
ATTACK CHAIN: web-01—[SSH]→203.0.113.9 ⇒ db-01—[SSH]→10.0.4.12
All claims passed grounding verification (0 hallucination flags).
```

---

## 📐 Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full agent-interaction diagram and threat model (privacy: all inference is local; integrity: evidence spans validated; availability: robust-JSON salvage prevents ingestion crashes).

## 📄 License & Citation
MIT. If you extend this work, cite as: *LogAgent-SOC: An Autonomous Cyber Threat Hunting & Explainable AI Forensics Engine* (2026).
