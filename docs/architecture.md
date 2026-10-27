# LogAgent-SOC — System Architecture

## 1. Multi-Agent Dataflow

```mermaid
graph TD
    subgraph Sources["Heterogeneous Telemetry (schema-on-read)"]
        S1[Linux Syslog]
        S2[Windows Event Logs]
        S3[K8s Audit Logs]
        S4[PCAP / NetFlow]
    end

    S1 & S2 & S3 & S4 --> P["① Zero-Shot Parser Agent<br/>src/parser/zero_shot_parser.py<br/>LLM structured extraction +<br/>source-span hallucination guard"]

    P -->|ParsedEvent JSON| LS["Forensic LogStore<br/>src/brain/tools/log_store_tool.py"]

    LS --> B["② ReAct Correlation Engine<br/>src/brain/react_agent.py"]
    KB["MITRE ATT&CK KB<br/>src/brain/mitre_kb.py"] <-->|closed-set grounding| B
    LLM[("Local LLM/SLM<br/>Ollama · vLLM · HF<br/>src/core/llm_backend.py")] <-->|Thought/Action ⇄ Observation| B

    B -->|InvestigationVerdict<br/>+ react_trace + flags| X["③ XAI Forensics Reporter<br/>src/explainability/xai_reporter.py"]
    X --> R["Markdown report:<br/>confidence · evidence · timeline · CoT"]

    B -.-> E["④ CyberMetric Evaluator<br/>src/eval/cybermetric_bench.py"]
    G[(Golden scenarios<br/>data/golden)] --> E
    E -->|hallucination rate, P/R,<br/>latency, Brier| CI["Self-correcting gate<br/>(CI fails on regression)"]
    CI -.->|improvement ledger| B
```

## 2. The ReAct Loop (core algorithm)

```
initialize scratchpad with alert event
for turn in 1..MAX_STEPS:
    decision ← SLM(system_rules, scratchpad)   # constrained JSON decoding
    if decision unparseable: reject, re-prompt          # Grounded-ReAct guard
    branch on decision.action:
        query_log_store → typed store.query(...)        # closed grammar only
        get_neighbours  → entity-linked ±60min context
        map_mitre       → KB candidates (top-4, closed set)
        final_answer    → break
    append Thought/Action/Observation to trace           # full auditability
verdict ← post-process(
    MITRE grounding      : drop technique IDs ∉ ATTACK_KB,
    lateral backtrace    : deterministic graph-trace of hops,
    claim verification   : cited ids must resolve; narrative claims
                           must match backtrace, else flag,
    risk calibration     : 0.6·self-assessment + 0.4·objective − 0.15·flags)
```

## 3. Explainability Model (XAI pillars)

| Pillar | Mechanism | Artifact in report |
|---|---|---|
| Factuality | verbatim `raw_line` appendix, event-ID citations | §5 Evidence |
| Reasoning | persisted Thought→Action→Observation turns | §6 CoT trace |
| Trust | explicit score decomposition + penalty ledger | §2 Confidence, §7 Ledger |
| Temporality | Mermaid `timeline` + ASCII attack chain from `LateralHop`s | §4 Timeline |

## 4. Threat Model & Privacy
- **Privacy:** all inference executes on local weights; no telemetry leaves the host.
- **Integrity:** parser discards entities lacking a verbatim source span; brain flags fabricated evidence IDs; deterministic backtrace overrides the LLM narrative for audit.
- **Availability:** robust-JSON salvage + bounded step budget guarantee termination on malformed model output.

## 5. Runtime Backends
| Backend | When | Models |
|---|---|---|
| `ollama` | workstations/servers w/ Ollama | qwen2.5:3b, llama3.2, phi3 |
| `vllm` | GPU research rigs | Mistral-7B-Instruct etc. |
| `hf` | transformers-only environments | any causal LM |
| `heuristic` | CI / paper-reproduction baseline | Shadow SLM (deterministic) |
