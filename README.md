# 🛡️ AI SOC Detection Engine
> Continuous Threat Monitoring & Automated Alert Triage for Enterprise LLMs

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Build](https://img.shields.io/badge/CI%2FCD-Passing-2ea44f?style=flat-square&logo=githubactions&logoColor=white)
![Security](https://img.shields.io/badge/SAST-Bandit%20Verified-blueviolet?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-informational?style=flat-square)

---

## 📖 Executive Summary

* **The Problem:** As enterprise AI adoption accelerates, traditional security monitoring stacks fail to detect semantic-layer attacks such as prompt injection, agent tool misuse, and confidential data leakage.
* **The Solution:** The **AI SOC Detection Engine** provides an automated telemetry analysis pipeline designed to intercept, parse, and evaluate AI activity against customizable DevSecOps rules before incidents impact production systems.

---

## 🏗️ System Architecture

```mermaid
graph TD
    subgraph Telemetry Sources
        A[User Prompts] --> E
        B[Agent Tool Calls] --> E
        C[RAG Document Retrievals] --> E
    end

    E[JSON Telemetry Feed] -->|Structured Ingestion| F(Python Detection Engine)
    
    subgraph Detection & Response
        F -->|Rule Evaluation| G[DevSecOps Rule Engine]
        G -->|Match Found| H[Security Alert Dispatched]
        H --> I[SOC Incident Playbook]
    end
🎯 Key Detection ModulesRule ModuleTarget Attack VectorFramework MappingPrompt InjectionJailbreak patterns, instruction override, base64 evasionOWASP LLM01Shadow AI DLPPlaintext API keys, credentials, PII leakageOWASP LLM02 / LLM06Telemetry ParserMalformed payloads, unauthorized event schemasDefensive Logging⚙️ Environment Setup1. PrerequisitesPython 3.11 or higherGit2. Configure Environment VariablesBashcp .env.example .env
3. InstallationBashpython -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
💻 Usage & VerificationStep 1: Ingest TelemetryGenerate sample AI logs into data/sample_telemetry.json:Bashpython src/telemetry_simulator.py
Step 2: Execute Detection EngineRun the engine to process events and trigger security alerts:Bashpython src/detection_engine.py
Example Terminal Output:Plaintext2026-08-26 14:35:01 - INFO - Loaded 3 events for security scanning.
2026-08-26 14:35:01 - WARNING - SECURITY ALERT TRIGGERED:
{'alert_id': 'ALRT-evt_1111', 'rule_triggered': 'Prompt Injection / Jailbreak Attempt', 'reason': 'Matched malicious pattern: (?i)ignore\\s+all\\s+previous\\s+instructions'}
🔒 Security & Quality AssuranceZero Hardcoded Secrets: Dynamic runtime configuration via environment variables.Static Application Security Testing (SAST): Automated vulnerability scans via bandit in CI/CD.Test Coverage: Modular test suites implemented with pytest for all signature evaluations.Defensive Exception Handling: Prevents log ingestion crashes during malformed payload parsing.📄 LicenseDistributed under the MIT License. See LICENSE for more information.
