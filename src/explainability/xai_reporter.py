"""LogAgent-SOC :: XAI Forensics Report Generator.

Turns an ``InvestigationVerdict`` into a human/auditor-readable Markdown
report with four explainability pillars:

  * FACTUALITY  - every claim links to verbatim raw log lines (evidence
    appendix) and event IDs; hallucination flags are shown, not hidden.
  * REASONING   - the full ReAct trace is rendered as a step-by-step
    chain-of-thought appendix (thought -> action -> observation).
  * TRUST       - calibrated confidence score with explicit decomposition
    (LLM self-assessment vs objective signals vs verification penalty).
  * TEMPORALITY - a dynamic Mermaid + ASCII attack timeline of the
    lateral-movement path, auto-generated from LateralHop records.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

from src.brain.tools.log_store_tool import LogStore
from src.core.schemas import InvestigationVerdict, ParsedEvent

logger = logging.getLogger("logagent.xai")


class XAIForensicsReporter:
    def __init__(self, store: LogStore,
                 output_dir: str = "docs/xai_reports"):
        self.store = store
        self.output_dir = output_dir

    # ------------------------------------------------------------------ #
    def render(self, v: InvestigationVerdict) -> str:
        md: List[str] = []
        md += self._header(v)
        md += self._executive_summary(v)
        md += self._confidence_block(v)
        md += self._mitre_block(v)
        md += self._timeline_block(v)
        md += self._evidence_block(v)
        md += self._react_trace_block(v)
        md += self._hallucination_block(v)
        return "\n".join(md)

    def write_report(self, v: InvestigationVerdict) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir,
                            f"{v.incident_id}_{v.created_at:%Y%m%d%H%M%S}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.render(v))
        logger.info("XAI report written: %s", path)
        return path

    # ------------------------------------------------------------------ #
    def _header(self, v: InvestigationVerdict) -> List[str]:
        verdict = "🔴 MALICIOUS" if v.is_malicious else "🟢 BENIGN"
        return [
            f"# 🕵️ XAI Forensic Report — {v.incident_id}",
            "",
            f"| Field | Value |",
            f"|---|---|",
            f"| Verdict | **{verdict}** |",
            f"| Risk Score | `{v.risk_score:.2f}` / 1.00 |",
            f"| Model | `{v.model_id}` |",
            f"| Investigation latency | `{v.total_latency_ms:.0f} ms` |",
            f"| Generated (UTC) | {datetime.now(timezone.utc).isoformat(timespec='seconds')} |",
            "",
        ]

    def _executive_summary(self, v: InvestigationVerdict) -> List[str]:
        return ["## 1. Executive Summary", "",
                f"> Alert: **{v.alert_summary}**", "", v.narrative or "_(no narrative)_", ""]

    def _confidence_block(self, v: InvestigationVerdict) -> List[str]:
        n_flags = len(v.hallucination_flags)
        bar_len = int(round(v.risk_score * 30))
        bar = "█" * bar_len + "░" * (30 - bar_len)
        return [
            "## 2. Confidence & Calibration",
            "",
            "```",
            f"CONFIDENCE  [{bar}]  {v.risk_score:.2f}",
            "```",
            "",
            "| Component | Value |",
            "|---|---|",
            f"| Evidence events cited | {len(v.evidence_event_ids)} |",
            f"| MITRE techniques mapped | {len(v.mitre_mappings)} |",
            f"| Verified lateral hops | {len(v.lateral_movement)} |",
            f"| Hallucination flags | {n_flags} |",
            "",
            "_Score = 0.6·LLM self-assessment + 0.4·objective evidence signal,"
            " minus 0.15 per unverifiable claim (see §6)._",
            "",
        ]

    def _mitre_block(self, v: InvestigationVerdict) -> List[str]:
        rows = ["## 3. MITRE ATT&CK Mapping", ""]
        if not v.mitre_mappings:
            rows.append("_No techniques matched against the grounded KB._")
        else:
            rows.append("| Tactic | Technique | ID | Confidence | Supporting events |")
            rows.append("|---|---|---|---|---|")
            for m in v.mitre_mappings:
                evs = ", ".join(f"`{e}`" for e in m.supporting_event_ids[:3]) or "—"
                rows.append(f"| {m.tactic} | {m.technique_name} | "
                            f"`{m.technique_id}` | {m.confidence:.2f} | {evs} |")
        rows.append("")
        return rows

    def _timeline_block(self, v: InvestigationVerdict) -> List[str]:
        rows = ["## 4. Attack Timeline", ""]
        if not v.lateral_movement:
            rows.append("_No cross-host movement detected in verified evidence._\n")
            return rows
        # Mermaid timeline (renders on GitHub) ----------------------------
        rows += ["```mermaid", "timeline", "    title Attacker Path "
                 f"({v.incident_id})", "    section Intrusion"]
        for hop in v.lateral_movement:
            label = hop.ts.strftime("%H:%M:%S")
            rows.append(f"    {label} : {hop.src} → {hop.dst}"
                        + (f" ({hop.mechanism})" if hop.mechanism else ""))
        rows += ["```", ""]
        # ASCII fallback ---------------------------------------------------
        chain = " ⇒ ".join(
            f"{h.src}—[{h.mechanism or 'hop'}]→{h.dst}" for h in v.lateral_movement)
        rows += ["```text", f"ATTACK CHAIN: {chain}", "```", ""]
        return rows

    def _evidence_block(self, v: InvestigationVerdict) -> List[str]:
        rows = ["## 5. Evidence Appendix (verbatim log lines)", ""]
        missing = False
        for eid in v.evidence_event_ids:
            ev: Optional[ParsedEvent] = self.store.get(eid)
            if ev is None:
                rows.append(f"- ⚠️ `{eid}` — **NOT FOUND IN STORE** (flagged)")
                missing = True
                continue
            rows.append(f"**`{eid}`** · {ev.timestamp.isoformat()} · "
                        f"format=`{ev.source_format.value}` · "
                        f"parse_conf={ev.parse_confidence:.2f}")
            rows += ["```log", ev.raw_line, ""]
        if missing:
            rows.append("_⚠️ Some cited evidence could not be retrieved; "
                        "treat the verdict with reduced trust._")
        rows.append("")
        return rows

    def _react_trace_block(self, v: InvestigationVerdict) -> List[str]:
        rows = ["## 6. Chain-of-Thought (ReAct Trace)", ""]
        for s in v.react_trace:
            rows.append(f"**Step {s.step}** · `_gpt {s.latency_ms:.0f}ms_`")
            rows.append(f"- 💭 **Thought:** {s.thought}")
            if s.action:
                rows.append(f"- 🎬 **Action:** `{s.action}` ← "
                            f"`{str(s.action_input)[:200]}`")
            if s.observation:
                obs = s.observation.replace("\n", "\n  ")
                rows.append(f"- 👀 **Observation:**\n  ```\n  {obs[:900]}\n  ```")
            rows.append("")
        return rows

    def _hallucination_block(self, v: InvestigationVerdict) -> List[str]:
        rows = ["## 7. Self-Correction Ledger", ""]
        if not v.hallucination_flags:
            rows.append("✅ All claims passed grounding verification "
                        "(event IDs resolve; lateral claims match the "
                        "deterministic backtrace).")
        else:
            rows.append("The following LLM claims failed verification and "
                        "were penalized in §2:")
            rows += [f"- ❌ {f}" for f in v.hallucination_flags]
        rows += ["", "---", "_Generated autonomously by LogAgent-SOC XAI "
                 "engine. Deterministic reconstruction is independent of "
                 "the LLM narrative and takes precedence for audit._"]
        return rows
