"""End-to-end tests for the LogAgent-SOC multi-agent pipeline.

Run offline (no GPU) with the deterministic Shadow-SLM backend:
    pytest -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.brain.mitre_kb import semantic_candidates, validate_technique  # noqa: E402
from src.brain.react_agent import ReActCorrelationEngine               # noqa: E402
from src.brain.tools.log_store_tool import LogStore                    # noqa: E402
from src.core.llm_backend import LocalLLMBackend                       # noqa: E402
from src.explainability.xai_reporter import XAIForensicsReporter       # noqa: E402
from src.parser.zero_shot_parser import ZeroShotParser                 # noqa: E402


@pytest.fixture(scope="module")
def llm() -> LocalLLMBackend:
    return LocalLLMBackend(backend="heuristic")


@pytest.fixture(scope="module")
def scenario_corpus() -> dict:
    return json.loads((ROOT / "data/golden/scenarios.json").read_text())


def build_case(llm, raw_lines):
    parser = ZeroShotParser(llm=llm)
    events = parser.parse_batch(raw_lines)
    store = LogStore()
    store.ingest(events)
    return events, store


# --------------------------- Parser ---------------------------------- #
def test_parser_unified_json_and_entities(llm, scenario_corpus):
    sc = scenario_corpus["scenarios"][0]
    events, _ = build_case(llm, sc["raw_lines"])
    assert len(events) == len(sc["raw_lines"])
    alert = events[sc["alert_index"]]
    assert alert.source_format.value == "linux_syslog"
    # The alert line (db-01 session) must carry its own verbatim entities…
    assert "10.0.4.12" in [e.value for e in alert.entities]
    assert "jsmith" in [e.value for e in alert.entities]
    # …and the brute-force source IP must be extracted from the lines that contain it
    ip_lines = [ev for ev in events if "203.0.113.9" in ev.raw_line]
    assert ip_lines and all(
        "203.0.113.9" in [e.value for e in ev.entities] for ev in ip_lines
    )


def test_parser_hallucination_guard(llm):
    """Entities not present verbatim must be discarded."""
    line = "2026-10-21T08:15:03Z db-01 sshd[881]: session opened for user jsmith from 10.0.4.12"
    ev, _ = build_case(llm, [line])
    for e in ev[0].entities:
        assert e.value in line or e.source_span in line


# --------------------------- MITRE KB -------------------------------- #
def test_mitre_grounding_closed_set():
    cands = semantic_candidates("sshd failed password brute accepted session opened")
    assert cands and all(validate_technique(c["technique_id"]) for c in cands)


# --------------------------- ReAct Brain ------------------------------ #
def test_react_detects_lateral_attack(llm, scenario_corpus):
    sc = scenario_corpus["scenarios"][0]
    events, store = build_case(llm, sc["raw_lines"])
    engine = ReActCorrelationEngine(store=store, llm=llm, max_steps=6)
    verdict = engine.investigate(events[sc["alert_index"]])
    assert verdict.is_malicious
    assert verdict.risk_score >= 0.5
    assert verdict.react_trace  # CoT persisted
    tids = {m.technique_id for m in verdict.mitre_mappings}
    assert "T1110" in tids or "T1021" in tids           # brute force / lateral
    assert all(validate_technique(t) for t in tids)     # no fabricated IDs
    assert verdict.lateral_movement                     # hops traced


def test_react_benign_no_flags(llm, scenario_corpus):
    sc = next(s for s in scenario_corpus["scenarios"]
              if s["id"] == "SC-005-benign-admin-ssh")
    events, store = build_case(llm, sc["raw_lines"])
    engine = ReActCorrelationEngine(store=store, llm=llm, max_steps=6)
    verdict = engine.investigate(events[sc["alert_index"]])
    assert not verdict.is_malicious


def test_fabricated_evidence_is_flagged(llm, scenario_corpus):
    """If a model cites a non-existent event id, verification must flag it."""
    sc = scenario_corpus["scenarios"][0]
    events, store = build_case(llm, sc["raw_lines"])
    engine = ReActCorrelationEngine(store=store, llm=llm, max_steps=6)
    verdict_payload = {"is_malicious": True, "risk_score": 0.9,
                       "narrative": "see [evt_doesnotexist1]",
                       "evidence_event_ids": ["evt_doesnotexist1"],
                       "lateral_movement_claim": []}
    flags = engine._verify_claims(verdict_payload, [])
    assert any("FABRICATED_EVIDENCE_ID" in f for f in flags)


# --------------------------- XAI Reporter ----------------------------- #
def test_xai_report_contains_all_pillars(llm, scenario_corpus, tmp_path):
    sc = scenario_corpus["scenarios"][0]
    events, store = build_case(llm, sc["raw_lines"])
    engine = ReActCorrelationEngine(store=store, llm=llm, max_steps=6)
    verdict = engine.investigate(events[sc["alert_index"]])
    reporter = XAIForensicsReporter(store=store, output_dir=str(tmp_path))
    path = reporter.write_report(verdict)
    md = Path(path).read_text(encoding="utf-8")
    assert "Confidence & Calibration" in md
    assert "MITRE ATT&CK Mapping" in md
    assert "```mermaid" in md and "timeline" in md      # dynamic visual timeline
    assert sc["raw_lines"][sc["alert_index"]] in md     # verbatim evidence line
    assert "ReAct Trace" in md


# --------------------------- Eval harness ----------------------------- #
def test_cybermetric_gate_passes_on_golden(llm):
    from src.eval.cybermetric_bench import evaluate, load_scenarios
    report = evaluate(load_scenarios(ROOT / "data/golden/scenarios.json"),
                      "heuristic", "shadow-slm-v1")
    assert report["gate_passed"], report
    assert report["hallucination_rate"] <= 0.30
    assert report["precision"] >= 0.6 and report["recall"] >= 0.6
