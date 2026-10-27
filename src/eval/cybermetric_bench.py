"""LogAgent-SOC :: CyberMetric Self-Correcting Evaluation Framework.

Benchmark harness measuring the four dimensions a research panel cares
about, over a labelled scenario corpus (data/golden/scenarios.json):

  * Hallucination rate   - fraction of verdicts carrying grounding flags
                           (fabricated evidence IDs / unverified hops).
  * Precision / Recall   - verdict vs ground-truth label, with a special
                           zero-day slice (novel TTPs absent from any
                           rule/regex baseline -> only semantic engines
                           can catch them).
  * Inference latency    - p50/p95 per investigation + per ReAct turn.
  * Calibration          - Brier score of risk_score against labels.

"Self-correcting": every run writes an auto-generated improvement
suggestion block (e.g. hallucination hot-spots -> prompt hardening TODO)
into the JSON report, and exits non-zero if thresholds regress, so CI
gates on quality, not just test passage.
"""
from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.brain.react_agent import ReActCorrelationEngine          # noqa: E402
from src.brain.tools.log_store_tool import LogStore               # noqa: E402
from src.core.llm_backend import LocalLLMBackend                  # noqa: E402
from src.parser.zero_shot_parser import ZeroShotParser            # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("logagent.eval")

THRESHOLDS = {"hallucination_rate_max": 0.30, "precision_min": 0.60,
              "recall_min": 0.60, "p95_latency_ms_max": 15000}


def load_scenarios(path: Path) -> List[Dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)["scenarios"]


def evaluate(scenarios: List[Dict], backend: str,
             model_id: str) -> Dict:
    llm = LocalLLMBackend(model_id=model_id, backend=backend)
    parser = ZeroShotParser(llm=llm)

    tp = fp = fn = tn = 0
    z_tp = z_fp = z_fn = 0                      # zero-day slice
    halluc_verses = 0
    latencies: List[float] = []
    turn_latencies: List[float] = []
    brier_terms: List[float] = []
    failures: List[Dict] = []

    for sc in scenarios:
        events = parser.parse_batch(sc["raw_lines"])
        store = LogStore()
        store.ingest(events)
        alert_idx = sc.get("alert_index", len(events) - 1)
        engine = ReActCorrelationEngine(store=store, llm=llm, max_steps=6)
        verdict = engine.investigate(events[alert_idx])

        pred, truth = verdict.is_malicious, sc["label_malicious"]
        if pred and truth:
            tp += 1
        elif pred and not truth:
            fp += 1
        elif not pred and truth:
            fn += 1
            failures.append({"scenario": sc["id"], "type": "false_negative"})
        else:
            tn += 1
        if sc.get("zero_day"):
            z_tp += int(pred and truth)
            z_fp += int(pred and not truth)
            z_fn += int(not pred and truth)

        if verdict.hallucination_flags:
            halluc_verses += 1
        latencies.append(verdict.total_latency_ms)
        turn_latencies.extend(s.latency_ms for s in verdict.react_trace)
        brier_terms.append((verdict.risk_score - float(truth)) ** 2)

    n = len(scenarios)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    z_prec = z_tp / (z_tp + z_fp) if (z_tp + z_fp) else 0.0
    z_rec = z_tp / (z_tp + z_fn) if (z_tp + z_fn) else 0.0
    report = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "backend": backend, "model": model_id, "n_scenarios": n,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3),
        "zero_day": {"precision": round(z_prec, 3),
                     "recall": round(z_rec, 3), "support": z_tp + z_fn},
        "hallucination_rate": round(halluc_verses / n, 3) if n else 0.0,
        "latency_ms": {
            "p50": round(statistics.median(latencies), 1) if latencies else 0,
            "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 1)
                   if latencies else 0,
            "mean_turn": round(statistics.mean(turn_latencies), 1)
                         if turn_latencies else 0,
        },
        "brier_calibration_score": round(
            statistics.mean(brier_terms), 4) if brier_terms else None,
        "failures": failures,
    }
    report["suggestions"] = _self_correct(report)
    report["gate_passed"] = _gate(report)
    return report


def _self_correct(r: Dict) -> List[str]:
    """Auto-generated improvement ledger (the 'self-correcting' loop)."""
    s = []
    if r["hallucination_rate"] > THRESHOLDS["hallucination_rate_max"]:
        s.append("HARDEN PROMPT: raise citation strictness & add few-shot "
                 "grounded examples; consider lowering temperature to 0.")
    if r["recall"] < THRESHOLDS["recall_min"]:
        s.append("RECALL GAP: expand ATTACK_KB signals and increase "
                 "max_steps so the agent gathers more context before ruling.")
    if r["precision"] < THRESHOLDS["precision_min"]:
        s.append("PRECISION GAP: raise risk calibration penalty weight per "
                 "hallucination flag; require >=2 techniques for malicious.")
    if r["zero_day"]["support"] and r["zero_day"]["recall"] < 0.7:
        s.append("ZERO-DAY WEAKNESS: enable threat-intel retrieval tool and "
                 "increase ReAct budget for novel-TTP scenarios.")
    if not s:
        s.append("No regressions detected. Freeze this prompt/config hash.")
    return s


def _gate(r: Dict) -> bool:
    return (r["hallucination_rate"] <= THRESHOLDS["hallucination_rate_max"]
            and r["precision"] >= THRESHOLDS["precision_min"]
            and r["recall"] >= THRESHOLDS["recall_min"]
            and r["latency_ms"]["p95"] <= THRESHOLDS["p95_latency_ms_max"])


def main() -> int:
    ap = argparse.ArgumentParser(description="LogAgent-SOC CyberMetric benchmark")
    ap.add_argument("--scenarios", default="data/golden/scenarios.json")
    ap.add_argument("--backend", default="heuristic",
                    help="ollama|vllm|hf|heuristic")
    ap.add_argument("--model", default="qwen2.5:3b")
    ap.add_argument("--out", default="reports/cybermetric_latest.json")
    args = ap.parse_args()

    scenarios = load_scenarios(ROOT / args.scenarios)
    report = evaluate(scenarios, args.backend, args.model)

    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    log.info("Report written to %s | gate_passed=%s", out_path, report["gate_passed"])
    return 0 if report["gate_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
