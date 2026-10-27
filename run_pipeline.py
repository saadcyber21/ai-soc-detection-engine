"""LogAgent-SOC :: End-to-end multi-agent pipeline runner.

    raw logs ──▶ ZeroShotParser ──▶ LogStore ──▶ ReActCorrelationEngine
                                                        │
                                                        ▼
                                              XAIForensicsReporter (Markdown)

Usage:
    python run_pipeline.py --input data/raw_logs/mixed_attack.log \
                           --alert-contains "session opened"
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.brain.react_agent import ReActCorrelationEngine   # noqa: E402
from src.brain.tools.log_store_tool import LogStore        # noqa: E402
from src.core.llm_backend import LocalLLMBackend           # noqa: E402
from src.explainability.xai_reporter import XAIForensicsReporter  # noqa: E402
from src.parser.zero_shot_parser import ZeroShotParser     # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("logagent.pipeline")


def main() -> int:
    ap = argparse.ArgumentParser("LogAgent-SOC pipeline")
    ap.add_argument("--input", default="data/raw_logs/mixed_attack.log")
    ap.add_argument("--alert-contains", default="session opened",
                    help="substring identifying the alert line to investigate")
    ap.add_argument("--backend", default="auto")
    ap.add_argument("--model", default=None)
    ap.add_argument("--max-steps", type=int, default=8)
    args = ap.parse_args()

    lines = [l for l in Path(args.input).read_text(encoding="utf-8").splitlines()
             if l.strip()]
    llm = LocalLLMBackend(model_id=args.model, backend=args.backend)

    log.info("[1/4] Zero-shot parsing %d heterogeneous lines…", len(lines))
    events = ZeroShotParser(llm=llm).parse_batch(lines)

    log.info("[2/4] Ingesting into forensic store…")
    store = LogStore()
    store.ingest(events)

    alerts = [e for e in events if args.alert_contains.lower() in e.raw_line.lower()]
    if not alerts:
        log.error("No event matched --alert-contains=%r", args.alert_contains)
        return 2

    log.info("[3/4] Launching ReAct correlation engine on %d alert(s)…", len(alerts))
    engine = ReActCorrelationEngine(store=store, llm=llm,
                                    max_steps=args.max_steps)
    reporter = XAIForensicsReporter(store=store)
    for alert in alerts:
        verdict = engine.investigate(alert)
        path = reporter.write_report(verdict)
        log.info("VERDICT %s malicious=%s risk=%.2f flags=%d report=%s",
                 verdict.incident_id, verdict.is_malicious,
                 verdict.risk_score, len(verdict.hallucination_flags), path)
    log.info("[4/4] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
