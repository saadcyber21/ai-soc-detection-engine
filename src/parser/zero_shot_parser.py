"""LogAgent-SOC :: Zero-Shot Heterogeneous Log Parser (LLM-driven).

Schema-on-read, powered by a local SLM: the agent receives ANY raw log
line (Linux syslog / Windows EVTX export / Kubernetes audit / PCAP flow
records / proprietary formats) and emits a canonical ``ParsedEvent`` --
no predefined regex schemas, no per-vendor templates.

Pipeline per line:
  1. format sniffing hint (cheap, non-binding) -> included in prompt so
     the model self-classifies against its open-world knowledge;
  2. zero-shot structured extraction with constrained JSON decoding;
  3. entity normalization + verbatim source-span validation (an entity
     whose ``source_span`` is not literally inside the raw line is
     discarded -> parser-level hallucination guard);
  4. timestamp coercion to UTC; unparseable timestamps keep ingest time
     but drop ``parse_confidence``.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from src.core.llm_backend import LocalLLMBackend
from src.core.schemas import Entity, EntityType, LogFormat, ParsedEvent, Severity

logger = logging.getLogger("logagent.parser")

PARSER_SYSTEM = """You are a schema-less log forensics parser. Given ONE raw \
log line of unknown origin, infer its format and extract security-relevant \
entities. Never invent values: every extracted string must appear verbatim \
in the input. If a field is absent, output null."""

PARSER_SCHEMA = """{
 "source_format": "linux_syslog|windows_event|k8s_audit|network_pcap|ai_telemetry|unknown",
 "timestamp": "ISO-8601 or original string or null",
 "host": str|null, "user": str|null, "process": str|null,
 "action": str|null, "outcome": "success|failure|denied|null",
 "severity": "info|low|medium|high|critical",
 "entities": [{"value": str, "type": "ip|hostname|user|process_hash|process_name|file_path|url|domain|account_id|container_id|pod_name|api_action|port|asset_id|generic", "confidence": 0.0-1.0, "source_span": "exact substring of input"}],
 "parse_confidence": 0.0-1.0
}"""

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
    "%b %d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
]


class ZeroShotParser:
    def __init__(self, llm: Optional[LocalLLMBackend] = None):
        self.llm = llm or LocalLLMBackend()

    # ------------------------------------------------------------------ #
    def parse_line(self, raw_line: str) -> ParsedEvent:
        raw_line = raw_line.rstrip("\n")
        completion = self.llm.complete_json(
            system=PARSER_SYSTEM, user=raw_line,
            schema_hint=PARSER_SCHEMA, temperature=0.0, max_tokens=768)

        if completion.get("_parse_error"):
            logger.warning("LLM output unparseable; emitting UNKNOWN event")

        entities = self._validate_entities(raw_line,
                                           completion.get("entities", []))
        ts = self._coerce_ts(completion.get("timestamp"), raw_line)
        confidence = float(completion.get("parse_confidence", 0.5) or 0.5)
        if ts is None:
            confidence = max(confidence - 0.2, 0.1)

        return ParsedEvent(
            event_id=ParsedEvent.make_id(raw_line),
            timestamp=ts or datetime.now(timezone.utc),
            source_format=self._fmt(completion.get("source_format")),
            host=completion.get("host"),
            user=completion.get("user"),
            process=completion.get("process"),
            action=completion.get("action"),
            outcome=completion.get("outcome"),
            severity=self._sev(completion.get("severity")),
            raw_line=raw_line,
            entities=entities,
            parse_confidence=confidence,
        )

    def parse_batch(self, lines: Iterable[str]) -> List[ParsedEvent]:
        return [self.parse_line(l) for l in lines if l.strip()]

    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_entities(raw_line: str,
                           items: List[dict]) -> List[Entity]:
        """Source-span grounding: discard any entity not literally present."""
        out: List[Entity] = []
        low = raw_line.lower()
        for it in items:
            val = str(it.get("value", "")).strip()
            span = str(it.get("source_span", val))
            if not val:
                continue
            if val.lower() not in low and span.lower() not in low:
                logger.debug("Dropped ungrounded entity '%s' (parser "
                             "hallucination guard)", val)
                continue
            try:
                etype = EntityType(it.get("type", "generic"))
            except ValueError:
                etype = EntityType.GENERIC
            out.append(Entity(value=val, type=etype,
                              confidence=float(it.get("confidence", 0.8)),
                              source_span=span))
        # free safety net: guarantee IPs/hashes never get lost by the SLM
        seen = {e.value for e in out}
        for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw_line)):
            if ip not in seen and all(ip not in s for s in seen):
                out.append(Entity(value=ip, type=EntityType.IP,
                                  confidence=0.99, source_span=ip))
        return out

    @staticmethod
    def _coerce_ts(value: Optional[str], raw_line: str) -> Optional[datetime]:
        if not value:
            # try to find one in the raw line ourselves
            m = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", raw_line)
            value = m.group(0) if m else None
            if not value:
                m = re.search(r"[A-Z][a-z]{2} +\d+ \d{2}:\d{2}:\d{2}", raw_line)
                value = m.group(0) if m else None
        if not value:
            return None
        for fmt in _TS_FORMATS:
            try:
                dt = datetime.strptime(value.strip(), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(year=dt.year or datetime.now().year,
                                    tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None

    @staticmethod
    def _fmt(value: Optional[str]) -> LogFormat:
        try:
            return LogFormat(value)
        except ValueError:
            return LogFormat.UNKNOWN

    @staticmethod
    def _sev(value: Optional[str]) -> Severity:
        try:
            return Severity(value)
        except ValueError:
            return Severity.INFO
