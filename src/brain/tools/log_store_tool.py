"""LogAgent-SOC :: In-memory forensic log store (ReAct tool substrate).

A tiny columnar store over ``ParsedEvent`` objects supporting the
structured queries the agent is allowed to issue.  Deliberately not SQL:
constraining the agent to a closed query grammar is itself an
anti-hallucination measure — the agent can only ask questions the store
can factually answer, and every observation cites real event IDs.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from src.core.schemas import ParsedEvent

logger = logging.getLogger("logagent.store")


class LogStore:
    def __init__(self) -> None:
        self._events: Dict[str, ParsedEvent] = {}

    # ------------------------------------------------------------------ #
    def ingest(self, events: List[ParsedEvent]) -> int:
        for ev in events:
            self._events[ev.event_id] = ev
        logger.info("LogStore now holds %d events", len(self._events))
        return len(self._events)

    def get(self, event_id: str) -> Optional[ParsedEvent]:
        return self._events.get(event_id)

    @property
    def all_events(self) -> List[ParsedEvent]:
        return sorted(self._events.values(), key=lambda e: e.timestamp)

    # ------------------------------------------------------------------ #
    def query(self, *, host: Optional[str] = None, user: Optional[str] = None,
              ip: Optional[str] = None, outcome: Optional[str] = None,
              process: Optional[str] = None,
              window_minutes: int = 1440,
              around: Optional[datetime] = None,
              limit: int = 25) -> List[ParsedEvent]:
        """Structured search with a time window anchored on the alert."""
        anchor = around or datetime.now(timezone.utc)
        lo, hi = anchor - timedelta(minutes=window_minutes), anchor + timedelta(minutes=window_minutes)
        out: List[ParsedEvent] = []
        for ev in self.all_events:
            if not (lo <= ev.timestamp <= hi):
                continue
            if host and (ev.host or "") != host and host not in ev.raw_line:
                continue
            if user and (ev.user or "").lower() != user.lower() \
                    and user.lower() not in ev.raw_line.lower():
                continue
            if ip and ip not in ev.entity_values() and ip not in ev.raw_line:
                continue
            if outcome and (ev.outcome or "").lower() != outcome.lower():
                continue
            if process and process.lower() not in (ev.process or "").lower() \
                    and process.lower() not in ev.raw_line.lower():
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return out

    # ------------------------------------------------------------------ #
    def neighbours(self, event: ParsedEvent) -> List[ParsedEvent]:
        """Events sharing any entity with ``event`` within +/-60 min —
        the primitive that lets the agent trace attacker movement."""
        ents = {e.value for e in event.entities}
        lo = event.timestamp - timedelta(minutes=60)
        hi = event.timestamp + timedelta(minutes=60)
        hits = []
        for ev in self.all_events:
            if ev.event_id == event.event_id or not (lo <= ev.timestamp <= hi):
                continue
            if ents & {e.value for e in ev.entities}:
                hits.append(ev)
        return hits

    def format_observation(self, events: List[ParsedEvent], max_rows: int = 10) -> str:
        """Render query results as the Observation block of the ReAct loop.

        Every line is prefixed with its event_id so the LLM must cite
        evidence by ID — later, the hallucination checker verifies each
        cited ID actually exists and contains the claimed substring.
        """
        if not events:
            return "NO_MATCHES (0 rows). Do not invent data; report absence."
        rows = []
        for ev in events[:max_rows]:
            rows.append(
                f"[{ev.event_id}] {ev.timestamp.isoformat()} "
                f"host={ev.host or '?'} user={ev.user or '?'} "
                f"outcome={ev.outcome or '?'} :: {ev.raw_line[:180]}"
            )
        more = f"\n... ({len(events) - max_rows} more rows truncated)" \
            if len(events) > max_rows else ""
        return "\n".join(rows) + more
