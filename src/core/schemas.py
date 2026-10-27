"""LogAgent-SOC :: Canonical Data Contracts (Pydantic v2).

Every subsystem in the pipeline communicates exclusively through these
schemas.  The LLM parser emits ``ParsedEvent`` objects, the ReAct brain
consumes/produces them, and the XAI reporter renders them — a single
schema spine guarantees type safety across agent boundaries.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Entity taxonomy shared by all heterogeneous log sources
# --------------------------------------------------------------------------- #
class EntityType(str, Enum):
    IP = "ip"
    HOSTNAME = "hostname"
    USER = "user"
    PROCESS_HASH = "process_hash"
    PROCESS_NAME = "process_name"
    FILE_PATH = "file_path"
    URL = "url"
    DOMAIN = "domain"
    ACCOUNT_ID = "account_id"
    CONTAINER_ID = "container_id"
    POD_NAME = "pod_name"
    API_ACTION = "api_action"
    PORT = "port"
    ASSET_ID = "asset_id"
    GENERIC = "generic"


class Entity(BaseModel):
    """A normalized security-relevant entity extracted from raw text."""

    value: str
    type: EntityType = EntityType.GENERIC
    confidence: float = Field(0.9, ge=0.0, le=1.0)
    source_span: Optional[str] = None  # exact substring of the raw line


class LogFormat(str, Enum):
    LINUX_SYSLOG = "linux_syslog"
    WINDOWS_EVENT = "windows_event"
    K8S_AUDIT = "k8s_audit"
    NETWORK_PCAP = "network_pcap"
    AI_TELEMETRY = "ai_telemetry"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ParsedEvent(BaseModel):
    """Unified JSON representation of *any* ingested log line.

    This is the schema-less output contract of the Zero-Shot Parser:
    the LLM never invents fields outside this envelope; it maps whatever
    it finds into ``entities``, ``raw_message`` and ``extensions``.
    """

    event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_format: LogFormat = LogFormat.UNKNOWN
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    action: Optional[str] = None            # e.g. "authenticate", "exec", "GET /api"
    outcome: Optional[str] = None           # e.g. "success", "failure", "denied"
    severity: Severity = Severity.INFO
    raw_line: str = ""                       # verbatim evidence — never mutated
    entities: List[Entity] = Field(default_factory=list)
    extensions: Dict[str, Any] = Field(default_factory=dict)
    parse_confidence: float = Field(0.5, ge=0.0, le=1.0)

    @staticmethod
    def make_id(raw_line: str) -> str:
        return "evt_" + hashlib.sha256(raw_line.encode("utf-8", "replace")).hexdigest()[:12]

    def entity_values(self, etype: Optional[EntityType] = None) -> List[str]:
        return sorted({e.value for e in self.entities if etype is None or e.type == etype})


# --------------------------------------------------------------------------- #
# MITRE ATT&CK mapping artifacts
# --------------------------------------------------------------------------- #
class MitreMapping(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    rationale: str
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    supporting_event_ids: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# ReAct brain artifacts
# --------------------------------------------------------------------------- #
class ReActStep(BaseModel):
    """One Thought → Action → Observation turn in the agent loop."""

    step: int
    thought: str
    action: Optional[str] = None
    action_input: Optional[str] = None
    observation: Optional[str] = None
    latency_ms: float = 0.0


class LateralHop(BaseModel):
    ts: datetime
    src: str
    dst: str
    actor: Optional[str] = None
    mechanism: Optional[str] = None   # e.g. "RDP", "psexec", "kubectl exec"
    event_id: str


class InvestigationVerdict(BaseModel):
    """Final output of the Correlation Engine, input to the XAI module."""

    incident_id: str
    alert_summary: str
    is_malicious: bool
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    narrative: str
    mitre_mappings: List[MitreMapping] = Field(default_factory=list)
    lateral_movement: List[LateralHop] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    react_trace: List[ReActStep] = Field(default_factory=list)
    hallucination_flags: List[str] = Field(default_factory=list)
    model_id: str = "local-slm"
    total_latency_ms: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
