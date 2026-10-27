"""LogAgent-SOC :: Compact MITRE ATT&CK knowledge base.

A curated, machine-readable subset of ATT&CK (v14-aligned) covering the
techniques an autonomous hunter actually needs to correlate intrusions:
initial access -> credential access -> lateral movement -> exfiltration.

The ReAct agent uses two functions:
  * ``semantic_candidates`` - cheap signal scoring that narrows the search
    space BEFORE asking the LLM (reduces hallucination by grounding the
    model in a closed candidate list).
  * ``validate_technique``  - anti-hallucination guard: any technique_id
    emitted by the LLM must exist here or it is flagged.
"""
from __future__ import annotations

import re
from typing import Dict, List

# technique_id -> {name, tactic, trigger signals}
ATTACK_KB: Dict[str, Dict] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "signals": ["failed", "invalid user", "authentication failure",
                          "4625", "account lockout"]},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion",
              "signals": ["logged in", "4624", "success", "accepted password",
                          "session opened"]},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access",
                  "signals": ["multiple hosts", "same password", "spray"]},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "signals": ["ssh", "rdp", "3389", ":22", "winrm", "5985",
                          "session opened for user"]},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement",
                  "signals": ["rdp", "3389", "terminal services"]},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement",
                  "signals": ["sshd", "authorized_keys", "publickey", ":22"]},
    "T1021.007": {"name": "Cloud Services", "tactic": "Lateral Movement",
                  "signals": ["kubectl", "kube", "serviceaccount", "iam"]},
    "T1570": {"name": "Exploit Remote Services", "tactic": "Lateral Movement",
              "signals": ["eternalblue", "smb", "445", "exploit", "cve-"]},
    "T1550.001": {"name": "Application Access Token", "tactic": "Defense Evasion",
                  "signals": ["token", "bearer", "jwt", "api_key"]},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access",
              "signals": ["mimikatz", "lsass", "sam dump", "ntds.dit",
                          "secretsdump", "credential dump"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",
              "signals": ["powershell", "bash -c", "cmd.exe", "python -c",
                          "/bin/", "encodedcommand"]},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution",
                  "signals": ["powershell", "-enc", "encodedcommand"]},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control",
              "signals": ["http beacon", "dns query", "user-agent", "post /"]},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control",
                  "signals": ["dns", "query name", ".resolve"]},
    "T1048": {"name": "Exfiltration Over Alternative Protocol",
              "tactic": "Exfiltration",
              "signals": ["scp", "rsync", "ftp", "exfil", "large transfer"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "signals": ["bytes_sent", "upload", "outbound large"]},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact",
              "signals": ["ransomware", "encrypt", "readme.txt", "locker"]},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence",
              "signals": ["useradd", "add member", "domain admins",
                          "authorized_keys", "4732", "privileged"]},
    "T1610": {"name": "Deploy Container", "tactic": "Initial Access",
              "signals": ["kubectl exec", "pod created", "docker run", "nsenter"]},
    "T1611": {"name": "Escape to Host", "tactic": "Privilege Escalation",
              "signals": ["nsenter", "--pid=host", "privileged container", "cgroup"]},
    "T1053.003": {"name": "Scheduled Task/Job: Cron", "tactic": "Persistence",
                  "signals": ["cron", "crontab", "(CRON)"]},
}


def semantic_candidates(text: str, top_k: int = 4) -> List[Dict]:
    """Score techniques against raw evidence text (closed-set retrieval).

    The LLM may only choose from candidates returned here, which
    structurally prevents fabricated technique IDs.
    """
    low = text.lower()
    scored = []
    for tid, meta in ATTACK_KB.items():
        hits = sum(1 for s in meta["signals"] if s in low)
        if hits:
            scored.append({"technique_id": tid, "name": meta["name"],
                           "tactic": meta["tactic"], "signals": meta["signals"],
                           "_score": hits})
    scored.sort(key=lambda x: x["_score"], reverse=True)
    return scored[:top_k]


def validate_technique(technique_id: str) -> bool:
    return technique_id in ATTACK_KB


def tactic_of(technique_id: str) -> str:
    return ATTACK_KB.get(technique_id, {}).get("tactic", "Unknown")


def name_of(technique_id: str) -> str:
    return ATTACK_KB.get(technique_id, {}).get("name", "Unknown")


def render_candidate_block(cands: List[Dict]) -> str:
    """Format grounded candidates for prompt injection."""
    lines = [f"- {c['technique_id']}: {c['name']} [{c['tactic']}] "
             f"signals={', '.join(c['signals'])}" for c in cands]
    return "\n".join(lines) if lines else "- (no KB matches; answer 'NONE')"


# Patterns the correlation engine uses to detect host-to-host hops
LATERAL_PATTERNS = [
    (re.compile(r"sshd.*?(?:Accepted|session opened).*?from (\d+\.\d+\.\d+\.\d+)", re.I), "SSH"),
    (re.compile(r"(?:RDP|TerminalServices).*?src[=:] ?(\d+\.\d+\.\d+\.\d+)", re.I), "RDP"),
    (re.compile(r"kubectl\s+exec", re.I), "kubectl exec"),
    (re.compile(r"[Pp]s[Ee]xec", re.I), "SMB/PsExec"),
    (re.compile(r"nsenter", re.I), "container escape"),
]
