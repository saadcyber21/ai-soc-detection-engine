import re
from typing import Dict, Any, Tuple

class PromptInjectionRule:
    """Detects common jailbreak and prompt injection attempts in user inputs."""
    
    def __init__(self):
        self.rule_name = "Prompt Injection / Jailbreak Attempt"
        # Enterprise-grade regex patterns for known attack vectors
        self.patterns = [
            r"(?i)ignore\s+all\s+previous\s+instructions",
            r"(?i)system\s+prompt",
            r"(?i)you\s+are\s+now\s+(DAN|unbound|free)",
            r"(?i)forget\s+your\s+rules",
            r"(?i)base64", # Basic encoding evasion detection
        ]

    def evaluate(self, event: Dict[str, Any]) -> Tuple[bool, str]:
        """Evaluates the event payload for prompt injection signatures."""
        if event.get("action_type") != "chat_prompt":
            return False, ""
        
        prompt = event.get("metadata", {}).get("prompt", "")
        
        for pattern in self.patterns:
            if re.search(pattern, prompt):
                return True, f"Matched malicious pattern: {pattern}"
                
        return False, ""