import re
from typing import Dict, Any, Tuple

class ShadowAIDLPRule:
    """Detects Data Loss Prevention (DLP) violations like sensitive secrets in prompts."""
    
    def __init__(self):
        self.rule_name = "Shadow AI / DLP Violation"
        self.patterns = [
            r"(?i)api_key\s*=\s*['\"][a-zA-Z0-9_\-]+['\"]",  # Basic API key pattern
            r"(?i)password\s*=\s*",
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
        ]

    def evaluate(self, event: Dict[str, Any]) -> Tuple[bool, str]:
        if event.get("action_type") != "chat_prompt":
            return False, ""
        
        prompt = event.get("metadata", {}).get("prompt", "")
        
        for pattern in self.patterns:
            if re.search(pattern, prompt):
                return True, f"Matched DLP signature: {pattern}"
                
        return False, ""