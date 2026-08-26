import json
import logging
import os
from typing import List, Dict, Any

from dotenv import load_dotenv

# Load environment configurations securely
load_dotenv()

# Configure structured logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Import our modular rules and integration
from rules.prompt_injection import PromptInjectionRule
from rules.shadow_ai_dlp import ShadowAIDLPRule
from integrations.alerting import AlertIntegration

class DetectionEngine:
    """Core engine that reads AI telemetry and evaluates it against security rules."""

    def __init__(self):
        # Load configurations from environment variables
        self.telemetry_path = os.getenv("TELEMETRY_LOG_PATH", "data/sample_telemetry.json")
        alert_channel = os.getenv("ALERT_CHANNEL", "console")
        
        # Initialize rules and integrations
        self.rules = [PromptInjectionRule(), ShadowAIDLPRule()]
        self.alerter = AlertIntegration(channel=alert_channel)

    def load_telemetry(self) -> List[Dict[str, Any]]:
        """Safely loads telemetry data from the local JSON file."""
        if not os.path.exists(self.telemetry_path):
            logging.error(f"Telemetry file not found at {self.telemetry_path}")
            return []
            
        try:
            with open(self.telemetry_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON telemetry: {e}")
            return []
        except IOError as e:
            logging.error(f"IOError reading telemetry file: {e}")
            return []

    def run(self) -> None:
        """Executes the detection pipeline across all logs."""
        events = self.load_telemetry()
        logging.info(f"Loaded {len(events)} events for security scanning.")

        for event in events:
            for rule in self.rules:
                is_malicious, reason = rule.evaluate(event)
                
                if is_malicious:
                    # Construct a structured alert payload
                    alert_payload = {
                        "alert_id": f"ALRT-{event.get('event_id')}",
                        "rule_triggered": rule.rule_name,
                        "reason": reason,
                        "user_id": event.get("user_id"),
                        "timestamp": event.get("timestamp"),
                        "action_type": event.get("action_type")
                    }
                    self.alerter.send_alert(alert_payload)

if __name__ == "__main__":
    engine = DetectionEngine()
    engine.run()