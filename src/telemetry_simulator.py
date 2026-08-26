import json
import logging
import random
from datetime import datetime, timezone
from typing import Dict, Any

# Configure structured logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class AITelemetrySimulator:
    """Generates simulated JSON telemetry for an AI application."""

    def __init__(self, output_path: str = "data/sample_telemetry.json"):
        self.output_path = output_path
        self.users = ["emp_001", "emp_002", "sys_agent_01"]
        self.actions = ["chat_prompt", "rag_retrieval", "tool_execution"]

    def generate_event(self) -> Dict[str, Any]:
        """Creates a single structured AI log event."""
        action = random.choice(self.actions)
        
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": f"evt_{random.randint(1000, 9999)}",
            "user_id": random.choice(self.users),
            "action_type": action,
            "metadata": {}
        }

        # Simulate different payloads based on the action
        if action == "chat_prompt":
            event["metadata"]["prompt"] = "Summarize the Q3 financial report."
            event["metadata"]["model_response"] = "The Q3 revenue was up by 15%..."
        elif action == "rag_retrieval":
            event["metadata"]["document_id"] = "doc_fin_09"
            event["metadata"]["classification"] = "Internal"
        elif action == "tool_execution":
            event["metadata"]["tool_name"] = "jira_ticket_creation"
            event["metadata"]["status"] = "success"

        return event

    def write_telemetry(self, num_events: int = 5) -> None:
        """Writes a batch of events to the designated JSON file."""
        events = [self.generate_event() for _ in range(num_events)]
        
        try:
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=4)
            logging.info(f"Successfully wrote {num_events} events to {self.output_path}")
        except IOError as e:
            logging.error(f"Failed to write telemetry: {e}")

if __name__ == "__main__":
    simulator = AITelemetrySimulator()
    simulator.write_telemetry()