import logging
from typing import Dict, Any

class AlertIntegration:
    """Handles routing of triggered security alerts."""
    
    def __init__(self, channel: str = "console"):
        self.channel = channel

    def send_alert(self, alert_payload: Dict[str, Any]) -> None:
        """Dispatches the alert to the configured channel."""
        if self.channel == "console":
            logging.warning(f"SECURITY ALERT TRIGGERED:\n{alert_payload}")
        elif self.channel == "webhook":
            # In production, this would use requests to POST to a SIEM/ticketing system
            logging.info(f"Simulating webhook dispatch for alert: {alert_payload['alert_id']}")