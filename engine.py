import json
from datetime import datetime,timezone


class GuardrailEngine:
    """
    An object-oriented security guardrail engine for AI platforms.
    Maintains threat rules and generates structured audit logs.
    """

    def __init__(self, custom_threshold: int = 50):
        # Instance varaibles (the state)
        self.threshold = custom_threshold
        self.threat_database = {
            "HIGH": ["rm -rf", "DROP TABLE", "AWS_SECRET_ACCESS_KEY"],
            "MEDIUM": ["sudo", "chmod 777", "eval("],
            "LOW": ["password", "token", "secret"]
        }

    def inspect(self, user_input:str) -> dict:
        """
        Inspects input, evalutes risk, and formats an audit record.
        """
        clean_input = user_input.lower()
        timestamp = datetime.now(timezone.utc).isoformat()

        # Check HIGH risk
        for keyword in self.threat_database["HIGH"]:
            if keyword.lower() in clean_input:
                record = self._build_record("BLOCKED", "HIGH", 95, keyword, timestamp, user_input)
                self._log_to_file(record)
                return record

        # Check MEDIUM risk
        for keyword in self.threat_database["MEDIUM"]:
            if keyword.lower() in clean_input:
                record = self._build_record("WARNING", "MEDIUM", 50, keyword, timestamp, user_input)
                self._log_to_file(record)
                return record

        # Safe input
        record = self._build_record("PASSED", "LOW", 0, None, timestamp, user_input)
        self._log_to_file(record)
        return record


    def _build_record(self, status: str, risk_level: str, score: int, flagged: str, timestamp: str, original: str) -> dict:
            """
            Construction of audit record.
            """
            if status == "BLOCKED":
                reason = f"Critical security hazard: '{flagged}' detected."
            elif status == "WARNING":
                reason = f"Elevated privilege command: '{flagged}' detected."
            else:
                 reason = f"Input passed all security checks."
            
            return {
                "timestamp": timestamp,
                "status": status,
                "risk_level": risk_level,
                "risk_score": score,
                "flagged_term": flagged,
                "reason": reason,
                "input_preview": original[:30] + "..." if len(original) > 30 else original
            }


    def _log_to_file(self, record: dict, filename: str = "audit.log"):
            """ Append audit record as a json line to a log file."""
            with open(filename, "a") as log_file:
                log_file.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    guardrail = GuardrailEngine()

    test_inputs = [
        "Show me the system CPU metrics.",
        "Please run sudo systemctl restart service",
        "Execute rm -rf /root directory"
    ]

    print("--- RUNNING OOP GUARDRAIL ENGINE")

    for text in test_inputs:
        result = guardrail.inspect(text)
        print(f"[{result['status']}] Risk: {result['risk_level']} | Flagged: {result['flagged_term']}")

    print("\nAudit logs successfully written to 'audit.log'.")
