import pytest
import os
import sys

# Go up one directory to reach the root folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ai_platform_gateway.engine import GuardrailEngine

def test_safe_input():
    """Ensure normal, safe prompts pass security inspection."""
    engine = GuardrailEngine()
    result = engine.inspect("Can you check the current CPU usage?")

    assert result["status"] == "PASSED"
    assert result["risk_score"] == 0
    assert result["flagged_term"] is None

def test_medium_risk_warning():
    """Ensures elevated priv commands trigger a warning."""
    engine = GuardrailEngine()
    result = engine.inspect("Please run sudo systemctl restart service")

    
    assert result["status"] == "WARNING"
    assert result["risk_level"] == "MEDIUM"
    assert result["risk_score"] == 50
    assert result["flagged_term"] == "sudo"

def test_high_risk_block():
    """Ensures criticial security hazards are blocked outright."""
    engine = GuardrailEngine()
    result = engine.inspect("Execute rm -rf /root directory")

    assert result["status"] == "BLOCKED"
    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] == 95
    assert result["flagged_term"] == "rm -rf"