"""
Pattern Detector Agent for Zero-Day Detection
"""
from src.agents.base_agent import BaseAgent
from config.settings import AGENT_MODELS


class PatternDetector(BaseAgent):
    """Pattern recognition specialist for zero-day vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            agent_name="PatternDetector",
            model_id=AGENT_MODELS["PatternDetector"]
        )