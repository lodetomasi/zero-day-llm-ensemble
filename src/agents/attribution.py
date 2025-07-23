"""
Attribution Expert Agent for Zero-Day Detection
"""
from src.agents.base_agent import BaseAgent
from config.settings import AGENT_MODELS


class AttributionExpert(BaseAgent):
    """Threat attribution specialist focusing on zero-day usage"""
    
    def __init__(self):
        super().__init__(
            agent_name="AttributionExpert",
            model_id=AGENT_MODELS["AttributionExpert"]
        )