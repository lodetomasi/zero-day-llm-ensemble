"""
Temporal Analyst Agent for Zero-Day Detection
"""
from src.agents.base_agent import BaseAgent
from config.settings import AGENT_MODELS


class TemporalAnalyst(BaseAgent):
    """Temporal analysis expert for zero-day detection"""
    
    def __init__(self):
        super().__init__(
            agent_name="TemporalAnalyst",
            model_id=AGENT_MODELS["TemporalAnalyst"]
        )