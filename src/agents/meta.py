"""
Meta Analyst Agent for Zero-Day Detection
"""
from src.agents.base_agent import BaseAgent
from config.settings import AGENT_MODELS


class MetaAnalyst(BaseAgent):
    """Meta-analysis expert synthesizing multiple zero-day indicators"""
    
    def __init__(self):
        super().__init__(
            agent_name="MetaAnalyst",
            model_id=AGENT_MODELS["MetaAnalyst"]
        )