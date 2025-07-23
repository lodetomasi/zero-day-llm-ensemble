"""
Forensic Analyst Agent for Zero-Day Detection
"""
from src.agents.base_agent import BaseAgent
from config.settings import AGENT_MODELS


class ForensicAnalyst(BaseAgent):
    """Digital forensics expert specializing in zero-day vulnerability analysis"""
    
    def __init__(self):
        super().__init__(
            agent_name="ForensicAnalyst",
            model_id=AGENT_MODELS["ForensicAnalyst"]
        )
    
    def analyze(self, cve_data):
        """Analyze CVE with forensic focus"""
        # Add forensic-specific context
        if 'notes' in cve_data and cve_data['notes']:
            # Append notes to description for forensic analysis
            cve_data = cve_data.copy()
            cve_data['description'] = f"{cve_data['description']} Additional notes: {cve_data['notes']}"
        
        return super().analyze(cve_data)