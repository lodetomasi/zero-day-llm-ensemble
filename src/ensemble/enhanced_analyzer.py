"""Enhanced analyzer that uses enriched context for better zero-day detection"""
import json
from typing import Dict, List, Optional
from pathlib import Path
import numpy as np
from ..utils.logger import get_logger

logger = get_logger(__name__)

class EnhancedZeroDayAnalyzer:
    """Combines LLM analysis with scraped evidence for better accuracy"""
    
    def __init__(self, multi_agent_system):
        self.multi_agent = multi_agent_system
        self.evidence_cache = {}
        self._load_evidence_cache()
        
    def _load_evidence_cache(self):
        """Load pre-scraped evidence"""
        evidence_dir = Path("data/zero_day_evidence")
        if evidence_dir.exists():
            for evidence_file in evidence_dir.glob("*.json"):
                try:
                    with open(evidence_file, 'r') as f:
                        evidence_data = json.load(f)
                        if isinstance(evidence_data, list):
                            for item in evidence_data:
                                self.evidence_cache[item['cve_id']] = item
                except Exception as e:
                    logger.warning(f"Failed to load evidence from {evidence_file}: {e}")
    
    def analyze_with_context(self, cve_data: Dict) -> Dict:
        """Analyze CVE with both LLM and scraped evidence"""
        cve_id = cve_data.get('cve_id', '')
        
        # Get LLM analysis
        llm_result = self.multi_agent.analyze_vulnerability(cve_data)
        
        # Get scraped evidence if available
        evidence = self.evidence_cache.get(cve_id, {})
        
        # Combine predictions
        enhanced_result = llm_result.copy()
        
        if evidence:
            # Get evidence-based score
            evidence_score = evidence.get('zero_day_score', 0.5)
            
            # Get LLM ensemble prediction
            llm_score = llm_result.get('ensemble', {}).get('prediction', 0.5)
            
            # Weighted combination (can be tuned)
            weights = {
                'llm': 0.6,      # Trust LLM analysis more
                'evidence': 0.4   # But evidence helps
            }
            
            combined_score = (weights['llm'] * llm_score + 
                            weights['evidence'] * evidence_score)
            
            # Add enhanced prediction
            enhanced_result['enhanced'] = {
                'prediction': combined_score,
                'llm_score': llm_score,
                'evidence_score': evidence_score,
                'evidence_sources': evidence.get('scraped_at', 'N/A'),
                'has_cisa_alerts': len(evidence.get('cisa', {}).get('cisa_alerts', [])) > 0,
                'has_github_pocs': evidence.get('github', {}).get('poc_count', 0) > 0,
                'confidence': self._calculate_enhanced_confidence(llm_result, evidence)
            }
            
            # Add key evidence points
            key_evidence = []
            
            # Check CISA alerts
            if evidence.get('cisa', {}).get('cisa_alerts'):
                for alert in evidence['cisa']['cisa_alerts']:
                    if alert.get('zero_day_mentions'):
                        key_evidence.append("CISA alert mentions zero-day exploitation")
                        break
            
            # Check security articles
            security_articles = evidence.get('security_week', [])
            zero_day_articles = [a for a in security_articles if a.get('mentions_zero_day')]
            if zero_day_articles:
                key_evidence.append(f"Security news coverage mentions zero-day ({len(zero_day_articles)} articles)")
            
            # Check GitHub timeline
            if evidence.get('github', {}).get('earliest_poc_date'):
                key_evidence.append("Early exploit PoC on GitHub")
            
            enhanced_result['enhanced']['key_evidence'] = key_evidence
            
        else:
            # No evidence available, use LLM only
            enhanced_result['enhanced'] = {
                'prediction': llm_result.get('ensemble', {}).get('prediction', 0.5),
                'llm_score': llm_result.get('ensemble', {}).get('prediction', 0.5),
                'evidence_score': None,
                'evidence_sources': 'No evidence available',
                'confidence': llm_result.get('ensemble', {}).get('confidence', 0.5)
            }
        
        return enhanced_result
    
    def _calculate_enhanced_confidence(self, llm_result: Dict, evidence: Dict) -> float:
        """Calculate confidence based on agreement between sources"""
        llm_pred = llm_result.get('ensemble', {}).get('prediction', 0.5)
        evidence_score = evidence.get('zero_day_score', 0.5)
        
        # High confidence if sources agree
        agreement = 1.0 - abs(llm_pred - evidence_score)
        
        # Factor in LLM ensemble confidence
        llm_conf = llm_result.get('ensemble', {}).get('confidence', 0.5)
        
        # Combined confidence
        return (agreement * 0.5 + llm_conf * 0.5)

def create_enriched_prompts(cve_data: Dict, evidence: Dict) -> Dict:
    """Create prompts enriched with evidence context"""
    enriched = cve_data.copy()
    
    # Add evidence summary to description
    evidence_summary = []
    
    if evidence.get('cisa', {}).get('cisa_alerts'):
        evidence_summary.append("CISA has issued alerts about this vulnerability.")
    
    if evidence.get('github', {}).get('poc_count', 0) > 0:
        evidence_summary.append(f"There are {evidence['github']['poc_count']} exploit PoCs on GitHub.")
    
    security_articles = evidence.get('security_week', [])
    if security_articles:
        zero_day_mentions = sum(1 for a in security_articles if a.get('mentions_zero_day'))
        if zero_day_mentions > 0:
            evidence_summary.append(f"{zero_day_mentions} security articles mention this as a zero-day.")
    
    if evidence_summary:
        enriched['description'] += f"\n\nAdditional context: {' '.join(evidence_summary)}"
    
    return enriched