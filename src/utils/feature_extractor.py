"""
Feature extraction for zero-day detection based on measurable metrics
Replaces hardcoded CVE database with objective features
"""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import numpy as np
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


class ZeroDayFeatureExtractor:
    """
    Extract objective, measurable features from CVE data and evidence
    for zero-day likelihood assessment
    """
    
    def __init__(self):
        """Initialize feature extractor"""
        self.feature_names = []
        self.feature_weights = {}  # To be learned from data, not hardcoded
        
    def extract_temporal_features(self, evidence: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract temporal features from disclosure timeline
        
        Returns:
            Dictionary of temporal features
        """
        features = {}
        
        # Get key dates
        nvd_data = evidence.get('sources', {}).get('nvd', {})
        kev_data = evidence.get('sources', {}).get('cisa_kev', {})
        github_data = evidence.get('sources', {}).get('github', {})
        
        disclosure_date = self._parse_date(nvd_data.get('published_date'))
        
        # Feature 1: Time to KEV addition (days)
        if kev_data.get('in_kev') and kev_data.get('date_added'):
            kev_date = self._parse_date(kev_data['date_added'])
            if disclosure_date and kev_date:
                days_to_kev = (kev_date - disclosure_date).days
                features['days_to_kev'] = float(days_to_kev)
                features['rapid_kev_addition'] = 1.0 if days_to_kev <= 7 else 0.0
            else:
                features['days_to_kev'] = -1.0  # Missing data
                features['rapid_kev_addition'] = 0.0
        else:
            features['days_to_kev'] = -1.0
            features['rapid_kev_addition'] = 0.0
            
        # Feature 2: PoC emergence velocity
        if github_data.get('poc_count', 0) > 0 and github_data.get('first_poc_date'):
            first_poc_date = self._parse_date(github_data['first_poc_date'])
            if disclosure_date and first_poc_date:
                days_to_poc = (first_poc_date - disclosure_date).days
                features['days_to_first_poc'] = float(days_to_poc)
                features['rapid_poc_emergence'] = 1.0 if days_to_poc <= 3 else 0.0
            else:
                features['days_to_first_poc'] = -1.0
                features['rapid_poc_emergence'] = 0.0
        else:
            features['days_to_first_poc'] = -1.0
            features['rapid_poc_emergence'] = 0.0
            
        # Feature 3: Patch timeline
        if nvd_data.get('patch_available_date'):
            patch_date = self._parse_date(nvd_data['patch_available_date'])
            if disclosure_date and patch_date:
                patch_delta = (patch_date - disclosure_date).days
                features['patch_delta_days'] = float(patch_delta)
                features['patch_before_disclosure'] = 1.0 if patch_delta < 0 else 0.0
            else:
                features['patch_delta_days'] = 0.0
                features['patch_before_disclosure'] = 0.0
        else:
            features['patch_delta_days'] = 0.0
            features['patch_before_disclosure'] = 0.0
            
        return features
    
    def extract_evidence_features(self, evidence: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features from collected evidence
        
        Returns:
            Dictionary of evidence-based features
        """
        features = {}
        
        # CISA KEV presence
        features['in_cisa_kev'] = 1.0 if evidence.get('sources', {}).get('cisa_kev', {}).get('in_kev') else 0.0
        
        # GitHub PoC metrics
        github_data = evidence.get('sources', {}).get('github', {})
        poc_count = github_data.get('poc_count', 0)
        features['poc_count'] = float(poc_count)
        features['has_many_pocs'] = 1.0 if poc_count > 50 else 0.0
        features['poc_count_log'] = float(np.log1p(poc_count))  # Log scale for count
        
        # News and media coverage
        news_data = evidence.get('sources', {}).get('security_news', {})
        features['news_mentions'] = float(news_data.get('total_mentions', 0))
        features['zero_day_news_mentions'] = float(news_data.get('zero_day_mentions', 0))
        features['news_coverage_ratio'] = (
            features['zero_day_news_mentions'] / max(1, features['news_mentions'])
        )
        
        # APT associations
        apt_groups = evidence.get('indicators', {}).get('apt_associations', [])
        features['apt_group_count'] = float(len(apt_groups))
        features['has_apt_association'] = 1.0 if len(apt_groups) > 0 else 0.0
        
        # Threat intelligence
        threat_intel = evidence.get('sources', {}).get('threat_intelligence', {})
        features['in_threat_intel'] = 1.0 if threat_intel.get('found') else 0.0
        features['campaign_count'] = float(len(threat_intel.get('campaigns', [])))
        
        # Exploitation indicators
        indicators = evidence.get('indicators', {})
        features['exploitation_before_patch'] = 1.0 if indicators.get('exploitation_before_patch') else 0.0
        features['emergency_patches'] = 1.0 if indicators.get('emergency_patches') else 0.0
        features['ransomware_used'] = 1.0 if indicators.get('ransomware_campaigns') else 0.0
        
        # Disclosure type
        features['coordinated_disclosure'] = 1.0 if indicators.get('coordinated_disclosure') else 0.0
        features['vendor_acknowledged'] = 1.0 if indicators.get('vendor_acknowledgment') else 0.0
        
        return features
    
    def extract_nlp_features(self, evidence: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract NLP-based features from text descriptions
        
        Returns:
            Dictionary of NLP features
        """
        features = {}
        
        # Keywords in descriptions
        nvd_desc = evidence.get('sources', {}).get('nvd', {}).get('description', '').lower()
        
        zero_day_keywords = [
            'actively exploited', 'in the wild', 'zero-day', '0-day',
            'before patch', 'unpatched', 'discovered through exploitation'
        ]
        
        research_keywords = [
            'discovered by', 'reported by', 'found by', 'research',
            'responsible disclosure', 'coordinated', 'bug bounty'
        ]
        
        # Count keyword occurrences
        features['zero_day_keyword_count'] = sum(
            1 for keyword in zero_day_keywords if keyword in nvd_desc
        )
        features['research_keyword_count'] = sum(
            1 for keyword in research_keywords if keyword in nvd_desc
        )
        
        # Binary features
        features['has_zero_day_keywords'] = 1.0 if features['zero_day_keyword_count'] > 0 else 0.0
        features['has_research_keywords'] = 1.0 if features['research_keyword_count'] > 0 else 0.0
        
        return features
    
    def extract_severity_features(self, evidence: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract severity and impact features
        
        Returns:
            Dictionary of severity features
        """
        features = {}
        
        nvd_data = evidence.get('sources', {}).get('nvd', {})
        
        # CVSS scores
        cvss_score = nvd_data.get('cvss_score', 0.0)
        features['cvss_score'] = float(cvss_score)
        features['is_critical'] = 1.0 if cvss_score >= 9.0 else 0.0
        features['is_high_severity'] = 1.0 if cvss_score >= 7.0 else 0.0
        
        # Exploitability
        features['exploitability_score'] = float(nvd_data.get('exploitability_score', 0.0))
        features['impact_score'] = float(nvd_data.get('impact_score', 0.0))
        
        # Attack complexity
        attack_vector = nvd_data.get('attack_vector', 'UNKNOWN')
        features['network_vector'] = 1.0 if attack_vector == 'NETWORK' else 0.0
        features['low_complexity'] = 1.0 if nvd_data.get('attack_complexity') == 'LOW' else 0.0
        features['no_user_interaction'] = 1.0 if nvd_data.get('user_interaction') == 'NONE' else 0.0
        
        return features
    
    def extract_all_features(self, evidence: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract all features from evidence
        
        Returns:
            Complete feature dictionary
        """
        all_features = {}
        
        # Extract feature groups
        temporal_features = self.extract_temporal_features(evidence)
        evidence_features = self.extract_evidence_features(evidence)
        nlp_features = self.extract_nlp_features(evidence)
        severity_features = self.extract_severity_features(evidence)
        
        # Combine all features
        all_features.update(temporal_features)
        all_features.update(evidence_features)
        all_features.update(nlp_features)
        all_features.update(severity_features)
        
        # Add metadata
        all_features['feature_count'] = float(len(all_features))
        all_features['missing_features'] = float(sum(1 for v in all_features.values() if v == -1.0))
        
        return all_features
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime object"""
        if not date_str:
            return None
            
        # Try common date formats
        formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%fZ'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str.split('T')[0], '%Y-%m-%d')
            except:
                continue
                
        return None
    
    def calculate_feature_importance(self, features: Dict[str, float], 
                                   ground_truth: Optional[bool] = None) -> Dict[str, float]:
        """
        Calculate feature importance scores
        
        Args:
            features: Extracted features
            ground_truth: True label if available
            
        Returns:
            Feature importance scores
        """
        importance = {}
        
        # Critical features for zero-day detection
        critical_features = {
            'in_cisa_kev': 0.8,
            'rapid_kev_addition': 0.7,
            'exploitation_before_patch': 0.9,
            'has_apt_association': 0.6,
            'emergency_patches': 0.7
        }
        
        # Negative indicators
        negative_features = {
            'coordinated_disclosure': -0.6,
            'has_research_keywords': -0.5,
            'has_many_pocs': -0.4,
            'patch_before_disclosure': -0.7
        }
        
        # Calculate importance
        for feature, value in features.items():
            if feature in critical_features and value > 0:
                importance[feature] = critical_features[feature]
            elif feature in negative_features and value > 0:
                importance[feature] = negative_features[feature]
            else:
                importance[feature] = 0.1  # Default low importance
                
        return importance
    
    def get_feature_vector(self, evidence: Dict[str, Any]) -> np.ndarray:
        """
        Get feature vector for ML models
        
        Returns:
            Numpy array of features
        """
        features = self.extract_all_features(evidence)
        
        # Ensure consistent ordering
        if not self.feature_names:
            self.feature_names = sorted(features.keys())
            
        # Create vector
        vector = np.zeros(len(self.feature_names))
        for i, name in enumerate(self.feature_names):
            vector[i] = features.get(name, 0.0)
            
        return vector