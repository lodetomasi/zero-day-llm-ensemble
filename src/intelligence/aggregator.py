"""
Multi-Source Intelligence Aggregation System
Focus on information quality and coverage rather than binary classification
"""
import json
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from pathlib import Path
import logging

from src.utils.feature_extractor import ZeroDayFeatureExtractor
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper
from src.ensemble.multi_agent import MultiAgentSystem

logger = logging.getLogger(__name__)


class IntelligenceAggregator:
    """
    Aggregates intelligence from multiple sources to provide
    comprehensive vulnerability assessment
    """
    
    def __init__(self):
        """Initialize intelligence aggregator"""
        self.scraper = ComprehensiveZeroDayScraper()
        self.feature_extractor = ZeroDayFeatureExtractor()
        self.llm_system = MultiAgentSystem(parallel_execution=True)
        
        # Intelligence quality metrics
        self.quality_weights = {
            'source_coverage': 0.2,
            'information_density': 0.2,
            'temporal_consistency': 0.2,
            'evidence_corroboration': 0.2,
            'analysis_confidence': 0.2
        }
    
    def aggregate_intelligence(self, cve_id: str) -> Dict[str, Any]:
        """
        Aggregate intelligence from all available sources
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Comprehensive intelligence report
        """
        logger.info(f"Aggregating intelligence for {cve_id}")
        
        # Phase 1: Collect raw intelligence
        web_evidence = self.scraper.scrape_all_sources(cve_id)
        
        # Phase 2: Extract objective features
        features = self.feature_extractor.extract_all_features(web_evidence)
        
        # Phase 3: LLM analysis with context
        llm_context = self._build_llm_context(cve_id, web_evidence, features)
        llm_analysis = self.llm_system.analyze_vulnerability(llm_context)
        
        # Phase 4: Calculate intelligence quality metrics
        quality_metrics = self._calculate_quality_metrics(web_evidence, features, llm_analysis)
        
        # Phase 5: Generate structured intelligence report
        intelligence_report = self._generate_intelligence_report(
            cve_id, web_evidence, features, llm_analysis, quality_metrics
        )
        
        return intelligence_report
    
    def _build_llm_context(self, cve_id: str, evidence: Dict[str, Any], 
                          features: Dict[str, float]) -> Dict[str, Any]:
        """Build context for LLM analysis"""
        nvd_data = evidence.get('sources', {}).get('nvd', {})
        
        # Create structured context
        context = {
            'cve_id': cve_id,
            'vendor': nvd_data.get('vendor', 'Unknown'),
            'product': nvd_data.get('product', 'Unknown'),
            'description': self._create_enhanced_description(nvd_data, evidence, features)
        }
        
        return context
    
    def _create_enhanced_description(self, nvd_data: Dict[str, Any], 
                                   evidence: Dict[str, Any], 
                                   features: Dict[str, float]) -> str:
        """Create enhanced description with intelligence context"""
        base_description = nvd_data.get('description', f'No description available')
        
        # Add intelligence summary
        intel_summary = f"""
{base_description}

INTELLIGENCE SUMMARY:
Source Coverage: {self._calculate_source_coverage(evidence):.0%}
Key Features Detected: {sum(1 for v in features.values() if v > 0)}
"""
        
        # Add significant findings
        findings = []
        
        if features.get('in_cisa_kev', 0) > 0:
            findings.append("• Listed in CISA Known Exploited Vulnerabilities catalog")
            
        if features.get('rapid_kev_addition', 0) > 0:
            findings.append("• Added to KEV within 7 days of disclosure")
            
        if features.get('has_apt_association', 0) > 0:
            findings.append("• Associated with APT group activity")
            
        if features.get('exploitation_before_patch', 0) > 0:
            findings.append("• Evidence of exploitation before patch availability")
            
        if findings:
            intel_summary += "\nKEY FINDINGS:\n" + "\n".join(findings)
            
        return intel_summary
    
    def _calculate_source_coverage(self, evidence: Dict[str, Any]) -> float:
        """Calculate percentage of sources with data"""
        sources = evidence.get('sources', {})
        total_sources = len(sources)
        sources_with_data = sum(
            1 for source_data in sources.values() 
            if source_data and any(v for v in source_data.values() if v)
        )
        
        return sources_with_data / max(1, total_sources)
    
    def _calculate_quality_metrics(self, evidence: Dict[str, Any], 
                                 features: Dict[str, float], 
                                 llm_analysis: Dict[str, Any]) -> Dict[str, float]:
        """Calculate intelligence quality metrics"""
        metrics = {}
        
        # Source coverage
        metrics['source_coverage'] = self._calculate_source_coverage(evidence)
        
        # Information density (non-empty features)
        total_features = len(features)
        populated_features = sum(1 for v in features.values() if v != -1.0 and v != 0.0)
        metrics['information_density'] = populated_features / max(1, total_features)
        
        # Temporal consistency
        temporal_features = ['days_to_kev', 'days_to_first_poc', 'patch_delta_days']
        temporal_present = sum(1 for f in temporal_features if features.get(f, -1) != -1)
        metrics['temporal_consistency'] = temporal_present / len(temporal_features)
        
        # Evidence corroboration (multiple sources agree)
        corroboration_score = 0
        if features.get('in_cisa_kev', 0) > 0 and features.get('news_mentions', 0) > 0:
            corroboration_score += 0.5
        if features.get('has_apt_association', 0) > 0 and features.get('in_threat_intel', 0) > 0:
            corroboration_score += 0.5
        metrics['evidence_corroboration'] = corroboration_score
        
        # Analysis confidence from LLM
        ensemble_data = llm_analysis.get('ensemble', {})
        metrics['analysis_confidence'] = ensemble_data.get('confidence', 0.5)
        
        # Overall quality score
        metrics['overall_quality'] = sum(
            metrics[key] * self.quality_weights[key] 
            for key in self.quality_weights
        )
        
        return metrics
    
    def _generate_intelligence_report(self, cve_id: str, evidence: Dict[str, Any],
                                    features: Dict[str, float], llm_analysis: Dict[str, Any],
                                    quality_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Generate comprehensive intelligence report"""
        
        # Feature importance
        feature_importance = self.feature_extractor.calculate_feature_importance(features)
        
        # Top positive and negative indicators
        sorted_features = sorted(feature_importance.items(), key=lambda x: abs(x[1]), reverse=True)
        top_positive = [(f, v) for f, v in sorted_features if v > 0][:5]
        top_negative = [(f, v) for f, v in sorted_features if v < 0][:5]
        
        # Timeline summary
        timeline_events = self._extract_timeline_events(evidence, features)
        
        # Intelligence report
        report = {
            'metadata': {
                'cve_id': cve_id,
                'analysis_timestamp': datetime.now().isoformat(),
                'intelligence_quality_score': quality_metrics['overall_quality'],
                'confidence_level': self._get_confidence_level(quality_metrics['overall_quality'])
            },
            'executive_summary': self._generate_executive_summary(features, quality_metrics),
            'intelligence_sources': {
                'sources_checked': len(evidence.get('sources', {})),
                'sources_with_data': sum(1 for s in evidence.get('sources', {}).values() if s),
                'primary_sources': self._identify_primary_sources(evidence)
            },
            'key_features': {
                'total_extracted': len(features),
                'populated_features': sum(1 for v in features.values() if v != -1.0),
                'critical_indicators': {
                    'positive': top_positive,
                    'negative': top_negative
                }
            },
            'temporal_analysis': {
                'timeline_events': timeline_events,
                'temporal_anomalies': self._identify_temporal_anomalies(features)
            },
            'llm_analysis': {
                'consensus_score': llm_analysis.get('ensemble', {}).get('prediction', 0.5),
                'confidence': llm_analysis.get('ensemble', {}).get('confidence', 0.5),
                'agent_agreement': llm_analysis.get('ensemble', {}).get('agreement', 0.0),
                'key_insights': self._extract_llm_insights(llm_analysis)
            },
            'quality_metrics': quality_metrics,
            'actionable_intelligence': self._generate_actionable_intelligence(features, evidence),
            'limitations': self._identify_limitations(evidence, features, quality_metrics),
            'raw_data': {
                'features': features,
                'evidence_summary': self._summarize_evidence(evidence)
            }
        }
        
        return report
    
    def _get_confidence_level(self, quality_score: float) -> str:
        """Convert quality score to confidence level"""
        if quality_score >= 0.8:
            return "HIGH"
        elif quality_score >= 0.6:
            return "MEDIUM"
        elif quality_score >= 0.4:
            return "LOW"
        else:
            return "VERY_LOW"
    
    def _generate_executive_summary(self, features: Dict[str, float], 
                                  quality_metrics: Dict[str, float]) -> str:
        """Generate executive summary of intelligence"""
        summary_parts = []
        
        # Quality assessment
        quality_level = self._get_confidence_level(quality_metrics['overall_quality'])
        summary_parts.append(f"Intelligence quality: {quality_level}")
        
        # Key findings
        if features.get('in_cisa_kev', 0) > 0:
            summary_parts.append("Listed in CISA KEV catalog")
            
        if features.get('exploitation_before_patch', 0) > 0:
            summary_parts.append("Evidence suggests exploitation before patch")
            
        if features.get('has_apt_association', 0) > 0:
            apt_count = int(features.get('apt_group_count', 0))
            summary_parts.append(f"Associated with {apt_count} APT group(s)")
            
        # Risk indicators
        if features.get('is_critical', 0) > 0 and features.get('network_vector', 0) > 0:
            summary_parts.append("Critical severity with network attack vector")
            
        return ". ".join(summary_parts)
    
    def _identify_primary_sources(self, evidence: Dict[str, Any]) -> List[str]:
        """Identify primary intelligence sources"""
        primary = []
        sources = evidence.get('sources', {})
        
        if sources.get('cisa_kev', {}).get('in_kev'):
            primary.append("CISA KEV")
            
        if sources.get('nvd', {}).get('published_date'):
            primary.append("NVD")
            
        if sources.get('security_news', {}).get('total_mentions', 0) > 0:
            primary.append("Security News")
            
        if sources.get('github', {}).get('poc_count', 0) > 0:
            primary.append("GitHub PoCs")
            
        return primary
    
    def _extract_timeline_events(self, evidence: Dict[str, Any], 
                               features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Extract key timeline events"""
        events = []
        
        # NVD publication
        nvd_date = evidence.get('sources', {}).get('nvd', {}).get('published_date')
        if nvd_date:
            events.append({
                'date': nvd_date,
                'event': 'CVE Published',
                'source': 'NVD'
            })
            
        # KEV addition
        if features.get('in_cisa_kev', 0) > 0:
            kev_date = evidence.get('sources', {}).get('cisa_kev', {}).get('date_added')
            if kev_date:
                events.append({
                    'date': kev_date,
                    'event': 'Added to CISA KEV',
                    'source': 'CISA'
                })
                
        # Sort by date
        events.sort(key=lambda x: x['date'])
        
        return events
    
    def _identify_temporal_anomalies(self, features: Dict[str, float]) -> List[str]:
        """Identify temporal anomalies in the data"""
        anomalies = []
        
        if features.get('rapid_kev_addition', 0) > 0:
            days = features.get('days_to_kev', -1)
            if days >= 0:
                anomalies.append(f"Unusually rapid KEV addition ({days} days)")
                
        if features.get('patch_before_disclosure', 0) > 0:
            anomalies.append("Patch available before public disclosure")
            
        if features.get('days_to_first_poc', -1) == 0:
            anomalies.append("PoC available on disclosure day")
            
        return anomalies
    
    def _extract_llm_insights(self, llm_analysis: Dict[str, Any]) -> List[str]:
        """Extract key insights from LLM analysis"""
        insights = []
        
        ensemble = llm_analysis.get('ensemble', {})
        
        if ensemble.get('agreement', 0) < 0.5:
            insights.append("High disagreement among analysis agents")
            
        if ensemble.get('uncertainty', 0) > 0.7:
            insights.append("High uncertainty in analysis")
            
        quality = ensemble.get('quality_metrics', {})
        if quality.get('decision_margin', 0) < 0.1:
            insights.append("Analysis result very close to decision boundary")
            
        return insights
    
    def _generate_actionable_intelligence(self, features: Dict[str, float], 
                                        evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Generate actionable intelligence recommendations"""
        actions = {
            'priority': 'MEDIUM',
            'recommended_actions': [],
            'monitoring_recommendations': []
        }
        
        # Determine priority
        if features.get('in_cisa_kev', 0) > 0:
            actions['priority'] = 'CRITICAL'
            actions['recommended_actions'].append("Immediate patching required (CISA KEV)")
            
        elif features.get('exploitation_before_patch', 0) > 0:
            actions['priority'] = 'HIGH'
            actions['recommended_actions'].append("Prioritize patching - exploitation detected")
            
        elif features.get('is_critical', 0) > 0 and features.get('network_vector', 0) > 0:
            actions['priority'] = 'HIGH'
            actions['recommended_actions'].append("Critical network-exploitable vulnerability")
            
        # Monitoring recommendations
        if features.get('has_apt_association', 0) > 0:
            actions['monitoring_recommendations'].append("Monitor for APT-related IOCs")
            
        if features.get('poc_count', 0) > 10:
            actions['monitoring_recommendations'].append("Multiple PoCs available - monitor for exploitation attempts")
            
        return actions
    
    def _identify_limitations(self, evidence: Dict[str, Any], features: Dict[str, float],
                            quality_metrics: Dict[str, float]) -> List[str]:
        """Identify limitations in the intelligence"""
        limitations = []
        
        if quality_metrics['source_coverage'] < 0.5:
            limitations.append("Limited source coverage - many sources returned no data")
            
        if quality_metrics['information_density'] < 0.3:
            limitations.append("Low information density - many features could not be extracted")
            
        if features.get('missing_features', 0) > 10:
            limitations.append("Significant missing data points")
            
        if not evidence.get('sources', {}).get('nvd', {}).get('published_date'):
            limitations.append("No official CVE publication date available")
            
        return limitations
    
    def _summarize_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of evidence collected"""
        summary = {}
        
        for source_name, source_data in evidence.get('sources', {}).items():
            if source_data:
                summary[source_name] = {
                    'has_data': bool(any(source_data.values())),
                    'key_findings': self._extract_source_findings(source_name, source_data)
                }
                
        return summary
    
    def _extract_source_findings(self, source_name: str, source_data: Dict[str, Any]) -> List[str]:
        """Extract key findings from a specific source"""
        findings = []
        
        if source_name == 'cisa_kev' and source_data.get('in_kev'):
            findings.append(f"Listed in KEV on {source_data.get('date_added', 'unknown date')}")
            
        elif source_name == 'github' and source_data.get('poc_count', 0) > 0:
            findings.append(f"{source_data['poc_count']} PoC repositories found")
            
        elif source_name == 'security_news' and source_data.get('zero_day_mentions', 0) > 0:
            findings.append(f"{source_data['zero_day_mentions']} articles mention zero-day")
            
        return findings