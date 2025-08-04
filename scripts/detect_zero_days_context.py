#!/usr/bin/env python3
"""
Context-Enhanced Zero-Day Detection Script
Uses massive context collection for improved LLM performance
"""
import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from src.scraping.context_enhanced_scraper import ContextEnhancedScraper
from src.utils.feature_extractor import ZeroDayFeatureExtractor
from src.ensemble.multi_agent import MultiAgentSystem
from src.agents.forensic import ForensicAnalyst
from src.agents.pattern import PatternDetector
from src.agents.temporal import TemporalAnalyst
from src.agents.attribution import AttributionExpert
from src.agents.meta import MetaAnalyst

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ContextEnhancedDetector:
    """Enhanced detector that leverages massive context for better detection"""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the context-enhanced detection system"""
        # Load configuration
        if config_path and config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            config = self._load_default_config()
        
        # Initialize components
        self.scraper = ContextEnhancedScraper()
        self.feature_extractor = ZeroDayFeatureExtractor()
        
        # Initialize LLM agents with context-aware configs
        self.agents = self._initialize_agents(config.get('agents', {}))
        self.llm_system = MultiAgentSystem(use_thompson_sampling=True, parallel_execution=True)
        
        # Load thresholds
        self.thresholds = config.get('detection_thresholds', {
            'HIGH': 0.50,
            'MEDIUM': 0.45,
            'LOW': 0.40,
            'VERY_LOW': 0.65
        })
        
        self.detection_threshold = config.get('default_threshold', 0.50)
        
    def _load_default_config(self) -> Dict:
        """Load default configuration with optimized thresholds"""
        config_path = Path(__file__).parent.parent / 'config' / 'optimized_thresholds.json'
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        return {
            'detection_thresholds': {
                'default': 0.50,
                'by_confidence': {
                    'HIGH': 0.50,
                    'MEDIUM': 0.45,
                    'LOW': 0.40,
                    'VERY_LOW': 0.65
                }
            }
        }
    
    def _initialize_agents(self, agent_configs: Dict) -> List:
        """Initialize agents with context-aware configurations"""
        agents = []
        
        # Create each agent - they don't take configs in constructor
        agents.append(ForensicAnalyst())
        agents.append(PatternDetector())
        agents.append(TemporalAnalyst())
        agents.append(AttributionExpert())
        agents.append(MetaAnalyst())
        
        return agents
    
    def detect_zero_day(self, cve_id: str, verbose: bool = False) -> Dict[str, Any]:
        """
        Detect if a CVE is a zero-day with enhanced context
        """
        logger.info(f"Starting context-enhanced detection for {cve_id}")
        start_time = time.time()
        
        # Step 1: Collect evidence with massive context
        if verbose:
            print(f"\n🔍 Collecting enhanced evidence for {cve_id}...")
        
        evidence = self.scraper.scrape_all_sources_context_enhanced(cve_id)
        
        if verbose:
            self._display_context_summary(evidence)
        
        # Step 2: Extract features
        if verbose:
            print("\n📊 Extracting features from evidence...")
        
        features = self.feature_extractor.extract_features(cve_id, evidence)
        
        # Step 3: Analyze with LLMs using enhanced context
        if verbose:
            print("\n🤖 Analyzing with LLM agents (with extended context)...")
        
        # Build context-rich prompt for LLMs
        llm_context = self._build_context_rich_prompt(cve_id, evidence, features)
        llm_result = self.llm_system.analyze_vulnerability(llm_context, verbose=verbose)
        
        # Step 4: Calculate detection score with context awareness
        detection_score = self._calculate_context_aware_score(features, llm_result, evidence)
        
        # Step 5: Calculate confidence with context quality
        confidence = self._calculate_context_confidence(detection_score, features, llm_result, evidence)
        
        # Get confidence level and threshold
        confidence_level = self._get_confidence_level(confidence)
        threshold = self._get_dynamic_threshold(confidence_level)
        
        # Make detection decision
        is_zero_day = detection_score >= threshold
        
        # Prepare result with context metrics
        result = {
            'cve_id': cve_id,
            'is_zero_day': is_zero_day,
            'detection_score': detection_score,
            'confidence': confidence,
            'confidence_level': confidence_level,
            'threshold_used': threshold,
            'evidence_summary': self._summarize_context_evidence(features, evidence),
            'context_metrics': self._calculate_context_metrics(evidence),
            'agent_consensus': llm_result.get('ensemble', {}).get('agreement', 0),
            'key_indicators': self._extract_key_indicators(features, evidence),
            'detection_time': time.time() - start_time
        }
        
        # Save detection report
        self._save_detection_report(result, evidence, llm_result)
        
        if verbose:
            self._display_context_result(result)
        
        return result
    
    def _build_context_rich_prompt(self, cve_id: str, evidence: Dict, features: Dict) -> Dict:
        """Build a context-rich prompt for LLM analysis"""
        context = evidence.get('extended_context', {})
        
        # Prepare massive context for LLMs
        llm_context = {
            'cve_id': cve_id,
            'basic_evidence': {
                'nvd': evidence.get('sources', {}).get('nvd', {}),
                'cisa_kev': evidence.get('sources', {}).get('cisa_kev', {}),
                'exploit_db': evidence.get('sources', {}).get('exploit_db', {}),
                'threat_intel': evidence.get('sources', {}).get('threat_intel', {})
            },
            'extended_evidence': {
                'government_alerts': evidence.get('sources', {}).get('government_alerts', {}),
                'security_researchers': evidence.get('sources', {}).get('security_researchers', {}),
                'honeypot_data': evidence.get('sources', {}).get('honeypot_data', {}),
                'social_media': evidence.get('sources', {}).get('social_media', {})
            },
            'code_context': {
                'vulnerable_code': context.get('code_analysis', {}).get('vulnerable_code_snippets', []),
                'patch_analysis': context.get('patch_details', {}).get('patch_commits', []),
                'poc_implementations': context.get('code_analysis', {}).get('poc_implementations', [])
            },
            'discussion_context': {
                'technical_discussions': context.get('full_discussions', {}).get('stackoverflow_threads', []),
                'reddit_threads': context.get('full_discussions', {}).get('reddit_discussions', []),
                'mailing_lists': context.get('full_discussions', {}).get('mailing_lists', []),
                'total_comments': context.get('full_discussions', {}).get('total_comments', 0)
            },
            'historical_context': {
                'similar_vulnerabilities': context.get('historical_vulns', {}).get('similar_cves', []),
                'vendor_history': context.get('historical_vulns', {}).get('vendor_history', []),
                'vulnerability_trends': context.get('historical_vulns', {}).get('vulnerability_trends', {})
            },
            'technical_context': {
                'documentation': context.get('documentation', {}),
                'configurations': context.get('configurations', {}),
                'deployment_guides': context.get('deployment_guides', {}),
                'architecture_info': context.get('deployment_guides', {}).get('architecture_diagrams', [])
            },
            'exploitation_context': {
                'exploit_tutorials': context.get('exploit_tutorials', {}).get('tutorials', []),
                'attack_patterns': context.get('attack_patterns', {}),
                'forensic_evidence': context.get('forensic_evidence', {}),
                'incident_reports': context.get('incident_analysis', {}).get('incident_reports', [])
            },
            'mitigation_context': {
                'official_mitigations': context.get('mitigations', {}).get('official_mitigations', []),
                'workarounds': context.get('mitigations', {}).get('workarounds', []),
                'security_advisories': context.get('security_advisories', {})
            },
            'features': features,
            'context_quality_score': self._calculate_context_quality(evidence)
        }
        
        return llm_context
    
    def _calculate_context_aware_score(self, features: Dict[str, float], 
                                     llm_result: Dict[str, Any],
                                     evidence: Dict[str, Any]) -> float:
        """Calculate detection score with context awareness"""
        # Base calculation similar to enhanced detector
        feature_score = 0.0
        
        # Critical positive indicators
        if features.get('in_cisa_kev', 0) > 0:
            feature_score += 0.25
            if features.get('rapid_kev_addition', 0) > 0:
                feature_score += 0.15
        
        if features.get('exploitation_before_patch', 0) > 0:
            feature_score += 0.25
        
        # Context-enhanced indicators
        context = evidence.get('extended_context', {})
        
        # Code evidence (very strong signal)
        if context.get('code_analysis', {}).get('poc_implementations'):
            feature_score += 0.20
        elif context.get('code_analysis', {}).get('vulnerable_code_snippets'):
            feature_score += 0.10
        
        # Exploit tutorials (strong signal)
        if context.get('exploit_tutorials', {}).get('tutorials'):
            feature_score += 0.15
        
        # Rich discussions with high engagement
        if context.get('full_discussions', {}).get('total_comments', 0) > 50:
            feature_score += 0.10
        elif context.get('full_discussions', {}).get('total_comments', 0) > 20:
            feature_score += 0.05
        
        # Historical pattern matching
        similar_cves = context.get('historical_vulns', {}).get('similar_cves', [])
        if similar_cves:
            # Check if similar CVEs were zero-days
            similar_zd_count = sum(1 for cve in similar_cves[:5] if 'rapid' in str(cve).lower() or 'emergency' in str(cve).lower())
            if similar_zd_count >= 3:
                feature_score += 0.10
        
        # Incident reports
        if context.get('incident_analysis', {}).get('incident_reports'):
            feature_score += 0.15
        
        # Negative indicators
        if features.get('coordinated_disclosure', 0) > 0:
            feature_score -= 0.15
        
        if features.get('bug_bounty_report', 0) > 0:
            feature_score -= 0.20
        
        # Normalize
        feature_score = max(0, min(1, feature_score))
        
        # LLM ensemble score
        llm_score = llm_result.get('ensemble', {}).get('prediction', 0.5)
        
        # Context quality bonus
        context_quality = self._calculate_context_quality(evidence)
        
        # Combine with context-aware weights
        combined_score = (
            0.40 * feature_score +      # Slightly less weight on features
            0.35 * llm_score +          # LLMs get good context
            0.25 * context_quality      # Context quality matters
        )
        
        return combined_score
    
    def _calculate_context_confidence(self, detection_score: float, 
                                    features: Dict[str, float],
                                    llm_result: Dict[str, Any],
                                    evidence: Dict[str, Any]) -> float:
        """Calculate confidence considering context richness"""
        # Base confidence
        distance_confidence = abs(detection_score - self.detection_threshold) * 2
        
        # LLM agreement
        agreement = llm_result.get('ensemble', {}).get('agreement', 0.5)
        
        # Context quality
        context_quality = self._calculate_context_quality(evidence)
        
        # Context coverage (how many sources had rich data)
        context = evidence.get('extended_context', {})
        context_coverage = sum(1 for k, v in context.items() if v and not isinstance(v, dict) or (isinstance(v, dict) and len(v) > 0)) / 15
        
        # Combined confidence
        confidence = (
            0.25 * distance_confidence + 
            0.25 * agreement + 
            0.25 * context_quality +
            0.25 * context_coverage
        )
        
        return min(1.0, confidence)
    
    def _calculate_context_quality(self, evidence: Dict) -> float:
        """Calculate quality score based on context richness"""
        quality = 0.0
        context = evidence.get('extended_context', {})
        
        # Check each context type
        quality_factors = {
            'code_analysis': 0.15,
            'full_discussions': 0.10,
            'patch_details': 0.10,
            'documentation': 0.05,
            'exploit_tutorials': 0.15,
            'historical_vulns': 0.10,
            'incident_analysis': 0.10,
            'technical_blogs': 0.05,
            'attack_patterns': 0.10,
            'mitigations': 0.05,
            'security_advisories': 0.05
        }
        
        for factor, weight in quality_factors.items():
            if factor in context:
                data = context[factor]
                if isinstance(data, dict):
                    # Check if dict has meaningful content
                    has_content = any(v for v in data.values() if v and (not isinstance(v, list) or len(v) > 0))
                    if has_content:
                        quality += weight
                elif isinstance(data, list) and len(data) > 0:
                    quality += weight
        
        return min(1.0, quality)
    
    def _calculate_context_metrics(self, evidence: Dict) -> Dict:
        """Calculate metrics about the context collected"""
        context = evidence.get('extended_context', {})
        
        metrics = {
            'total_context_sources': len(context),
            'sources_with_data': sum(1 for v in context.values() if v and len(str(v)) > 100),
            'code_snippets': len(context.get('code_analysis', {}).get('vulnerable_code_snippets', [])) + 
                           len(context.get('code_analysis', {}).get('poc_implementations', [])),
            'discussion_comments': context.get('full_discussions', {}).get('total_comments', 0),
            'similar_cves': len(context.get('historical_vulns', {}).get('similar_cves', [])),
            'documentation_pages': context.get('documentation', {}).get('total_pages', 0),
            'exploit_resources': len(context.get('exploit_tutorials', {}).get('tutorials', [])),
            'patch_commits': len(context.get('patch_details', {}).get('patch_commits', [])),
            'context_quality_score': self._calculate_context_quality(evidence)
        }
        
        return metrics
    
    def _summarize_context_evidence(self, features: Dict, evidence: Dict) -> Dict:
        """Summarize evidence including context"""
        base_summary = {
            'sources_checked': len(evidence.get('sources', {})) + len(evidence.get('extended_context', {})),
            'sources_with_data': sum(1 for v in evidence.get('sources', {}).values() if v and not (isinstance(v, dict) and v.get('error'))) +
                               sum(1 for v in evidence.get('extended_context', {}).values() if v and len(str(v)) > 100),
            'cisa_kev': evidence.get('sources', {}).get('cisa_kev', {}).get('in_kev', False),
            'has_code_context': bool(evidence.get('extended_context', {}).get('code_analysis', {}).get('vulnerable_code_snippets')),
            'has_exploit_tutorials': bool(evidence.get('extended_context', {}).get('exploit_tutorials', {}).get('tutorials')),
            'discussion_volume': evidence.get('extended_context', {}).get('full_discussions', {}).get('total_comments', 0),
            'historical_patterns': len(evidence.get('extended_context', {}).get('historical_vulns', {}).get('similar_cves', [])),
            'has_incident_reports': bool(evidence.get('extended_context', {}).get('incident_analysis', {}).get('incident_reports'))
        }
        
        return base_summary
    
    def _extract_key_indicators(self, features: Dict, evidence: Dict) -> List[str]:
        """Extract key indicators including context-based ones"""
        indicators = []
        
        # Base indicators
        if features.get('in_cisa_kev'):
            indicators.append("Listed in CISA KEV")
        
        if features.get('rapid_kev_addition'):
            indicators.append("Rapid KEV addition (<7 days)")
        
        if features.get('exploitation_before_patch'):
            indicators.append("Exploitation before patch")
        
        # Context indicators
        context = evidence.get('extended_context', {})
        
        if context.get('code_analysis', {}).get('poc_implementations'):
            indicators.append(f"PoC implementations found: {len(context['code_analysis']['poc_implementations'])}")
        
        if context.get('exploit_tutorials', {}).get('tutorials'):
            indicators.append(f"Exploit tutorials available: {len(context['exploit_tutorials']['tutorials'])}")
        
        if context.get('full_discussions', {}).get('total_comments', 0) > 50:
            indicators.append(f"High community engagement: {context['full_discussions']['total_comments']} comments")
        
        if context.get('incident_analysis', {}).get('incident_reports'):
            indicators.append("Real incident reports available")
        
        if context.get('patch_details', {}).get('lines_changed', 0) > 100:
            indicators.append(f"Large patch: {context['patch_details']['lines_changed']} lines changed")
        
        return indicators
    
    def _display_context_summary(self, evidence: Dict):
        """Display summary of collected context"""
        print("\n📚 Context Collection Summary:")
        
        # Base sources
        base_sources = evidence.get('sources', {})
        print(f"  Base sources: {len(base_sources)}")
        
        # Extended context
        context = evidence.get('extended_context', {})
        print(f"  Extended sources: {len(context)}")
        
        # Specific context details
        if context:
            code_data = context.get('code_analysis', {})
            discussions = context.get('full_discussions', {})
            
            print("\n  📄 Documentation & Code:")
            print(f"    - Code snippets: {len(code_data.get('vulnerable_code_snippets', [])) + len(code_data.get('poc_implementations', []))}")
            print(f"    - Patch commits: {len(context.get('patch_details', {}).get('patch_commits', []))}")
            print(f"    - Config examples: {len(context.get('configurations', {}).get('config_examples', []))}")
            
            print("\n  💬 Discussions & Analysis:")
            print(f"    - Total comments: {discussions.get('total_comments', 0)}")
            print(f"    - Stack Overflow: {len(discussions.get('stackoverflow_threads', []))} threads")
            print(f"    - Reddit: {len(discussions.get('reddit_discussions', []))} discussions")
            print(f"    - Technical blogs: {len(context.get('technical_blogs', {}).get('blog_posts', []))}")
            
            print("\n  🔍 Security Context:")
            print(f"    - Similar CVEs: {len(context.get('historical_vulns', {}).get('similar_cves', []))}")
            print(f"    - Exploit tutorials: {len(context.get('exploit_tutorials', {}).get('tutorials', []))}")
            print(f"    - Incident reports: {len(context.get('incident_analysis', {}).get('incident_reports', []))}")
    
    def _display_context_result(self, result: Dict):
        """Display enhanced detection result"""
        print(f"\n{'='*60}")
        print(f"🎯 DETECTION RESULT: {'ZERO-DAY DETECTED' if result['is_zero_day'] else 'NOT A ZERO-DAY'}")
        print(f"{'='*60}")
        
        print(f"\n📊 Detection Score: {result['detection_score']:.2%}")
        print(f"   Confidence: {result['confidence']:.2%} ({result['confidence_level']})")
        print(f"   Agent Consensus: {result['agent_consensus']:.2%}")
        
        # Context metrics
        metrics = result.get('context_metrics', {})
        print(f"\n📚 Context Metrics:")
        print(f"   Total sources: {metrics.get('total_context_sources', 0)}")
        print(f"   Code snippets: {metrics.get('code_snippets', 0)}")
        print(f"   Discussion volume: {metrics.get('discussion_comments', 0)} comments")
        print(f"   Similar CVEs analyzed: {metrics.get('similar_cves', 0)}")
        print(f"   Context quality: {metrics.get('context_quality_score', 0):.2%}")
        
        print(f"\n🔍 Key Indicators ({len(result['key_indicators'])}):")
        for indicator in result['key_indicators']:
            print(f"   • {indicator}")
        
        print(f"\n⏱️  Detection time: {result['detection_time']:.2f}s")
    
    def _save_detection_report(self, result: Dict, evidence: Dict, llm_result: Dict):
        """Save comprehensive detection report"""
        report = {
            'detection_result': result,
            'llm_analysis': llm_result,
            'context_collected': {
                'base_sources': len(evidence.get('sources', {})),
                'extended_sources': len(evidence.get('extended_context', {})),
                'total_data_size': len(json.dumps(evidence))
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Save to file
        report_dir = Path('detection_reports')
        report_dir.mkdir(exist_ok=True)
        
        filename = f"{result['cve_id']}_context_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = report_dir / filename
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Detection report saved to {report_path}")
    
    def _get_confidence_level(self, confidence: float) -> str:
        """Get confidence level category"""
        if confidence >= 0.8:
            return 'HIGH'
        elif confidence >= 0.6:
            return 'MEDIUM'
        elif confidence >= 0.4:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def _get_dynamic_threshold(self, confidence_level: str) -> float:
        """Get threshold based on confidence level"""
        return self.thresholds.get(confidence_level, self.detection_threshold)


def main():
    parser = argparse.ArgumentParser(description='Context-Enhanced Zero-Day Detection')
    parser.add_argument('cve_id', help='CVE ID to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-c', '--config', type=Path, help='Configuration file path')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = ContextEnhancedDetector(config_path=args.config)
    
    # Run detection
    result = detector.detect_zero_day(args.cve_id, verbose=args.verbose)
    
    # Return appropriate exit code
    sys.exit(0 if result['is_zero_day'] else 1)


if __name__ == "__main__":
    main()