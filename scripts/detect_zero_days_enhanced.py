#!/usr/bin/env python3
"""
Enhanced Zero-Day Detection Script
Uses the enhanced scraper with additional intelligence sources
"""
import argparse
import sys
from pathlib import Path
# Add parent directory to Python path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from src.ensemble.multi_agent import MultiAgentSystem
from src.scraping.enhanced_scraper import EnhancedZeroDayScraper
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper
from src.scraping.smart_cache import get_smart_cache
from src.utils.feature_extractor import ZeroDayFeatureExtractor
from src.utils.logger import get_logger
import json
from datetime import datetime
import numpy as np
from typing import Dict, List, Any

logger = get_logger(__name__)


class EnhancedZeroDayDetector:
    """
    Enhanced zero-day detection with additional intelligence sources
    """
    
    def __init__(self, use_enhanced_scraping: bool = True):
        """Initialize enhanced detector components"""
        # Use enhanced scraper
        self.scraper = EnhancedZeroDayScraper() if use_enhanced_scraping else ComprehensiveZeroDayScraper()
        self.feature_extractor = ZeroDayFeatureExtractor()
        self.llm_system = MultiAgentSystem(parallel_execution=True)
        
        # Smart cache
        self.cache = get_smart_cache()
        
        # Detection thresholds
        self.detection_threshold = 0.65
        self.high_confidence_threshold = 0.8
        self.low_confidence_threshold = 0.4
        
        # Load optimized dynamic thresholds
        self.dynamic_thresholds = self._load_dynamic_thresholds()
        
        logger.info(f"Initialized {'Enhanced' if use_enhanced_scraping else 'Standard'} Zero-Day Detector")
        
    def detect(self, cve_id: str, verbose: bool = False, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Detect if CVE is a zero-day vulnerability with enhanced data
        
        Args:
            cve_id: CVE identifier
            verbose: Show detailed analysis
            force_refresh: Force refresh of cached data
            
        Returns:
            Enhanced detection result with confidence and evidence
        """
        print(f"\n🔍 Analyzing {cve_id} with Enhanced Detection System")
        print("=" * 60)
        
        # Check cache first
        cache_key = f"detection:{cve_id}"
        if not force_refresh:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                print("📦 Using cached analysis (use --force-refresh for new analysis)")
                return cached_result
        
        # Step 1: Collect enhanced evidence
        if verbose:
            print("\n📡 Step 1: Collecting enhanced web evidence...")
            print("   Sources: NVD, CISA, Government Alerts, Security Researchers,")
            print("            Bug Bounty, Honeypots, Threat Intel, and more...")
        
        evidence = self.scraper.scrape_all_sources_enhanced(cve_id)
        
        # Display source summary
        if verbose:
            self._display_source_summary(evidence)
        
        # Step 2: Extract enhanced features
        if verbose:
            print("\n📊 Step 2: Extracting advanced features...")
        
        # Extract base features
        features = self.feature_extractor.extract_all_features(evidence)
        
        # Add advanced features
        advanced_features = evidence.get('advanced_features', {})
        features.update(self._flatten_advanced_features(advanced_features))
        
        if verbose:
            print(f"   Extracted {len(features)} total features")
            print(f"   Including behavioral, social, and economic indicators")
        
        # Step 3: Multi-agent analysis with enhanced context
        if verbose:
            print("\n🤖 Step 3: Running enhanced multi-agent analysis...")
        
        # Build enhanced context for LLMs
        llm_context = self._build_enhanced_llm_context(cve_id, evidence, features)
        llm_result = self.llm_system.analyze_vulnerability(llm_context, verbose=verbose)
        
        # Step 4: Calculate enhanced detection score
        detection_score = self._calculate_enhanced_detection_score(features, llm_result, evidence)
        
        # Step 5: Calculate confidence with quality metrics
        confidence = self._calculate_enhanced_confidence(detection_score, features, llm_result, evidence)
        
        # Get confidence level and threshold
        confidence_level = self._get_confidence_level(confidence)
        threshold = self._get_dynamic_threshold(confidence_level)
        
        # Make detection decision
        is_zero_day = detection_score >= threshold
        
        # Prepare enhanced result
        result = {
            'cve_id': cve_id,
            'is_zero_day': is_zero_day,
            'detection_score': detection_score,
            'confidence': confidence,
            'confidence_level': confidence_level,
            'threshold_used': threshold,
            'evidence_summary': self._summarize_enhanced_evidence(features, evidence),
            'agent_consensus': llm_result.get('ensemble', {}).get('agreement', 0),
            'key_indicators': self._extract_enhanced_indicators(features, evidence),
            'detection_reasoning': self._generate_enhanced_reasoning(is_zero_day, features, evidence),
            'advanced_metrics': {
                'threat_actor_interest': evidence.get('scores', {}).get('threat_actor_interest', 0),
                'exploitation_velocity': evidence.get('scores', {}).get('exploitation_velocity', 0),
                'defensive_gap': evidence.get('scores', {}).get('defensive_gap', 0),
                'data_quality': self._calculate_data_quality(evidence)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Cache result with adaptive TTL
        cache_ttl = self.cache.adaptive_ttl({'cve_id': cve_id, 'is_zero_day': is_zero_day})
        self.cache.set(cache_key, result, {'cve_id': cve_id})
        
        # Display result
        self._display_enhanced_result(result, verbose)
        
        # Save detailed report
        self._save_enhanced_report(cve_id, result, evidence, features, llm_result)
        
        return result
    
    def _build_enhanced_llm_context(self, cve_id: str, evidence: Dict[str, Any], 
                                  features: Dict[str, float]) -> Dict[str, Any]:
        """Build enhanced context for LLM analysis"""
        nvd_data = evidence.get('sources', {}).get('nvd', {})
        
        # Create rich description with all evidence
        description = nvd_data.get('description', 'No description available')
        
        # Add government alerts
        gov_alerts = evidence.get('sources', {}).get('government_alerts', {})
        if gov_alerts.get('alerts'):
            description += f"\n[GOVERNMENT ALERTS: {len(gov_alerts['alerts'])} alerts from {', '.join(gov_alerts.get('countries_alerting', []))}]"
        
        # Add researcher analysis
        researchers = evidence.get('sources', {}).get('security_researchers', {})
        if researchers.get('researcher_posts'):
            description += f"\n[SECURITY RESEARCH: {len(researchers['researcher_posts'])} analyses from top researchers]"
        
        # Add behavioral indicators
        behavioral = evidence.get('advanced_features', {}).get('behavioral', {})
        if behavioral.get('adoption_velocity', 0) > 0.7:
            description += "\n[BEHAVIORAL: Rapid adoption velocity detected]"
        
        # Add all key feature indicators
        if features.get('in_cisa_kev', 0) > 0:
            description += "\n[EVIDENCE: Listed in CISA Known Exploited Vulnerabilities]"
        
        if features.get('rapid_kev_addition', 0) > 0:
            description += "\n[EVIDENCE: Added to KEV within 7 days of disclosure]"
        
        if features.get('exploitation_before_patch', 0) > 0:
            description += "\n[EVIDENCE: Exploitation detected before patch]"
        
        if features.get('has_apt_association', 0) > 0:
            description += f"\n[EVIDENCE: Associated with {int(features.get('apt_group_count', 0))} APT groups]"
        
        # Add honeypot data
        honeypot = evidence.get('sources', {}).get('honeypot_data', {})
        if honeypot.get('honeypot_detections', 0) > 0:
            description += f"\n[HONEYPOT: {honeypot['honeypot_detections']} detections in honeypots]"
        
        # Add threat actor interest
        if evidence.get('scores', {}).get('threat_actor_interest', 0) > 0.5:
            description += "\n[THREAT INTEL: High threat actor interest detected]"
        
        return {
            'cve_id': cve_id,
            'vendor': nvd_data.get('vendor', 'Unknown'),
            'product': nvd_data.get('product', 'Unknown'), 
            'description': description,
            'enriched_context': {
                'government_response': len(gov_alerts.get('countries_alerting', [])),
                'researcher_attention': len(researchers.get('researcher_posts', [])),
                'exploitation_velocity': evidence.get('scores', {}).get('exploitation_velocity', 0),
                'data_quality_score': self._calculate_data_quality(evidence)
            }
        }
    
    def _calculate_enhanced_detection_score(self, features: Dict[str, float], 
                                          llm_result: Dict[str, Any],
                                          evidence: Dict[str, Any]) -> float:
        """Calculate enhanced detection score with all available signals"""
        # Start with base calculation
        feature_score = 0.0
        
        # Critical positive indicators (same as before)
        if features.get('in_cisa_kev', 0) > 0:
            feature_score += 0.25
            if features.get('rapid_kev_addition', 0) > 0:
                feature_score += 0.15
        
        if features.get('exploitation_before_patch', 0) > 0:
            feature_score += 0.25
        
        # APT associations
        if features.get('has_apt_association', 0) > 0:
            apt_count = features.get('apt_group_count', 0)
            feature_score += min(0.15 * apt_count, 0.3)
        
        # Government alerts (new)
        gov_alerts = evidence.get('sources', {}).get('government_alerts', {})
        if len(gov_alerts.get('alerts', [])) > 0:
            feature_score += 0.1
            if len(gov_alerts.get('countries_alerting', [])) > 2:
                feature_score += 0.1
        
        # Security researcher attention (new)
        researchers = evidence.get('sources', {}).get('security_researchers', {})
        if len(researchers.get('researcher_posts', [])) > 0:
            feature_score += 0.05
            if any(p.get('has_poc') for p in researchers.get('researcher_posts', [])):
                feature_score += 0.1
        
        # Honeypot activity (new)
        honeypot = evidence.get('sources', {}).get('honeypot_data', {})
        if honeypot.get('honeypot_detections', 0) > 5:
            feature_score += 0.15
        elif honeypot.get('honeypot_detections', 0) > 0:
            feature_score += 0.1
        
        # Behavioral indicators (new)
        behavioral = evidence.get('advanced_features', {}).get('behavioral', {})
        if behavioral.get('adoption_velocity', 0) > 0.7:
            feature_score += 0.1
        
        # Negative indicators
        if features.get('coordinated_disclosure', 0) > 0:
            feature_score -= 0.15
        
        if features.get('bug_bounty_report', 0) > 0:
            feature_score -= 0.2
        
        if features.get('patch_before_disclosure', 0) > 0:
            feature_score -= 0.15
        
        # Normalize feature score
        feature_score = max(0, min(1, feature_score))
        
        # LLM ensemble score
        llm_score = llm_result.get('ensemble', {}).get('prediction', 0.5)
        
        # Enhanced score from threat intelligence
        threat_score = evidence.get('scores', {}).get('threat_actor_interest', 0)
        
        # Combine scores with weights
        combined_score = (
            0.5 * feature_score + 
            0.35 * llm_score + 
            0.15 * threat_score
        )
        
        return combined_score
    
    def _calculate_enhanced_confidence(self, detection_score: float, 
                                     features: Dict[str, float],
                                     llm_result: Dict[str, Any],
                                     evidence: Dict[str, Any]) -> float:
        """Calculate enhanced confidence with data quality metrics"""
        # Base confidence from score distance
        distance_confidence = abs(detection_score - self.detection_threshold) * 2
        
        # LLM agreement
        agreement = llm_result.get('ensemble', {}).get('agreement', 0.5)
        
        # Data quality score
        data_quality = self._calculate_data_quality(evidence)
        
        # Source diversity bonus
        source_count = len([s for s in evidence.get('sources', {}).values() if s and not isinstance(s, dict) or (isinstance(s, dict) and not s.get('error'))])
        source_diversity = min(source_count / 15, 1.0)  # 15 sources = max diversity
        
        # Combined confidence
        confidence = (
            0.3 * distance_confidence + 
            0.25 * agreement + 
            0.25 * data_quality +
            0.2 * source_diversity
        )
        
        return min(confidence, 1.0)
    
    def _calculate_data_quality(self, evidence: Dict[str, Any]) -> float:
        """Calculate overall data quality score"""
        quality_score = 0.0
        
        # Source reliability
        source_confidence = evidence.get('source_confidence', {})
        if source_confidence:
            avg_confidence = sum(source_confidence.values()) / len(source_confidence)
            quality_score += avg_confidence * 0.3
        
        # Cross-validation bonus
        if evidence.get('cross_validation', {}).get('authoritative_consensus'):
            quality_score += 0.2
        
        # Feature completeness
        sources = evidence.get('sources', {})
        successful_sources = sum(1 for s in sources.values() if s and not (isinstance(s, dict) and s.get('error')))
        completeness = successful_sources / len(sources) if sources else 0
        quality_score += completeness * 0.3
        
        # Temporal freshness
        scraped_at = evidence.get('scraped_at')
        if scraped_at:
            try:
                age_hours = (datetime.now() - datetime.fromisoformat(scraped_at)).total_seconds() / 3600
                freshness = max(0, 1 - (age_hours / 168))  # 1 week = 0 freshness
                quality_score += freshness * 0.2
            except:
                pass
        
        return min(quality_score, 1.0)
    
    def _flatten_advanced_features(self, advanced_features: Dict[str, Any]) -> Dict[str, float]:
        """Flatten nested advanced features into flat feature dict"""
        flat_features = {}
        
        # Behavioral features
        behavioral = advanced_features.get('behavioral', {})
        flat_features['adoption_velocity'] = behavioral.get('adoption_velocity', 0)
        flat_features['geographic_concentration'] = 1.0 if behavioral.get('geographic_distribution', {}).get('concentration') == 'GLOBAL' else 0.0
        
        # Social features
        social = advanced_features.get('social', {})
        flat_features['twitter_mentions'] = min(social.get('twitter_metrics', {}).get('mention_count', 0) / 100, 1.0)
        flat_features['infosec_concern'] = 1.0 if social.get('infosec_community', {}).get('community_concern_level') == 'HIGH' else 0.0
        
        # Technical depth
        technical = advanced_features.get('technical_depth', {})
        flat_features['exploit_complexity'] = technical.get('exploit_complexity', 0.5)
        flat_features['mitigation_difficulty'] = technical.get('mitigation_difficulty', 0.3)
        
        # Economic features
        economic = advanced_features.get('economic', {})
        flat_features['high_value_targets'] = 1.0 if economic.get('business_disruption_level') == 'HIGH' else 0.0
        
        return flat_features
    
    def _display_source_summary(self, evidence: Dict[str, Any]):
        """Display summary of data sources"""
        sources = evidence.get('sources', {})
        print(f"\n📋 Source Collection Summary:")
        
        for source_name, data in sources.items():
            if data and not (isinstance(data, dict) and data.get('error')):
                status = "✅"
                extra = ""
                
                # Add source-specific info
                if source_name == 'government_alerts':
                    alerts = len(data.get('alerts', []))
                    if alerts > 0:
                        extra = f" ({alerts} alerts)"
                elif source_name == 'security_researchers':
                    posts = len(data.get('researcher_posts', []))
                    if posts > 0:
                        extra = f" ({posts} analyses)"
                elif source_name == 'honeypot_data':
                    detections = data.get('honeypot_detections', 0)
                    if detections > 0:
                        extra = f" ({detections} detections)"
                        
            else:
                status = "❌"
                extra = ""
            
            print(f"   {status} {source_name.replace('_', ' ').title()}{extra}")
    
    def _summarize_enhanced_evidence(self, features: Dict[str, float], 
                                   evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize enhanced evidence"""
        summary = {
            'sources_checked': len(evidence.get('sources', {})),
            'sources_with_data': sum(1 for s in evidence.get('sources', {}).values() 
                                   if s and not (isinstance(s, dict) and s.get('error'))),
            'cisa_kev': features.get('in_cisa_kev', 0) > 0,
            'government_alerts': len(evidence.get('sources', {}).get('government_alerts', {}).get('countries_alerting', [])),
            'researcher_analyses': len(evidence.get('sources', {}).get('security_researchers', {}).get('researcher_posts', [])),
            'apt_groups': int(features.get('apt_group_count', 0)),
            'honeypot_activity': evidence.get('sources', {}).get('honeypot_data', {}).get('honeypot_detections', 0) > 0,
            'exploitation_evidence': features.get('exploitation_before_patch', 0) > 0,
            'poc_repositories': int(features.get('poc_count', 0)),
            'data_quality_score': self._calculate_data_quality(evidence)
        }
        return summary
    
    def _extract_enhanced_indicators(self, features: Dict[str, float],
                                   evidence: Dict[str, Any]) -> List[str]:
        """Extract enhanced key indicators"""
        indicators = []
        
        # Government response
        gov_alerts = evidence.get('sources', {}).get('government_alerts', {})
        if gov_alerts.get('countries_alerting'):
            countries = ', '.join(gov_alerts['countries_alerting'])
            indicators.append(f"Government alerts: {countries}")
        
        # CISA KEV
        if features.get('in_cisa_kev', 0) > 0:
            indicators.append("Listed in CISA KEV")
            if features.get('rapid_kev_addition', 0) > 0:
                indicators.append("Rapid KEV addition (<7 days)")
        
        # Researcher attention
        researchers = evidence.get('sources', {}).get('security_researchers', {})
        if len(researchers.get('researcher_posts', [])) > 2:
            indicators.append(f"High researcher attention ({len(researchers['researcher_posts'])} analyses)")
        
        # Exploitation evidence
        if features.get('exploitation_before_patch', 0) > 0:
            indicators.append("Exploitation before patch")
        
        # Honeypot activity
        honeypot = evidence.get('sources', {}).get('honeypot_data', {})
        if honeypot.get('honeypot_detections', 0) > 0:
            indicators.append(f"Honeypot detections: {honeypot['honeypot_detections']}")
        
        # APT activity
        if features.get('has_apt_association', 0) > 0:
            indicators.append(f"APT association ({int(features['apt_group_count'])} groups)")
        
        # Behavioral indicators
        behavioral = evidence.get('advanced_features', {}).get('behavioral', {})
        if behavioral.get('adoption_velocity', 0) > 0.7:
            indicators.append("Rapid exploitation adoption")
        
        if behavioral.get('geographic_distribution', {}).get('concentration') == 'GLOBAL':
            indicators.append("Global exploitation campaign")
        
        # Threat actor interest
        if evidence.get('scores', {}).get('threat_actor_interest', 0) > 0.5:
            indicators.append("High threat actor interest")
        
        return indicators
    
    def _generate_enhanced_reasoning(self, is_zero_day: bool, 
                                   features: Dict[str, float],
                                   evidence: Dict[str, Any]) -> str:
        """Generate enhanced reasoning with additional context"""
        if is_zero_day:
            reasoning = "Detected as zero-day based on: "
            reasons = []
            
            # Government response
            gov_countries = evidence.get('sources', {}).get('government_alerts', {}).get('countries_alerting', [])
            if gov_countries:
                reasons.append(f"government alerts from {len(gov_countries)} countries")
            
            if features.get('in_cisa_kev', 0) > 0:
                reasons.append("CISA KEV listing")
            
            if features.get('exploitation_before_patch', 0) > 0:
                reasons.append("pre-patch exploitation")
            
            honeypot = evidence.get('sources', {}).get('honeypot_data', {})
            if honeypot.get('honeypot_detections', 0) > 5:
                reasons.append("significant honeypot activity")
            
            if features.get('has_apt_association', 0) > 0:
                reasons.append("APT group activity")
            
            # Add confidence context
            data_quality = self._calculate_data_quality(evidence)
            if data_quality > 0.8:
                reasons.append("high-quality corroborating evidence")
            
            reasoning += ", ".join(reasons) if reasons else "multiple strong indicators"
        else:
            reasoning = "Not detected as zero-day due to: "
            reasons = []
            
            if features.get('coordinated_disclosure', 0) > 0:
                reasons.append("coordinated disclosure")
            
            if features.get('bug_bounty_report', 0) > 0:
                reasons.append("bug bounty program")
            
            if evidence.get('sources', {}).get('security_researchers', {}).get('responsible_disclosure'):
                reasons.append("responsible disclosure by researchers")
            
            if not evidence.get('sources', {}).get('government_alerts', {}).get('alerts'):
                reasons.append("no government alerts")
            
            reasoning += ", ".join(reasons) if reasons else "insufficient evidence"
        
        return reasoning
    
    def _display_enhanced_result(self, result: Dict[str, Any], verbose: bool):
        """Display enhanced detection result"""
        print(f"\n{'='*60}")
        print(f"🎯 DETECTION RESULT: {'ZERO-DAY DETECTED' if result['is_zero_day'] else 'NOT A ZERO-DAY'}")
        print(f"{'='*60}")
        
        print(f"\n📊 Detection Score: {result['detection_score']:.2%}")
        print(f"   Confidence: {result['confidence']:.2%} ({result['confidence_level']})")
        print(f"   Agent Consensus: {result['agent_consensus']:.2%}")
        print(f"   Data Quality: {result['advanced_metrics']['data_quality']:.2%}")
        
        print(f"\n🔍 Key Indicators ({len(result['key_indicators'])}):")
        for indicator in result['key_indicators'][:8]:  # Show top 8
            print(f"   • {indicator}")
        
        if verbose and result.get('advanced_metrics'):
            print(f"\n📈 Advanced Metrics:")
            metrics = result['advanced_metrics']
            print(f"   Threat Actor Interest: {metrics['threat_actor_interest']:.2%}")
            print(f"   Exploitation Velocity: {metrics['exploitation_velocity']:.2%}")
            print(f"   Defensive Gap: {metrics['defensive_gap']:.2%}")
        
        print(f"\n💭 Reasoning: {result['detection_reasoning']}")
        
        if verbose:
            print(f"\n📋 Evidence Summary:")
            summary = result['evidence_summary']
            print(f"   Sources analyzed: {summary['sources_with_data']}/{summary['sources_checked']}")
            print(f"   Government alerts: {summary['government_alerts']} countries")
            print(f"   Researcher analyses: {summary['researcher_analyses']}")
            print(f"   Honeypot activity: {'Yes' if summary['honeypot_activity'] else 'No'}")
            print(f"   Data quality: {summary['data_quality_score']:.2%}")
    
    def _save_enhanced_report(self, cve_id: str, result: Dict[str, Any], 
                            evidence: Dict[str, Any], features: Dict[str, float],
                            llm_result: Dict[str, Any]):
        """Save enhanced detection report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = Path('detection_reports')
        output_dir.mkdir(exist_ok=True)
        
        report = {
            'detection_result': result,
            'features_extracted': features,
            'llm_analysis': llm_result,
            'evidence_sources': {
                'sources_checked': len(evidence.get('sources', {})),
                'sources_with_data': sum(1 for s in evidence.get('sources', {}).values() 
                                       if s and not (isinstance(s, dict) and s.get('error'))),
                'enhanced_sources': [
                    'government_alerts', 'security_researchers', 'bug_bounty',
                    'honeypot_data', 'threat_intel', 'social_media'
                ]
            },
            'advanced_features': evidence.get('advanced_features', {}),
            'data_quality_metrics': {
                'overall_quality': result['advanced_metrics']['data_quality'],
                'source_confidence': evidence.get('source_confidence', {}),
                'cross_validation': evidence.get('cross_validation', {})
            },
            'cache_info': {
                'cache_stats': self.cache.get_stats()
            },
            'timestamp': timestamp
        }
        
        report_file = output_dir / f'{cve_id}_enhanced_detection_{timestamp}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n💾 Enhanced report saved to: {report_file}")
    
    def _load_dynamic_thresholds(self) -> Dict[str, float]:
        """Load optimized thresholds from config"""
        try:
            with open('config/optimized_thresholds.json', 'r') as f:
                config = json.load(f)
                return config['detection_thresholds']['by_confidence']
        except:
            # Fallback to default thresholds
            return {
                'HIGH': 0.70,
                'MEDIUM': 0.83,
                'LOW': 0.67,
                'VERY_LOW': 0.65
            }
    
    def _get_confidence_level(self, confidence: float) -> str:
        """Convert confidence score to level"""
        if confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        elif confidence >= 0.4:
            return "LOW"
        else:
            return "VERY_LOW"
    
    def _get_dynamic_threshold(self, confidence_level: str) -> float:
        """Get threshold based on confidence level"""
        return self.dynamic_thresholds.get(confidence_level, self.detection_threshold)


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Zero-Day Detection with Additional Intelligence Sources'
    )
    parser.add_argument('cve_ids', nargs='+', help='CVE IDs to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Show detailed analysis')
    parser.add_argument('--force-refresh', action='store_true',
                       help='Force refresh of cached data')
    parser.add_argument('--standard', action='store_true',
                       help='Use standard scraper instead of enhanced')
    parser.add_argument('--cache-stats', action='store_true',
                       help='Show cache statistics')
    
    args = parser.parse_args()
    
    print("🚀 Enhanced Zero-Day Detection System")
    print("Multi-Agent LLM Ensemble with Extended Intelligence")
    print("="*60)
    
    # Initialize detector
    detector = EnhancedZeroDayDetector(use_enhanced_scraping=not args.standard)
    
    # Show cache stats if requested
    if args.cache_stats:
        stats = detector.cache.get_stats()
        print("\n📊 Cache Statistics:")
        print(f"   Total requests: {stats['total_requests']}")
        print(f"   Cache hits: {stats['hits']} ({stats['hit_rate']:.1%} hit rate)")
        print(f"   Hot cache size: {stats['hot_cache_size']}")
        print()
    
    results = []
    
    for cve_id in args.cve_ids:
        try:
            result = detector.detect(cve_id, args.verbose, args.force_refresh)
            results.append(result)
        except Exception as e:
            logger.error(f"Error detecting {cve_id}: {e}")
            print(f"\n❌ Error analyzing {cve_id}: {e}")
    
    # Summary for multiple CVEs
    if len(results) > 1:
        print("\n" + "="*60)
        print("📊 DETECTION SUMMARY")
        print("="*60)
        
        zero_days = sum(1 for r in results if r['is_zero_day'])
        print(f"\nTotal CVEs analyzed: {len(results)}")
        print(f"Zero-days detected: {zero_days}")
        print(f"Regular vulnerabilities: {len(results) - zero_days}")
        
        # Calculate average metrics
        avg_confidence = sum(r['confidence'] for r in results) / len(results)
        avg_quality = sum(r['advanced_metrics']['data_quality'] for r in results) / len(results)
        
        print(f"\nAverage confidence: {avg_confidence:.1%}")
        print(f"Average data quality: {avg_quality:.1%}")
        
        print("\nResults:")
        for result in results:
            status = "Zero-day" if result['is_zero_day'] else "Regular"
            print(f"  {result['cve_id']}: {status} "
                  f"(score: {result['detection_score']:.1%}, "
                  f"confidence: {result['confidence_level']}, "
                  f"quality: {result['advanced_metrics']['data_quality']:.1%})")


if __name__ == "__main__":
    main()