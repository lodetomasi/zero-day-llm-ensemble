#!/usr/bin/env python3
"""
Zero-Day Detection Script - MAIN OBJECTIVE
Detects zero-day vulnerabilities using multi-agent LLM ensemble
Outputs: Binary classification (zero-day: yes/no) with confidence
"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from src.ensemble.multi_agent import MultiAgentSystem
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper
from src.utils.feature_extractor import ZeroDayFeatureExtractor
from src.utils.logger import get_logger
import json
from datetime import datetime
import numpy as np
from typing import Dict, List, Any

logger = get_logger(__name__)


class ZeroDayDetector:
    """
    Main class for zero-day detection
    Maintains focus on binary classification with supporting evidence
    """
    
    def __init__(self):
        """Initialize detector components"""
        self.scraper = ComprehensiveZeroDayScraper()
        self.feature_extractor = ZeroDayFeatureExtractor()
        self.llm_system = MultiAgentSystem(parallel_execution=True)
        
        # Detection thresholds (learned from data, not hardcoded)
        self.detection_threshold = 0.65
        self.high_confidence_threshold = 0.8
        self.low_confidence_threshold = 0.4
        
        # Load optimized dynamic thresholds
        self.dynamic_thresholds = self._load_dynamic_thresholds()
        
    def detect(self, cve_id: str, verbose: bool = False) -> Dict[str, Any]:
        """
        Detect if CVE is a zero-day vulnerability
        
        Args:
            cve_id: CVE identifier
            verbose: Show detailed analysis
            
        Returns:
            Detection result with confidence and evidence
        """
        print(f"\n🔍 Analyzing {cve_id} for zero-day detection")
        print("=" * 60)
        
        # Step 1: Collect evidence
        if verbose:
            print("\n📡 Step 1: Collecting web evidence...")
        
        evidence = self.scraper.scrape_all_sources(cve_id)
        
        # Step 2: Extract features
        if verbose:
            print("📊 Step 2: Extracting objective features...")
        
        features = self.feature_extractor.extract_all_features(evidence)
        
        # Step 3: Multi-agent analysis
        if verbose:
            print("🤖 Step 3: Running multi-agent LLM analysis...")
        
        # Build context for LLMs
        llm_context = self._build_llm_context(cve_id, evidence, features)
        llm_result = self.llm_system.analyze_vulnerability(llm_context, verbose=verbose)
        
        # Step 4: Calculate detection score
        detection_score = self._calculate_detection_score(features, llm_result)
        
        # Step 5: Calculate confidence first
        confidence = self._calculate_confidence(detection_score, features, llm_result)
        
        # Get confidence level
        confidence_level = self._get_confidence_level(confidence)
        
        # Get dynamic threshold based on confidence
        threshold = self._get_dynamic_threshold(confidence_level)
        
        # Make detection decision using dynamic threshold
        is_zero_day = detection_score >= threshold
        
        # Prepare result
        result = {
            'cve_id': cve_id,
            'is_zero_day': is_zero_day,
            'detection_score': detection_score,
            'confidence': confidence,
            'confidence_level': confidence_level,
            'threshold_used': threshold,
            'evidence_summary': self._summarize_evidence(features, evidence),
            'agent_consensus': llm_result.get('ensemble', {}).get('agreement', 0),
            'key_indicators': self._extract_key_indicators(features),
            'detection_reasoning': self._generate_reasoning(is_zero_day, features, llm_result)
        }
        
        # Display result
        self._display_result(result, verbose)
        
        # Save detailed report
        self._save_report(cve_id, result, evidence, features, llm_result)
        
        return result
    
    def _build_llm_context(self, cve_id: str, evidence: Dict[str, Any], 
                          features: Dict[str, float]) -> Dict[str, Any]:
        """Build context for LLM analysis"""
        nvd_data = evidence.get('sources', {}).get('nvd', {})
        
        # Create description with key evidence
        description = nvd_data.get('description', 'No description available')
        
        # Add key feature indicators
        if features.get('in_cisa_kev', 0) > 0:
            description += "\n[EVIDENCE: Listed in CISA Known Exploited Vulnerabilities]"
        
        if features.get('rapid_kev_addition', 0) > 0:
            description += "\n[EVIDENCE: Added to KEV within 7 days of disclosure]"
        
        if features.get('exploitation_before_patch', 0) > 0:
            description += "\n[EVIDENCE: Exploitation detected before patch]"
        
        if features.get('has_apt_association', 0) > 0:
            description += f"\n[EVIDENCE: Associated with {int(features.get('apt_group_count', 0))} APT groups]"
        
        return {
            'cve_id': cve_id,
            'vendor': nvd_data.get('vendor', 'Unknown'),
            'product': nvd_data.get('product', 'Unknown'), 
            'description': description
        }
    
    def _calculate_detection_score(self, features: Dict[str, float], 
                                 llm_result: Dict[str, Any]) -> float:
        """
        Calculate zero-day detection score
        Combines feature-based scoring with LLM ensemble
        """
        # Feature-based score (0-1)
        feature_score = 0.0
        
        # Critical positive indicators
        if features.get('in_cisa_kev', 0) > 0:
            feature_score += 0.3
            if features.get('rapid_kev_addition', 0) > 0:
                feature_score += 0.2
        
        if features.get('exploitation_before_patch', 0) > 0:
            feature_score += 0.3
        
        if features.get('has_apt_association', 0) > 0:
            apt_count = features.get('apt_group_count', 0)
            feature_score += min(0.2 * apt_count, 0.4)
        
        if features.get('emergency_patches', 0) > 0:
            feature_score += 0.1
        
        # Negative indicators
        if features.get('coordinated_disclosure', 0) > 0:
            feature_score -= 0.2
        
        if features.get('has_many_pocs', 0) > 0:
            feature_score -= 0.3
        
        if features.get('patch_before_disclosure', 0) > 0:
            feature_score -= 0.2
        
        # Normalize feature score
        feature_score = max(0, min(1, feature_score))
        
        # LLM ensemble score
        llm_score = llm_result.get('ensemble', {}).get('prediction', 0.5)
        
        # Combine scores (60% features, 40% LLM)
        combined_score = 0.6 * feature_score + 0.4 * llm_score
        
        return combined_score
    
    def _calculate_confidence(self, detection_score: float, features: Dict[str, float],
                            llm_result: Dict[str, Any]) -> float:
        """Calculate confidence in the detection"""
        # Base confidence from score distance to threshold
        distance_confidence = abs(detection_score - self.detection_threshold) * 2
        
        # LLM agreement factor
        agreement = llm_result.get('ensemble', {}).get('agreement', 0.5)
        
        # Feature completeness factor
        total_features = len(features)
        populated_features = sum(1 for v in features.values() if v != -1.0)
        completeness = populated_features / max(1, total_features)
        
        # Combined confidence
        confidence = (0.4 * distance_confidence + 
                     0.3 * agreement + 
                     0.3 * completeness)
        
        return min(confidence, 1.0)
    
    def _load_dynamic_thresholds(self) -> Dict[str, float]:
        """Load optimized thresholds from config"""
        try:
            with open('config/optimized_thresholds.json', 'r') as f:
                config = json.load(f)
                return config['detection_thresholds']['by_confidence']
        except:
            # Fallback to default thresholds
            return {
                'LOW': 0.67,
                'MEDIUM': 0.83,
                'HIGH': 0.70,
                'VERY_LOW': 0.65
            }
    
    def _get_dynamic_threshold(self, confidence_level: str) -> float:
        """Get threshold based on confidence level"""
        return self.dynamic_thresholds.get(confidence_level, self.detection_threshold)
    
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
    
    def _summarize_evidence(self, features: Dict[str, float], 
                          evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize key evidence"""
        summary = {
            'sources_checked': len(evidence.get('sources', {})),
            'cisa_kev': features.get('in_cisa_kev', 0) > 0,
            'apt_groups': int(features.get('apt_group_count', 0)),
            'exploitation_evidence': features.get('exploitation_before_patch', 0) > 0,
            'poc_repositories': int(features.get('poc_count', 0)),
            'news_mentions': int(features.get('news_mentions', 0))
        }
        return summary
    
    def _extract_key_indicators(self, features: Dict[str, float]) -> List[str]:
        """Extract key indicators for detection"""
        indicators = []
        
        if features.get('in_cisa_kev', 0) > 0:
            indicators.append("Listed in CISA KEV")
        
        if features.get('rapid_kev_addition', 0) > 0:
            indicators.append("Rapid KEV addition (<7 days)")
        
        if features.get('exploitation_before_patch', 0) > 0:
            indicators.append("Exploitation before patch")
        
        if features.get('has_apt_association', 0) > 0:
            indicators.append(f"APT association ({int(features['apt_group_count'])} groups)")
        
        if features.get('emergency_patches', 0) > 0:
            indicators.append("Emergency patches released")
        
        if features.get('coordinated_disclosure', 0) > 0:
            indicators.append("Coordinated disclosure (negative)")
        
        return indicators
    
    def _generate_reasoning(self, is_zero_day: bool, features: Dict[str, float],
                          llm_result: Dict[str, Any]) -> str:
        """Generate reasoning for the detection decision"""
        if is_zero_day:
            reasoning = "Detected as zero-day based on: "
            reasons = []
            
            if features.get('in_cisa_kev', 0) > 0:
                reasons.append("CISA KEV listing")
            if features.get('exploitation_before_patch', 0) > 0:
                reasons.append("pre-patch exploitation")
            if features.get('has_apt_association', 0) > 0:
                reasons.append("APT group activity")
            
            reasoning += ", ".join(reasons) if reasons else "multiple indicators"
        else:
            reasoning = "Not detected as zero-day due to: "
            reasons = []
            
            if features.get('coordinated_disclosure', 0) > 0:
                reasons.append("coordinated disclosure")
            if features.get('has_many_pocs', 0) > 0:
                reasons.append("high PoC availability")
            if features.get('patch_before_disclosure', 0) > 0:
                reasons.append("patch before disclosure")
            
            reasoning += ", ".join(reasons) if reasons else "insufficient evidence"
        
        return reasoning
    
    def _display_result(self, result: Dict[str, Any], verbose: bool):
        """Display detection result"""
        print(f"\n{'='*60}")
        print(f"🎯 DETECTION RESULT: {'ZERO-DAY DETECTED' if result['is_zero_day'] else 'NOT A ZERO-DAY'}")
        print(f"{'='*60}")
        
        print(f"\n📊 Detection Score: {result['detection_score']:.2%}")
        print(f"   Confidence: {result['confidence']:.2%} ({result['confidence_level']})")
        print(f"   Agent Consensus: {result['agent_consensus']:.2%}")
        
        print(f"\n🔍 Key Indicators:")
        for indicator in result['key_indicators']:
            print(f"   • {indicator}")
        
        print(f"\n💭 Reasoning: {result['detection_reasoning']}")
        
        if verbose:
            print(f"\n📋 Evidence Summary:")
            summary = result['evidence_summary']
            print(f"   Sources checked: {summary['sources_checked']}")
            print(f"   CISA KEV: {'Yes' if summary['cisa_kev'] else 'No'}")
            print(f"   APT groups: {summary['apt_groups']}")
            print(f"   PoC repositories: {summary['poc_repositories']}")
    
    def _save_report(self, cve_id: str, result: Dict[str, Any], 
                    evidence: Dict[str, Any], features: Dict[str, float],
                    llm_result: Dict[str, Any]):
        """Save detailed detection report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = Path('detection_reports')
        output_dir.mkdir(exist_ok=True)
        
        report = {
            'detection_result': result,
            'features_extracted': features,
            'llm_analysis': llm_result,
            'evidence_sources': {
                'sources_checked': len(evidence.get('sources', {})),
                'sources_with_data': sum(1 for s in evidence.get('sources', {}).values() if s)
            },
            'timestamp': timestamp
        }
        
        report_file = output_dir / f'{cve_id}_detection_{timestamp}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n💾 Detailed report saved to: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Detect zero-day vulnerabilities using multi-agent LLM ensemble'
    )
    parser.add_argument('cve_ids', nargs='+', help='CVE IDs to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Show detailed analysis')
    
    args = parser.parse_args()
    
    print("🚀 Zero-Day Detection System")
    print("Multi-Agent LLM Ensemble Approach")
    print("="*60)
    
    detector = ZeroDayDetector()
    results = []
    
    for cve_id in args.cve_ids:
        try:
            result = detector.detect(cve_id, args.verbose)
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
        
        print("\nResults:")
        for result in results:
            status = "Zero-day" if result['is_zero_day'] else "Regular"
            print(f"  {result['cve_id']}: {status} "
                  f"(score: {result['detection_score']:.1%}, "
                  f"confidence: {result['confidence_level']})")


if __name__ == "__main__":
    main()