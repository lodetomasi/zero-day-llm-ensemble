#!/usr/bin/env python3
"""
Single unified script for zero-day detection
Flow: Web Scraping → Pass evidence to LLM → Get final classification
"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from src.ensemble.multi_agent import MultiAgentSystem
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper
from src.scraping.enhanced_temporal_analyzer import TemporalAnalyzer
from src.utils.known_false_positives import check_known_status
from src.utils.logger import get_logger
import json
from datetime import datetime

logger = get_logger(__name__)


def analyze_cve(cve_id: str, verbose: bool = False):
    """
    Analyze a single CVE with the complete flow:
    1. Scrape web evidence
    2. Pass evidence to LLM agents
    3. Get final zero-day classification
    """
    print(f"\n🔍 Analyzing {cve_id}")
    print("=" * 60)
    
    # Check known database first
    known_status = check_known_status(cve_id)
    if known_status['is_known']:
        print(f"\n⚠️  Found in known database: {known_status.get('name', cve_id)}")
        print(f"   Status: {'CONFIRMED ZERO-DAY' if known_status['is_zero_day'] else 'NOT A ZERO-DAY'}")
        print(f"   Reason: {known_status['reason']}")
        if verbose:
            print("\n   Key facts:")
            for fact in known_status['facts']:
                print(f"   • {fact}")
    
    # Step 1: Web Scraping
    if verbose:
        print("\n📡 Step 1: Collecting web evidence...")
    
    scraper = ComprehensiveZeroDayScraper()
    evidence = scraper.scrape_all_sources(cve_id)
    
    # Add temporal analysis
    temporal_analyzer = TemporalAnalyzer()
    timeline_analysis = temporal_analyzer.analyze_timeline(evidence)
    evidence['timeline_analysis'] = timeline_analysis
    
    if verbose:
        print(f"  ✓ Evidence collected from {len(evidence['sources'])} sources")
        
        # Show what we found
        if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
            print("  📌 Found in CISA Known Exploited Vulnerabilities")
        
        apt_groups = evidence['indicators'].get('apt_associations', [])
        if apt_groups:
            print(f"  📌 Associated with APT groups: {', '.join([a['group'] for a in apt_groups])}")
        
        github_pocs = evidence['sources'].get('github', {}).get('poc_count', 0)
        if github_pocs > 0:
            print(f"  📌 Found {github_pocs} proof-of-concept repositories")
        
        if evidence['indicators'].get('emergency_patches'):
            print("  📌 Emergency patches released")
    
    # Step 2: Prepare CVE data with evidence for LLM
    nvd_info = evidence['sources'].get('nvd', {})
    
    # Build the context that will be passed to LLMs
    cve_context = f"""CVE: {cve_id}
Vendor: {nvd_info.get('vendor', 'Unknown')}
Product: {nvd_info.get('product', 'Unknown')}
Description: {nvd_info.get('description', f'CVE {cve_id}')}

TIMELINE ANALYSIS:
{timeline_analysis.get('analysis', 'No timeline data available')}
Zero-day confidence from timeline: {timeline_analysis.get('confidence', 0):.0%}

EVIDENCE FROM WEB SOURCES:
"""
    
    # Add key evidence points
    if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
        cve_context += "- ⚠️ LISTED IN CISA KNOWN EXPLOITED VULNERABILITIES CATALOG\n"
        kev_data = evidence['sources']['cisa_kev']
        if kev_data.get('date_added'):
            cve_context += f"  - Added to KEV: {kev_data['date_added']}\n"
    
    news_mentions = evidence['sources'].get('security_news', {}).get('zero_day_mentions', 0)
    if news_mentions > 0:
        cve_context += f"- 📰 Found {news_mentions} security articles mentioning zero-day exploitation\n"
    
    apt_groups = evidence['indicators'].get('apt_associations', [])
    if apt_groups:
        cve_context += f"- 🎯 Associated with APT groups: {', '.join([g['group'] for g in apt_groups])}\n"
    
    github_data = evidence['sources'].get('github', {})
    if github_data.get('poc_count', 0) > 0:
        cve_context += f"- 💻 Found {github_data['poc_count']} proof-of-concept repositories\n"
        if github_data.get('first_poc_date'):
            cve_context += f"  - First PoC appeared: {github_data['first_poc_date']}\n"
    
    if evidence['indicators'].get('exploitation_before_patch'):
        cve_context += "- 🚨 Evidence of exploitation BEFORE patch\n"
    
    if evidence['indicators'].get('emergency_patches'):
        cve_context += "- 🔧 Emergency/out-of-band patches released\n"
    
    threat_intel = evidence['sources'].get('threat_intelligence', {})
    if threat_intel.get('campaigns'):
        cve_context += f"- 🕵️ Linked to campaigns: {', '.join(threat_intel['campaigns'])}\n"
    
    # Add key timeline events
    if timeline_analysis.get('timeline_events'):
        cve_context += "\nKEY TIMELINE EVENTS:\n"
        for event in timeline_analysis['timeline_events'][:3]:  # Top 3 events
            date_str = event['date'].strftime('%Y-%m-%d')
            cve_context += f"- {date_str}: {event['event']}\n"
    
    if not any([evidence['sources'].get('cisa_kev', {}).get('in_kev'),
                news_mentions > 0,
                apt_groups,
                github_data.get('poc_count', 0) > 0]):
        cve_context += "- ℹ️ No significant zero-day indicators found in web sources\n"
    
    # Step 3: LLM Analysis with Evidence
    if verbose:
        print("\n🤖 Step 2: Analyzing with LLM ensemble (with web evidence)...")
        print(f"\n📄 Evidence context passed to LLMs:")
        print("-" * 40)
        print(cve_context)
        print("-" * 40)
    
    # Initialize LLM system
    llm_system = MultiAgentSystem(parallel_execution=True)
    
    # Create CVE data structure for LLM
    cve_data = {
        'cve_id': cve_id,
        'vendor': nvd_info.get('vendor', 'Unknown'),
        'product': nvd_info.get('product', 'Unknown'),
        'description': cve_context  # This now includes all evidence
    }
    
    # Run LLM analysis
    llm_result = llm_system.analyze_vulnerability(cve_data, verbose=verbose)
    
    # Get the final score from LLM ensemble
    llm_score = llm_result.get('ensemble', {}).get('prediction', 0.5)
    llm_confidence = llm_result.get('ensemble', {}).get('confidence', 0.5)
    
    # Combine LLM score with timeline analysis for better accuracy
    timeline_confidence = timeline_analysis.get('confidence', 0.0)
    
    # Apply known database adjustments
    if known_status['is_known']:
        if known_status['is_zero_day'] is False:
            # Known false positive - cap the score
            llm_score = min(llm_score, known_status.get('override_score', 0.3))
            print(f"\n   🛡️ Score adjusted due to known false positive: {llm_score:.1%}")
        elif known_status['is_zero_day'] is True:
            # Known zero-day - boost the score
            llm_score = max(llm_score, known_status.get('boost_score', 0.7))
            print(f"\n   ✅ Score boosted due to confirmed zero-day: {llm_score:.1%}")
    
    # Weighted combination: LLM (70%) + Timeline (30%)
    final_score = (0.7 * llm_score) + (0.3 * timeline_confidence)
    confidence = (0.7 * llm_confidence) + (0.3 * timeline_confidence)
    
    # Make final decision with adjusted threshold
    # Use lower threshold if strong timeline evidence
    threshold = 0.45 if timeline_confidence > 0.7 else 0.5
    is_zero_day = final_score >= threshold
    
    # Display results
    print(f"\n🎯 FINAL VERDICT: {'ZERO-DAY' if is_zero_day else 'NOT A ZERO-DAY'}")
    print(f"   Score: {final_score:.1%} (confidence: {confidence:.1%})")
    print(f"   LLM Score: {llm_score:.1%} | Timeline Score: {timeline_confidence:.1%}")
    print(f"   Decision threshold: {threshold:.1%}")
    
    if verbose and 'agent_scores' in llm_result:
        print("\n📊 Individual Agent Scores:")
        for agent, scores in llm_result['agent_scores'].items():
            print(f"   {agent}: {scores.get('prediction', 0):.1%}")
    
    # Save detailed report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report = {
        'cve_id': cve_id,
        'timestamp': timestamp,
        'is_zero_day': is_zero_day,
        'final_score': final_score,
        'confidence': confidence,
        'evidence_collected': {
            'sources_checked': len(evidence['sources']),
            'key_findings': {
                'in_cisa_kev': evidence['sources'].get('cisa_kev', {}).get('in_kev', False),
                'apt_associations': [g['group'] for g in apt_groups],
                'github_pocs': github_data.get('poc_count', 0),
                'zero_day_news_mentions': news_mentions,
                'emergency_patches': evidence['indicators'].get('emergency_patches', False),
                'exploitation_before_patch': evidence['indicators'].get('exploitation_before_patch', False)
            },
            'timeline_analysis': {
                'is_zero_day': timeline_analysis.get('is_zero_day'),
                'confidence': timeline_analysis.get('confidence'),
                'analysis': timeline_analysis.get('analysis')
            },
            'known_database_check': known_status
        },
        'llm_analysis': llm_result,
        'scoring': {
            'llm_score': llm_score,
            'timeline_score': timeline_confidence,
            'final_score': final_score,
            'threshold_used': threshold
        }
    }
    
    # Save report
    output_dir = Path('results')
    output_dir.mkdir(exist_ok=True)
    report_file = output_dir / f'{cve_id}_analysis_{timestamp}.json'
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n💾 Detailed report saved to: {report_file}")
    
    return is_zero_day, final_score, report


def main():
    parser = argparse.ArgumentParser(
        description='Analyze CVE for zero-day exploitation using web evidence + LLM'
    )
    parser.add_argument('cve_ids', nargs='+', help='CVE IDs to analyze (e.g., CVE-2023-23397)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed analysis')
    
    args = parser.parse_args()
    
    print("🚀 Zero-Day Detection System")
    print("Flow: Web Scraping → Evidence to LLM → Classification")
    
    results = []
    
    for cve_id in args.cve_ids:
        try:
            is_zero_day, score, report = analyze_cve(cve_id, args.verbose)
            results.append({
                'cve_id': cve_id,
                'is_zero_day': is_zero_day,
                'score': score
            })
        except Exception as e:
            logger.error(f"Error analyzing {cve_id}: {e}")
            print(f"\n❌ Error analyzing {cve_id}: {e}")
    
    # Summary if multiple CVEs
    if len(results) > 1:
        print("\n" + "=" * 60)
        print("📊 SUMMARY")
        print("=" * 60)
        for result in results:
            verdict = "Zero-day" if result['is_zero_day'] else "Regular"
            print(f"{result['cve_id']}: {verdict} (score: {result['score']:.1%})")


if __name__ == "__main__":
    main()