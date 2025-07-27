#!/usr/bin/env python3
"""
Main script to run zero-day analysis with web scraping enhancement
"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from src.ensemble.multi_agent import MultiAgentSystem
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper
from src.utils.logger import get_logger
import json
from datetime import datetime
from typing import List, Dict

logger = get_logger(__name__)


def analyze_single_cve(cve_id: str, system: MultiAgentSystem, scraper: ComprehensiveZeroDayScraper, 
                      verbose: bool = False) -> Dict:
    """
    Analyze a single CVE using both LLM and web scraping
    """
    logger.info(f"Analyzing {cve_id}")
    
    # Step 1: Web scraping for evidence
    if verbose:
        print(f"\n📡 Collecting evidence for {cve_id}...")
    
    evidence = scraper.scrape_all_sources(cve_id)
    scraping_score = evidence['scores']['zero_day_confidence']
    
    if verbose:
        print(f"  ✓ Evidence collected from {len(evidence['sources'])} sources")
        print(f"  ✓ Zero-day confidence from evidence: {scraping_score:.1%}")
        
        # Show key findings
        if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
            print("  📌 Found in CISA Known Exploited Vulnerabilities")
        
        apt_groups = evidence['indicators'].get('apt_associations', [])
        if apt_groups:
            print(f"  📌 Associated with APT groups: {', '.join([a['group'] for a in apt_groups])}")
    
    # Step 2: Prepare CVE data for LLM analysis with evidence
    # First get basic CVE info from NVD if available
    nvd_info = evidence['sources'].get('nvd', {})
    cve_data = {
        'cve_id': cve_id,
        'vendor': nvd_info.get('vendor', 'Unknown'),
        'product': nvd_info.get('product', 'Unknown'),
        'description': nvd_info.get('description', f"CVE {cve_id}")
    }
    
    # Build comprehensive evidence context for LLM
    evidence_context = "\n\nEVIDENCE COLLECTED:\n"
    
    # CISA KEV status
    if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
        evidence_context += "- ⚠️ LISTED IN CISA KNOWN EXPLOITED VULNERABILITIES\n"
        kev_data = evidence['sources']['cisa_kev']
        if kev_data.get('date_added'):
            evidence_context += f"  - Added to KEV: {kev_data['date_added']}\n"
        if kev_data.get('short_description'):
            evidence_context += f"  - KEV Description: {kev_data['short_description']}\n"
    
    # Security news mentions
    news_data = evidence['sources'].get('security_news', {})
    if news_data.get('zero_day_mentions', 0) > 0:
        evidence_context += f"- 📰 Found {news_data['zero_day_mentions']} security articles mentioning zero-day exploitation\n"
        for article in news_data.get('articles', [])[:3]:  # Top 3 articles
            evidence_context += f"  - {article.get('source', 'News')}: {article.get('title', '')}\n"
    
    # APT associations
    apt_groups = evidence['indicators'].get('apt_associations', [])
    if apt_groups:
        evidence_context += f"- 🎯 Associated with APT groups: {', '.join([g['group'] for g in apt_groups])}\n"
    
    # GitHub activity
    github_data = evidence['sources'].get('github', {})
    if github_data.get('poc_count', 0) > 0:
        evidence_context += f"- 💻 Found {github_data['poc_count']} proof-of-concept repositories on GitHub\n"
        if github_data.get('first_poc_date'):
            evidence_context += f"  - First PoC appeared: {github_data['first_poc_date']}\n"
    
    # Exploitation indicators
    if evidence['indicators'].get('exploitation_before_patch'):
        evidence_context += "- 🚨 Evidence suggests exploitation BEFORE patch was available\n"
    
    if evidence['indicators'].get('emergency_patches'):
        evidence_context += "- 🔧 Vendor released EMERGENCY/OUT-OF-BAND patches\n"
    
    # Threat intelligence
    threat_intel = evidence['sources'].get('threat_intelligence', {})
    if threat_intel.get('campaigns'):
        evidence_context += f"- 🕵️ Linked to campaigns: {', '.join(threat_intel['campaigns'])}\n"
    
    # Add evidence to description
    cve_data['description'] += evidence_context
    
    # Step 3: LLM analysis
    if verbose:
        print(f"\n🤖 Running LLM analysis...")
    
    llm_result = system.analyze_vulnerability(cve_data)
    llm_score = llm_result.get('ensemble', {}).get('prediction', 0.5)
    
    if verbose:
        print(f"  ✓ LLM prediction: {llm_score:.1%}")
    
    # Step 4: Combined analysis
    # Weight: 70% evidence-based, 30% LLM (evidence is more reliable)
    combined_score = (0.7 * scraping_score) + (0.3 * llm_score)
    
    # Decision with confidence threshold
    threshold = 0.55  # Slightly above neutral
    is_zero_day = combined_score >= threshold
    
    result = {
        'cve_id': cve_id,
        'is_zero_day': is_zero_day,
        'scores': {
            'evidence_based': scraping_score,
            'llm_based': llm_score,
            'combined': combined_score
        },
        'evidence': evidence,
        'llm_analysis': llm_result,
        'threshold': threshold
    }
    
    if verbose:
        print(f"\n🎯 Final verdict: {'Zero-day' if is_zero_day else 'NOT zero-day'}")
        print(f"  Combined score: {combined_score:.1%} (threshold: {threshold:.1%})")
    
    return result


def analyze_cve_list(cve_list: List[str], output_dir: Path, parallel: bool = True, 
                    verbose: bool = False) -> Dict:
    """
    Analyze a list of CVEs and generate report
    """
    print(f"\n🚀 Zero-Day Detection System")
    print("=" * 60)
    print(f"Analyzing {len(cve_list)} CVEs")
    print(f"Output directory: {output_dir}")
    print("=" * 60)
    
    # Initialize systems
    system = MultiAgentSystem(parallel_execution=parallel)
    scraper = ComprehensiveZeroDayScraper()
    
    results = []
    
    for i, cve_id in enumerate(cve_list, 1):
        print(f"\n[{i}/{len(cve_list)}] {cve_id}")
        
        try:
            result = analyze_single_cve(cve_id, system, scraper, verbose)
            results.append(result)
            
            # Quick summary
            verdict = "Zero-day" if result['is_zero_day'] else "NOT zero-day"
            score = result['scores']['combined']
            print(f"  → {verdict} (confidence: {score:.1%})")
            
        except Exception as e:
            logger.error(f"Error analyzing {cve_id}: {e}")
            results.append({
                'cve_id': cve_id,
                'error': str(e),
                'is_zero_day': None
            })
    
    # Generate report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = output_dir / f"analysis_report_{timestamp}.json"
    
    report = {
        'timestamp': timestamp,
        'cve_count': len(cve_list),
        'results': results,
        'summary': {
            'zero_days_found': sum(1 for r in results if r.get('is_zero_day') is True),
            'not_zero_days': sum(1 for r in results if r.get('is_zero_day') is False),
            'errors': sum(1 for r in results if 'error' in r)
        }
    }
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Generate markdown summary
    md_path = output_dir / f"analysis_summary_{timestamp}.md"
    with open(md_path, 'w') as f:
        f.write("# Zero-Day Analysis Summary\n\n")
        f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**CVEs Analyzed**: {len(cve_list)}\n\n")
        
        f.write("## Results\n\n")
        f.write(f"- **Zero-days identified**: {report['summary']['zero_days_found']}\n")
        f.write(f"- **Regular vulnerabilities**: {report['summary']['not_zero_days']}\n")
        f.write(f"- **Analysis errors**: {report['summary']['errors']}\n\n")
        
        f.write("## Detailed Results\n\n")
        f.write("| CVE ID | Verdict | Evidence Score | LLM Score | Combined Score |\n")
        f.write("|--------|---------|----------------|-----------|----------------|\n")
        
        for result in results:
            if 'error' not in result:
                cve_id = result['cve_id']
                verdict = "Zero-day" if result['is_zero_day'] else "Regular"
                ev_score = result['scores']['evidence_based']
                llm_score = result['scores']['llm_based']
                combined = result['scores']['combined']
                
                f.write(f"| {cve_id} | {verdict} | {ev_score:.1%} | {llm_score:.1%} | {combined:.1%} |\n")
            else:
                f.write(f"| {result['cve_id']} | ERROR | - | - | - |\n")
    
    print(f"\n✅ Analysis complete!")
    print(f"📄 Report saved to: {report_path}")
    print(f"📄 Summary saved to: {md_path}")
    
    return report


def main():
    parser = argparse.ArgumentParser(description='Analyze CVEs for zero-day exploitation')
    parser.add_argument('cves', nargs='*', help='CVE IDs to analyze')
    parser.add_argument('--file', '-f', help='File containing CVE IDs (one per line)')
    parser.add_argument('--output', '-o', default='results', help='Output directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--no-parallel', action='store_true', help='Disable parallel execution')
    
    args = parser.parse_args()
    
    # Collect CVE IDs
    cve_list = []
    
    if args.cves:
        cve_list.extend(args.cves)
    
    if args.file:
        with open(args.file, 'r') as f:
            cve_list.extend([line.strip() for line in f if line.strip()])
    
    if not cve_list:
        # Default test set
        cve_list = [
            "CVE-2023-23397",  # Microsoft Outlook (known zero-day)
            "CVE-2021-44228",  # Log4Shell (NOT zero-day)
            "CVE-2023-3519",   # Citrix NetScaler
            "CVE-2024-3400",   # Palo Alto PAN-OS
            "CVE-2017-0144"    # EternalBlue
        ]
        print("No CVEs specified, using default test set")
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Run analysis
    analyze_cve_list(
        cve_list, 
        output_dir,
        parallel=not args.no_parallel,
        verbose=args.verbose
    )


if __name__ == "__main__":
    main()