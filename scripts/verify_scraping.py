#!/usr/bin/env python3
"""
Comprehensive verification script for context-enhanced scraping
Shows exactly what data is being collected from each source
"""
import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import logging

sys.path.append(str(Path(__file__).parent.parent))

from src.scraping.context_enhanced_scraper import ContextEnhancedScraper
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper

# Set up detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScrapingVerifier:
    """Verify and display scraping results in a user-friendly way"""
    
    def __init__(self):
        self.basic_scraper = ComprehensiveZeroDayScraper()
        self.context_scraper = ContextEnhancedScraper()
        
    def verify_cve(self, cve_id: str, full_context: bool = False):
        """Verify scraping for a single CVE"""
        print(f"\n{'='*80}")
        print(f"🔍 SCRAPING VERIFICATION FOR {cve_id}")
        print(f"{'='*80}")
        
        # Phase 1: Basic scraping
        print("\n📊 PHASE 1: Basic Evidence Collection")
        print("-" * 40)
        
        start_time = time.time()
        basic_evidence = self.basic_scraper.scrape_all_sources(cve_id)
        basic_time = time.time() - start_time
        
        self._display_basic_results(basic_evidence, basic_time)
        
        # Phase 2: Context-enhanced scraping
        if full_context:
            print("\n\n📚 PHASE 2: Enhanced Context Collection")
            print("-" * 40)
            
            start_time = time.time()
            context_evidence = self.context_scraper.scrape_all_sources_context_enhanced(cve_id)
            context_time = time.time() - start_time
            
            self._display_context_results(context_evidence, context_time)
            
            # Summary comparison
            self._display_comparison(basic_evidence, context_evidence, basic_time, context_time)
        
        return basic_evidence, context_evidence if full_context else None
    
    def _display_basic_results(self, evidence: Dict, elapsed_time: float):
        """Display basic scraping results"""
        sources = evidence.get('sources', {})
        
        print(f"\n✅ Sources checked: {len(sources)}")
        print(f"⏱️  Time taken: {elapsed_time:.2f}s")
        
        # Display each source
        for source_name, data in sources.items():
            if isinstance(data, dict) and not data.get('error'):
                # Count non-empty fields
                field_count = sum(1 for v in data.values() if v not in [None, '', [], {}, False])
                print(f"\n📌 {source_name.upper()}: {field_count} data points")
                
                # Show key findings
                if source_name == 'nvd' and data.get('found'):
                    print(f"   - Published: {data.get('published_date', 'N/A')}")
                    print(f"   - CVSS Score: {data.get('cvss_score', 'N/A')}")
                    print(f"   - References: {len(data.get('references', []))}")
                
                elif source_name == 'cisa_kev' and data.get('in_kev'):
                    print(f"   - In KEV: ✓")
                    print(f"   - Date Added: {data.get('date_added', 'N/A')}")
                    print(f"   - Action Required: {data.get('required_action', 'N/A')[:100]}...")
                
                elif source_name == 'exploit_db':
                    print(f"   - Exploit Available: {'✓' if data.get('exploit_db') else '✗'}")
                    print(f"   - Metasploit: {'✓' if data.get('metasploit') else '✗'}")
                    print(f"   - Exploit Count: {data.get('exploit_count', 0)}")
                
                elif source_name == 'github':
                    print(f"   - PoC Repos: {data.get('poc_repositories', 0)}")
                    if data.get('earliest_poc_date'):
                        print(f"   - First PoC: {data.get('earliest_poc_date')}")
                
                elif source_name == 'security_news':
                    print(f"   - Articles: {len(data.get('articles', []))}")
                    print(f"   - Zero-day mentions: {data.get('zero_day_mentions', 0)}")
                    print(f"   - Exploitation mentions: {data.get('exploitation_mentions', 0)}")
                
                elif source_name == 'social_media':
                    print(f"   - Twitter mentions: {data.get('twitter_mentions', 0)}")
                    print(f"   - Reddit discussions: {data.get('reddit_discussions', 0)}")
                    print(f"   - InfoSec buzz: {'✓' if data.get('infosec_community_buzz') else '✗'}")
                
            elif isinstance(data, dict) and data.get('error'):
                print(f"\n❌ {source_name.upper()}: Error - {data['error'][:50]}...")
    
    def _display_context_results(self, evidence: Dict, elapsed_time: float):
        """Display enhanced context results"""
        context = evidence.get('extended_context', {})
        
        print(f"\n✅ Extended sources checked: {len(context)}")
        print(f"⏱️  Time taken: {elapsed_time:.2f}s")
        
        # Display each context source
        for context_name, data in context.items():
            if isinstance(data, dict) and not data.get('error'):
                # Count meaningful data
                item_count = 0
                details = []
                
                # Documentation
                if context_name == 'documentation':
                    item_count = data.get('total_pages', 0)
                    if data.get('official_docs'):
                        details.append(f"Official docs: {len(data['official_docs'])}")
                    if data.get('man_pages'):
                        details.append(f"Man pages: {len(data['man_pages'])}")
                
                # Code analysis
                elif context_name == 'code_analysis':
                    snippets = data.get('vulnerable_code_snippets', [])
                    pocs = data.get('poc_implementations', [])
                    item_count = len(snippets) + len(pocs)
                    if snippets:
                        details.append(f"Vulnerable code: {len(snippets)}")
                    if pocs:
                        details.append(f"PoC implementations: {len(pocs)}")
                
                # Discussions
                elif context_name == 'full_discussions':
                    item_count = data.get('total_comments', 0)
                    if data.get('stackoverflow_threads'):
                        details.append(f"Stack Overflow: {len(data['stackoverflow_threads'])} threads")
                    if data.get('reddit_discussions'):
                        details.append(f"Reddit: {len(data['reddit_discussions'])} discussions")
                    if data.get('mailing_lists'):
                        details.append(f"Mailing lists: {len(data['mailing_lists'])} posts")
                
                # Patch details
                elif context_name == 'patch_details':
                    commits = data.get('patch_commits', [])
                    item_count = len(commits)
                    if commits:
                        details.append(f"Patch commits: {len(commits)}")
                        details.append(f"Lines changed: {data.get('lines_changed', 0)}")
                
                # Historical
                elif context_name == 'historical_vulns':
                    similar = data.get('similar_cves', [])
                    item_count = len(similar)
                    if similar:
                        details.append(f"Similar CVEs: {len(similar)}")
                    if data.get('vulnerability_trends'):
                        details.append("Trend analysis available")
                
                # Exploits
                elif context_name == 'exploit_tutorials':
                    tutorials = data.get('tutorials', [])
                    item_count = len(tutorials)
                    if tutorials:
                        details.append(f"Tutorials: {len(tutorials)}")
                    if data.get('video_references'):
                        details.append(f"Videos: {len(data['video_references'])}")
                
                # Display results
                if item_count > 0 or details:
                    print(f"\n🔍 {context_name.upper().replace('_', ' ')}: {item_count} items")
                    for detail in details:
                        print(f"   - {detail}")
            
            elif isinstance(data, dict) and data.get('error'):
                print(f"\n❌ {context_name.upper()}: Error")
    
    def _display_comparison(self, basic: Dict, context: Dict, basic_time: float, context_time: float):
        """Display comparison between basic and enhanced scraping"""
        print(f"\n\n{'='*80}")
        print("📊 SCRAPING COMPARISON")
        print(f"{'='*80}")
        
        basic_sources = len(basic.get('sources', {}))
        context_sources = len(context.get('extended_context', {}))
        
        print(f"\n📈 Data Volume:")
        print(f"   Basic sources: {basic_sources}")
        print(f"   Extended sources: {context_sources}")
        print(f"   Total sources: {basic_sources + context_sources}")
        
        print(f"\n⏱️  Performance:")
        print(f"   Basic scraping: {basic_time:.2f}s")
        print(f"   Context scraping: {context_time:.2f}s")
        print(f"   Total time: {basic_time + context_time:.2f}s")
        
        # Estimate data richness
        basic_data_points = sum(
            sum(1 for v in source.values() if v not in [None, '', [], {}, False])
            for source in basic.get('sources', {}).values()
            if isinstance(source, dict) and not source.get('error')
        )
        
        context_data_points = sum(
            len(v) if isinstance(v, list) else (1 if v else 0)
            for source in context.get('extended_context', {}).values()
            if isinstance(source, dict) and not source.get('error')
            for v in source.values()
        )
        
        print(f"\n💾 Data Richness:")
        print(f"   Basic data points: ~{basic_data_points}")
        print(f"   Context data points: ~{context_data_points}")
        print(f"   Total data points: ~{basic_data_points + context_data_points}")
        
        # Calculate JSON size
        basic_size = len(json.dumps(basic)) / 1024
        context_size = len(json.dumps(context)) / 1024
        
        print(f"\n📦 Data Size:")
        print(f"   Basic evidence: {basic_size:.1f} KB")
        print(f"   Context evidence: {context_size:.1f} KB")
        print(f"   Total size: {basic_size + context_size:.1f} KB")


def main():
    """Main verification function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Verify zero-day detection scraping capabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s CVE-2024-3400                    # Basic scraping only
  %(prog)s CVE-2024-3400 --full            # Include context enhancement
  %(prog)s CVE-2024-3400 --full --output   # Save results to file
  
Common CVEs for testing:
  CVE-2024-3400  - Palo Alto PAN-OS (Zero-day)
  CVE-2021-44228 - Log4j (Zero-day)
  CVE-2021-3156  - Sudo Baron Samedit (Regular)
  CVE-2024-38063 - Windows TCP/IP (Regular)
        """
    )
    
    parser.add_argument('cve_id', help='CVE ID to verify scraping for')
    parser.add_argument('--full', '-f', action='store_true', 
                       help='Include enhanced context scraping')
    parser.add_argument('--output', '-o', action='store_true',
                       help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Create verifier
    verifier = ScrapingVerifier()
    
    # Run verification
    basic, context = verifier.verify_cve(args.cve_id, full_context=args.full)
    
    # Save results if requested
    if args.output:
        output_dir = Path('scraping_verification')
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{args.cve_id}_verification_{timestamp}.json"
        
        results = {
            'cve_id': args.cve_id,
            'timestamp': datetime.now().isoformat(),
            'basic_evidence': basic,
            'context_evidence': context if args.full else None
        }
        
        with open(output_dir / filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: {output_dir / filename}")


if __name__ == "__main__":
    main()