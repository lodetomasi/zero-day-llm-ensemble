#!/usr/bin/env python3
"""
Zero-Day Detection CLI - Clean and Simple Interface
Usage: zeroday CVE-2024-3400
"""

import argparse
import sys
import os
import json
from typing import List, Dict
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scripts.detect_zero_days_enhanced import EnhancedZeroDayDetector
import logging

# Set up minimal logging
logging.getLogger('scrapy').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('src.scraping').setLevel(logging.ERROR)

class CleanDetector:
    """Clean interface wrapper for zero-day detection"""
    
    def __init__(self, quiet=False, json_output=False):
        self.quiet = quiet
        self.json_output = json_output
        self.detector = EnhancedZeroDayDetector(use_turbo=True)
        
    def detect(self, cve_ids: List[str], show_details=False):
        """Detect zero-days with clean output"""
        results = []
        
        if not self.quiet and not self.json_output:
            if len(cve_ids) == 1:
                print(f"🔍 Analyzing {cve_ids[0]}...")
            else:
                print(f"🔍 Analyzing {len(cve_ids)} CVEs...")
        
        for i, cve_id in enumerate(cve_ids):
            try:
                # Show progress for multiple CVEs
                if len(cve_ids) > 1 and not self.quiet and not self.json_output:
                    print(f"\r[{i+1}/{len(cve_ids)}] Processing {cve_id}...", end='', flush=True)
                
                result = self.detector.detect(cve_id, verbose=False)
                results.append(result)
                
                # Single CVE - show detailed result
                if len(cve_ids) == 1 and not self.json_output:
                    self._print_single_result(result, show_details)
                    
            except Exception as e:
                error_result = {
                    'cve_id': cve_id,
                    'error': str(e),
                    'is_zero_day': None
                }
                results.append(error_result)
                
                if not self.quiet and not self.json_output:
                    print(f"\n❌ Error analyzing {cve_id}: {e}")
        
        # Clear progress line
        if len(cve_ids) > 1 and not self.quiet and not self.json_output:
            print("\r" + " " * 80 + "\r", end='')
        
        # Output results
        if self.json_output:
            print(json.dumps(results, indent=2))
        elif len(cve_ids) > 1:
            self._print_summary(results)
        
        return results
    
    def _print_single_result(self, result: Dict, show_details: bool):
        """Print result for single CVE"""
        if result.get('error'):
            return
            
        # Simple output
        if result['is_zero_day']:
            print(f"\n✅ ZERO-DAY DETECTED")
            print(f"   Score: {result['detection_score']:.1%}")
            print(f"   Confidence: {result['confidence']:.1%} ({result['confidence_level']})")
        else:
            print(f"\n❌ Not a zero-day")
            print(f"   Score: {result['detection_score']:.1%}")
            print(f"   Confidence: {result['confidence']:.1%} ({result['confidence_level']})")
        
        # Key evidence
        if result.get('key_indicators'):
            print(f"\n📍 Key Evidence:")
            for indicator in result['key_indicators'][:3]:
                print(f"   • {indicator}")
        
        # Details if requested
        if show_details:
            print(f"\n📊 Detailed Metrics:")
            print(f"   Agent Consensus: {result['agent_consensus']:.1%}")
            print(f"   Data Quality: {result['advanced_metrics']['data_quality']:.1%}")
            if result['evidence_summary'].get('cisa_kev'):
                print(f"   ⚠️  Listed in CISA KEV")
    
    def _print_summary(self, results: List[Dict]):
        """Print summary for multiple CVEs"""
        valid_results = [r for r in results if not r.get('error')]
        errors = [r for r in results if r.get('error')]
        
        zero_days = [r for r in valid_results if r['is_zero_day']]
        regular = [r for r in valid_results if not r['is_zero_day']]
        
        print(f"\n📊 Summary")
        print(f"{'─' * 40}")
        print(f"Total analyzed: {len(results)}")
        print(f"Zero-days found: {len(zero_days)} 🎯")
        print(f"Regular CVEs: {len(regular)}")
        if errors:
            print(f"Errors: {len(errors)} ❌")
        
        # Show zero-days
        if zero_days:
            print(f"\n🎯 Zero-Days Detected:")
            for r in sorted(zero_days, key=lambda x: x['detection_score'], reverse=True)[:10]:
                print(f"   {r['cve_id']}: {r['detection_score']:.1%} confidence")
        
        # Show high-confidence regular CVEs that might be missed
        high_score_regular = [r for r in regular if r['detection_score'] > 0.4]
        if high_score_regular:
            print(f"\n⚠️  High-Score Regular CVEs (possible false negatives):")
            for r in sorted(high_score_regular, key=lambda x: x['detection_score'], reverse=True)[:5]:
                print(f"   {r['cve_id']}: {r['detection_score']:.1%}")


def main():
    parser = argparse.ArgumentParser(
        description='Zero-Day Vulnerability Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  zeroday CVE-2024-3400                    # Analyze single CVE
  zeroday CVE-2024-3400 CVE-2021-44228    # Analyze multiple CVEs
  zeroday -q CVE-2024-3400                # Quiet mode (result only)
  zeroday --json CVE-2024-3400            # JSON output
  zeroday -d CVE-2024-3400                # Show details
  cat cve_list.txt | xargs zeroday        # Analyze from file
        """
    )
    
    parser.add_argument('cve_ids', nargs='+', help='CVE IDs to analyze')
    parser.add_argument('-d', '--details', action='store_true', help='Show detailed analysis')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--no-turbo', action='store_true', help='Disable TurboScraper')
    
    args = parser.parse_args()
    
    # Create detector with options
    detector = CleanDetector(quiet=args.quiet, json_output=args.json)
    
    # Disable turbo if requested
    if args.no_turbo:
        detector.detector = EnhancedZeroDayDetector(use_turbo=False)
    
    # Run detection
    try:
        detector.detect(args.cve_ids, show_details=args.details)
    except KeyboardInterrupt:
        print("\n\n⚠️  Detection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()