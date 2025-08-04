#!/usr/bin/env python3
"""
Zero-Day Detector - Main CLI Interface
A user-friendly command-line tool for zero-day vulnerability detection
"""
import argparse
import sys
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict
import logging

# Add src to path
sys.path.append(str(Path(__file__).parent))

# Configure logging to be less verbose for users
logging.basicConfig(
    level=logging.WARNING,
    format='%(message)s'
)

# Import our detection systems
from scripts.detect_zero_days_enhanced import EnhancedZeroDayDetector as EnhancedDetector
from scripts.verify_scraping import ScrapingVerifier
from scripts.universal_tester import UniversalTester


class ZeroDayDetectorCLI:
    """Main CLI interface for zero-day detection"""
    
    def __init__(self):
        self.version = "3.12.1"
        
    def print_banner(self):
        """Print welcome banner"""
        print(r"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🎯 Zero-Day Vulnerability Detection System v3.12.1        ║
║     Multi-Agent LLM Ensemble with Context Enhancement         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """)
    
    def detect_single_cve(self, cve_id: str, verbose: bool = False, 
                         evidence_only: bool = False, save_report: bool = True):
        """Detect if a single CVE is a zero-day"""
        print(f"\n🔍 Analyzing {cve_id}...")
        print("-" * 50)
        
        if evidence_only:
            # Just show evidence collection
            verifier = ScrapingVerifier()
            verifier.verify_cve(cve_id, full_context=False)
        else:
            # Full detection
            detector = EnhancedDetector()
            
            start_time = time.time()
            result = detector.detect(cve_id, verbose=verbose)
            elapsed = time.time() - start_time
            
            # Display results
            self._display_results(result, elapsed)
            
            # Save report if requested
            if save_report:
                self._save_report(result, cve_id)
    
    def test_multiple_cves(self, zero_days: int = 10, regular: int = 10):
        """Test system with multiple CVEs"""
        print(f"\n🧪 Testing with {zero_days} zero-days and {regular} regular CVEs...")
        print("-" * 50)
        
        tester = UniversalTester()
        
        # Filter CVEs
        datasets = tester.load_datasets()
        cves_to_test = tester.filter_cves(
            datasets, 
            zero_days=zero_days, 
            regular=regular
        )
        
        print(f"Selected {len(cves_to_test)} CVEs for testing")
        
        # Run test
        results = tester.run_tests(
            cves_to_test, 
            datasets,
            parallel=True,
            max_workers=4
        )
        
        # Display results
        tester.display_results(results)
    
    def verify_scraping(self, cve_id: str, show_context: bool = False):
        """Verify data collection for a CVE"""
        print(f"\n🔍 Verifying data collection for {cve_id}...")
        
        verifier = ScrapingVerifier()
        verifier.verify_cve(cve_id, full_context=show_context)
    
    def show_status(self):
        """Show system status and configuration"""
        print("\n📊 System Status")
        print("-" * 50)
        
        # Load configuration
        config_path = Path('config/optimized_thresholds.json')
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            print("✅ Configuration loaded")
            print(f"   Version: {config.get('optimization_info', {}).get('version', 'Unknown')}")
            print(f"   Date: {config.get('optimization_info', {}).get('date', 'Unknown')}")
            
            print("\n🎯 Detection Thresholds:")
            thresholds = config.get('detection_thresholds', {}).get('by_confidence', {})
            for level, threshold in thresholds.items():
                print(f"   {level}: {threshold}")
        else:
            print("❌ Configuration not found")
        
        # Check cache
        cache_dir = Path('cache')
        if cache_dir.exists():
            cache_files = list(cache_dir.glob('*.json'))
            cache_size = sum(f.stat().st_size for f in cache_files) / (1024 * 1024)
            print(f"\n💾 Cache Status:")
            print(f"   Files: {len(cache_files)}")
            print(f"   Size: {cache_size:.1f} MB")
        
        # Check API key
        import os
        if os.getenv('OPENROUTER_API_KEY'):
            print("\n🔑 API Configuration:")
            print("   OpenRouter API key: ✅ Configured")
        else:
            print("\n🔑 API Configuration:")
            print("   OpenRouter API key: ❌ Not set")
            print("   Set with: export OPENROUTER_API_KEY='your-key'")
    
    def _display_results(self, result: Dict, elapsed_time: float):
        """Display detection results in a user-friendly way"""
        is_zero_day = result['is_zero_day']
        
        # Result banner
        if is_zero_day:
            print(f"\n{'='*50}")
            print("🚨 ZERO-DAY VULNERABILITY DETECTED! 🚨")
            print(f"{'='*50}")
        else:
            print(f"\n{'='*50}")
            print("✅ Regular Vulnerability (Not a Zero-Day)")
            print(f"{'='*50}")
        
        # Scores
        print(f"\n📊 Detection Metrics:")
        print(f"   Detection Score: {result['detection_score']:.1%}")
        print(f"   Confidence: {result['confidence']:.1%} ({result['confidence_level']})")
        print(f"   Agent Agreement: {result['agent_consensus']:.1%}")
        print(f"   Analysis Time: {elapsed_time:.1f}s")
        
        # Evidence summary
        evidence = result.get('evidence_summary', {})
        print(f"\n🔍 Evidence Summary:")
        print(f"   Sources Checked: {evidence.get('sources_checked', 0)}")
        print(f"   CISA KEV Listed: {'Yes' if evidence.get('cisa_kev') else 'No'}")
        print(f"   Exploitation Evidence: {'Found' if evidence.get('exploitation_evidence') else 'Not found'}")
        print(f"   Honeypot Activity: {'Detected' if evidence.get('honeypot_activity') else 'None'}")
        
        # Key indicators
        indicators = result.get('key_indicators', [])
        if indicators:
            print(f"\n📌 Key Indicators:")
            for indicator in indicators[:5]:  # Show top 5
                print(f"   • {indicator}")
        
        # Context metrics if available
        context_metrics = result.get('context_metrics')
        if context_metrics:
            print(f"\n📚 Context Analysis:")
            print(f"   Documentation: {context_metrics.get('documentation_pages', 0)} pages")
            print(f"   Code Snippets: {context_metrics.get('code_snippets', 0)}")
            print(f"   Discussions: {context_metrics.get('discussion_comments', 0)} comments")
            print(f"   Similar CVEs: {context_metrics.get('similar_cves', 0)}")
    
    def _save_report(self, result: Dict, cve_id: str):
        """Save detection report"""
        report_dir = Path('reports')
        report_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{cve_id}_report_{timestamp}.json"
        
        with open(report_dir / filename, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"\n💾 Report saved to: reports/{filename}")


def main():
    """Main entry point"""
    cli = ZeroDayDetectorCLI()
    
    parser = argparse.ArgumentParser(
        description='Zero-Day Vulnerability Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s detect CVE-2024-3400              # Detect single CVE
  %(prog)s detect CVE-2024-3400 -v           # Verbose output
  %(prog)s test --zero-days 10 --regular 10  # Test with multiple CVEs
  %(prog)s verify CVE-2024-3400              # Verify data collection
  %(prog)s status                            # Show system status

Common Zero-Day CVEs for Testing:
  CVE-2024-3400  - Palo Alto PAN-OS
  CVE-2021-44228 - Log4j (Log4Shell)
  CVE-2023-20198 - Cisco IOS XE
  CVE-2022-30190 - Microsoft MSDT (Follina)
  
Regular CVEs for Testing:
  CVE-2021-3156  - Sudo Baron Samedit
  CVE-2024-38063 - Windows TCP/IP
  CVE-2019-0708  - Windows RDP (BlueKeep)
        """
    )
    
    # Create subcommands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect if CVE is zero-day')
    detect_parser.add_argument('cve_id', help='CVE ID to analyze')
    detect_parser.add_argument('-v', '--verbose', action='store_true', 
                              help='Show detailed analysis')
    detect_parser.add_argument('-e', '--evidence-only', action='store_true',
                              help='Show only evidence collection')
    detect_parser.add_argument('--no-save', action='store_true',
                              help='Do not save report')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test system with multiple CVEs')
    test_parser.add_argument('--zero-days', type=int, default=10,
                            help='Number of zero-days to test (default: 10)')
    test_parser.add_argument('--regular', type=int, default=10,
                            help='Number of regular CVEs to test (default: 10)')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify data collection')
    verify_parser.add_argument('cve_id', help='CVE ID to verify')
    verify_parser.add_argument('-c', '--context', action='store_true',
                              help='Include context enhancement verification')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show banner
    cli.print_banner()
    
    # Execute command
    if args.command == 'detect':
        cli.detect_single_cve(
            args.cve_id, 
            verbose=args.verbose,
            evidence_only=args.evidence_only,
            save_report=not args.no_save
        )
    elif args.command == 'test':
        cli.test_multiple_cves(
            zero_days=args.zero_days,
            regular=args.regular
        )
    elif args.command == 'verify':
        cli.verify_scraping(
            args.cve_id,
            show_context=args.context
        )
    elif args.command == 'status':
        cli.show_status()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()