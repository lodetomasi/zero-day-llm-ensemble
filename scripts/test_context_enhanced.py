#!/usr/bin/env python3
"""
Test script for context-enhanced detection system
"""
import sys
import json
from pathlib import Path
import time

sys.path.append(str(Path(__file__).parent.parent))

# from scripts.detect_zero_days_context import ContextEnhancedDetector  # Commented for now

def test_context_collection():
    """Test the context collection capabilities"""
    print("="*60)
    print("CONTEXT-ENHANCED DETECTION TEST")
    print("="*60)
    print("⚠️  Full detection test requires fixing imports. Use --scraping-only for now.")

def test_context_scraping_only():
    """Test just the context scraping without LLM calls"""
    print("\n\n" + "="*60)
    print("TESTING CONTEXT SCRAPING (No LLM calls)")
    print("="*60)
    
    from src.scraping.context_enhanced_scraper import ContextEnhancedScraper
    
    scraper = ContextEnhancedScraper()
    cve_id = "CVE-2024-3400"
    
    print(f"\nScraping context for {cve_id}...")
    start = time.time()
    
    try:
        # Get base evidence first (quick test)
        base_evidence = scraper.scrape_all_sources(cve_id)
        print(f"\n✅ Base sources scraped: {len(base_evidence.get('sources', {}))}")
        
        # Now test extended context
        print("\n🔍 Testing extended context sources...")
        
        # Test individual context functions
        tests = [
            ("Documentation", scraper.scrape_documentation),
            ("Code repositories", scraper.scrape_code_repositories),
            ("Full discussions", scraper.scrape_full_discussions),
            ("Technical blogs", scraper.scrape_technical_blogs),
            ("Patch analysis", scraper.scrape_patch_analysis),
        ]
        
        for name, func in tests:
            try:
                print(f"\n   Testing {name}...", end='', flush=True)
                result = func(cve_id)
                
                # Count results
                count = 0
                if isinstance(result, dict):
                    for v in result.values():
                        if isinstance(v, list):
                            count += len(v)
                        elif v:
                            count += 1
                
                print(f" ✅ Found {count} items")
                
                # Show sample
                if isinstance(result, dict):
                    for k, v in list(result.items())[:2]:
                        if isinstance(v, list) and v:
                            print(f"     - {k}: {len(v)} entries")
                        elif v:
                            print(f"     - {k}: {type(v).__name__}")
                            
            except Exception as e:
                print(f" ❌ Error: {str(e)[:100]}")
    
    except Exception as e:
        print(f"\n❌ Error during scraping: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n⏱️  Total time: {time.time() - start:.2f}s")

def main():
    """Run tests"""
    import argparse
    parser = argparse.ArgumentParser(description='Test context-enhanced detection')
    parser.add_argument('--scraping-only', action='store_true', 
                      help='Test only scraping without LLM calls')
    parser.add_argument('--full', action='store_true',
                      help='Run full detection test with LLMs')
    
    args = parser.parse_args()
    
    if args.scraping_only:
        test_context_scraping_only()
    elif args.full:
        test_context_collection()
    else:
        # Default: test scraping only
        print("Running scraping test (no LLM calls). Use --full for complete test.")
        test_context_scraping_only()

if __name__ == "__main__":
    main()