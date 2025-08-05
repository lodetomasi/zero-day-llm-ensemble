#!/usr/bin/env python3
"""
Comprehensive testing pipeline with integrated metrics and verified ground truth
"""

import json
import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from typing import Dict, List, Tuple
import argparse

# Import our modules
from scripts.calculate_metrics import calculate_metrics, print_metrics
from scripts.validate_ground_truth import get_cisa_kev_cves

def load_test_data(filename: str = "test_cves_100.json") -> List[Dict]:
    """Load test CVEs with verified ground truth"""
    with open(filename, 'r') as f:
        return json.load(f)

def run_detection_test(test_file: str = "test_cves_100.json", 
                      output_file: str = None,
                      quiet: bool = False) -> Dict:
    """Run comprehensive detection test"""
    from scripts.detect_zero_days_enhanced import EnhancedZeroDayDetector
    
    # Load test data
    test_data = load_test_data(test_file)
    
    # Initialize detector
    detector = EnhancedZeroDayDetector(use_turbo=True)
    
    # Results storage
    results = []
    ground_truth = {}
    predictions = {}
    
    # Timing
    start_time = time.time()
    
    print(f"\n{'='*60}")
    print(f"ZERO-DAY DETECTION COMPREHENSIVE TEST")
    print(f"{'='*60}")
    print(f"Test file: {test_file}")
    print(f"Total CVEs: {len(test_data)}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    # Process each CVE
    for i, entry in enumerate(test_data, 1):
        cve_id = entry['cve_id']
        expected = entry['expected']
        
        if not quiet:
            print(f"[{i}/{len(test_data)}] Analyzing {cve_id}...", end='', flush=True)
        
        # Run detection
        try:
            cve_start = time.time()
            result = detector.detect(cve_id, verbose=False)
            cve_time = time.time() - cve_start
            
            # Store results
            is_zero_day = result.get('is_zero_day', False)
            confidence = result.get('confidence', 0)
            
            ground_truth[cve_id] = expected
            predictions[cve_id] = is_zero_day
            
            results.append({
                'cve_id': cve_id,
                'expected': expected,
                'predicted': 'zero_day' if is_zero_day else 'regular',
                'is_zero_day': is_zero_day,
                'confidence': confidence,
                'time_seconds': cve_time,
                'correct': (expected == 'zero_day') == is_zero_day
            })
            
            if not quiet:
                status = "✓" if results[-1]['correct'] else "✗"
                print(f" {status} ({cve_time:.1f}s)")
                
        except Exception as e:
            print(f" ERROR: {str(e)}")
            results.append({
                'cve_id': cve_id,
                'expected': expected,
                'predicted': 'error',
                'error': str(e)
            })
    
    # Calculate metrics
    elapsed_time = time.time() - start_time
    metrics = calculate_metrics(ground_truth, predictions)
    
    # Add timing info
    metrics['total_time_seconds'] = elapsed_time
    metrics['avg_time_per_cve'] = elapsed_time / len(test_data) if test_data else 0
    
    # Print summary
    print(f"\n{'='*60}")
    print_metrics(metrics, ground_truth, predictions)
    
    print(f"\nTiming:")
    print(f"  Total time: {elapsed_time:.1f}s")
    print(f"  Average per CVE: {metrics['avg_time_per_cve']:.1f}s")
    
    # Save detailed results if requested
    if output_file:
        output_data = {
            'test_file': test_file,
            'timestamp': datetime.now().isoformat(),
            'summary': metrics,
            'detailed_results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nDetailed results saved to: {output_file}")
    
    return metrics

def verify_ground_truth_integrity(test_file: str = "test_cves_100.json") -> bool:
    """Verify ground truth matches CISA KEV"""
    print("\nVerifying ground truth integrity...")
    
    test_data = load_test_data(test_file)
    cisa_cves = get_cisa_kev_cves()
    
    errors = 0
    for entry in test_data:
        cve_id = entry['cve_id']
        expected = entry['expected']
        in_cisa = cve_id in cisa_cves
        
        # Check consistency
        if (expected == 'zero_day' and not in_cisa) or \
           (expected == 'regular' and in_cisa):
            errors += 1
            print(f"  ERROR: {cve_id} - expected={expected}, in_CISA={in_cisa}")
    
    if errors == 0:
        print("  ✓ Ground truth is 100% consistent with CISA KEV")
        return True
    else:
        print(f"  ✗ Found {errors} inconsistencies")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Run comprehensive zero-day detection test with metrics'
    )
    parser.add_argument(
        '--test-file', 
        default='test_cves_100.json',
        help='Test file with ground truth'
    )
    parser.add_argument(
        '--output', '-o',
        help='Save detailed results to JSON file'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output'
    )
    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify ground truth integrity'
    )
    
    args = parser.parse_args()
    
    # Verify ground truth first
    if not verify_ground_truth_integrity(args.test_file):
        print("\nERROR: Ground truth verification failed!")
        print("Run: python scripts/validate_ground_truth.py --fix")
        return 1
    
    if args.verify_only:
        return 0
    
    # Run comprehensive test
    try:
        metrics = run_detection_test(
            test_file=args.test_file,
            output_file=args.output,
            quiet=args.quiet
        )
        
        # Return 0 if F1 score is acceptable, 1 otherwise
        return 0 if metrics['f1_score'] >= 0.7 else 1
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        return 1
    except Exception as e:
        print(f"\nERROR: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())