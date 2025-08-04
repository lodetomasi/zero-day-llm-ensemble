#!/usr/bin/env python3
"""
Universal Testing System for Zero-Day Detection
Handles any number of CVEs from various sources dynamically
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import json
import argparse
import random
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from tqdm import tqdm

from dotenv import load_dotenv
load_dotenv()

class UniversalTester:
    """Universal testing system with dynamic dataset management"""
    
    def __init__(self, use_enhanced: bool = True, use_cache: bool = True):
        """Initialize the universal tester"""
        self.use_enhanced = use_enhanced
        self.use_cache = use_cache
        self.results_cache = {}
        
        # Import appropriate detector
        if use_enhanced:
            from detect_zero_days_enhanced import EnhancedZeroDayDetector
            self.detector = EnhancedZeroDayDetector()
            self.detector_type = "Enhanced"
        else:
            from detect_zero_days import ZeroDayDetector
            self.detector = ZeroDayDetector()
            self.detector_type = "Standard"
    
    def load_datasets(self) -> Dict[str, Dict[str, Any]]:
        """Load all available datasets dynamically"""
        datasets = {}
        data_dir = Path('data')
        
        # Load all dataset files
        dataset_files = [
            'extended_dataset.json',
            'expanded_dataset_60.json',
            'dynamic_dataset.json'
        ]
        
        for dataset_file in dataset_files:
            path = data_dir / dataset_file
            if path.exists():
                with open(path, 'r') as f:
                    data = json.load(f)
                    datasets.update(data)
                    print(f"✅ Loaded {len(data)} CVEs from {dataset_file}")
        
        # Load from CISA KEV if available
        cisa_path = data_dir / 'cache' / 'cisa_kev_data.json'
        if cisa_path.exists():
            with open(cisa_path, 'r') as f:
                cisa_data = json.load(f)
                for entry in cisa_data:
                    cve_id = entry.get('cve_id')
                    if cve_id and cve_id not in datasets:
                        datasets[cve_id] = {
                            'is_zero_day': True,  # CISA KEV = exploited in wild
                            'description': entry.get('vulnerability_name', ''),
                            'evidence': 'CISA KEV listing',
                            'source': 'CISA KEV'
                        }
            print(f"✅ Added {len(cisa_data)} CVEs from CISA KEV")
        
        # Load from test batches
        batch_files = list(data_dir.glob('test_batch_*.json'))
        for batch_file in batch_files:
            with open(batch_file, 'r') as f:
                batch_data = json.load(f)
                if 'cves' in batch_data:
                    for cve_id, is_zero_day in batch_data['cves'].items():
                        if cve_id not in datasets:
                            datasets[cve_id] = {
                                'is_zero_day': is_zero_day,
                                'description': 'From test batch',
                                'evidence': 'Test batch data',
                                'source': batch_file.name
                            }
        
        print(f"\n📊 Total unique CVEs loaded: {len(datasets)}")
        zero_days = sum(1 for d in datasets.values() if d.get('is_zero_day', False))
        print(f"   Zero-days: {zero_days}")
        print(f"   Regular CVEs: {len(datasets) - zero_days}")
        
        return datasets
    
    def filter_cves(self, datasets: Dict[str, Dict], 
                    zero_days: Optional[int] = None,
                    regular: Optional[int] = None,
                    total: Optional[int] = None,
                    pattern: Optional[str] = None) -> List[str]:
        """Filter CVEs based on criteria"""
        # Separate zero-days and regular CVEs
        zero_day_list = [cve for cve, data in datasets.items() if data.get('is_zero_day', False)]
        regular_list = [cve for cve, data in datasets.items() if not data.get('is_zero_day', False)]
        
        # Apply pattern filter if specified
        if pattern:
            import re
            regex = re.compile(pattern)
            zero_day_list = [cve for cve in zero_day_list if regex.match(cve)]
            regular_list = [cve for cve in regular_list if regex.match(cve)]
        
        # Select based on criteria
        selected_zero_days = []
        selected_regular = []
        
        if total is not None:
            # Select proportionally
            if zero_day_list and regular_list:
                zero_day_ratio = len(zero_day_list) / (len(zero_day_list) + len(regular_list))
                n_zero_days = int(total * zero_day_ratio)
                n_regular = total - n_zero_days
            else:
                n_zero_days = min(total, len(zero_day_list))
                n_regular = min(total - n_zero_days, len(regular_list))
            
            selected_zero_days = random.sample(zero_day_list, min(n_zero_days, len(zero_day_list)))
            selected_regular = random.sample(regular_list, min(n_regular, len(regular_list)))
        else:
            # Use specific counts
            if zero_days is not None:
                selected_zero_days = random.sample(zero_day_list, min(zero_days, len(zero_day_list)))
            if regular is not None:
                selected_regular = random.sample(regular_list, min(regular, len(regular_list)))
        
        # Combine and shuffle
        selected = selected_zero_days + selected_regular
        random.shuffle(selected)
        
        return selected
    
    def test_cve(self, cve_id: str, ground_truth: bool) -> Dict[str, Any]:
        """Test a single CVE with caching"""
        # Check cache first
        if self.use_cache and cve_id in self.results_cache:
            cached = self.results_cache[cve_id]
            cached['from_cache'] = True
            return cached
        
        try:
            # Detect
            result = self.detector.detect(cve_id, verbose=False)
            is_predicted = result['is_zero_day']
            
            # Prepare test result
            test_result = {
                'cve_id': cve_id,
                'actual': ground_truth,
                'predicted': is_predicted,
                'correct': is_predicted == ground_truth,
                'confidence': result['confidence'],
                'score': result['detection_score'],
                'confidence_level': result.get('confidence_level', 'UNKNOWN'),
                'from_cache': False
            }
            
            # Cache result
            if self.use_cache:
                self.results_cache[cve_id] = test_result
            
            return test_result
            
        except Exception as e:
            return {
                'cve_id': cve_id,
                'actual': ground_truth,
                'predicted': None,
                'correct': False,
                'error': str(e),
                'from_cache': False
            }
    
    def run_tests(self, cve_list: List[str], datasets: Dict[str, Dict],
                  parallel: bool = False, max_workers: int = 4) -> Dict[str, Any]:
        """Run tests on selected CVEs"""
        results = []
        start_time = time.time()
        
        if parallel and len(cve_list) > 5:
            # Parallel execution for large datasets
            print(f"\n🚀 Running tests in parallel with {max_workers} workers...")
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_cve = {
                    executor.submit(self.test_cve, cve_id, datasets[cve_id]['is_zero_day']): cve_id
                    for cve_id in cve_list
                }
                
                # Process results with progress bar
                with tqdm(total=len(cve_list), desc="Testing CVEs") as pbar:
                    for future in as_completed(future_to_cve):
                        result = future.result()
                        results.append(result)
                        
                        # Update progress
                        status = "✅" if result.get('correct', False) else "❌"
                        cached = "📦" if result.get('from_cache', False) else "🔍"
                        pbar.set_postfix_str(f"{cached} {status} {result['cve_id']}")
                        pbar.update(1)
        else:
            # Sequential execution
            print(f"\n🔍 Testing {len(cve_list)} CVEs sequentially...")
            for i, cve_id in enumerate(cve_list, 1):
                ground_truth = datasets[cve_id]['is_zero_day']
                
                # Test
                result = self.test_cve(cve_id, ground_truth)
                results.append(result)
                
                # Print progress
                status = "✅" if result.get('correct', False) else "❌"
                cached = "📦" if result.get('from_cache', False) else "🔍"
                actual_label = "Zero-day" if ground_truth else "Regular"
                predicted_label = "Zero-day" if result.get('predicted', False) else "Regular"
                
                if not result.get('error'):
                    print(f"[{i}/{len(cve_list)}] {cached} {status} {cve_id}: "
                          f"Actual={actual_label}, Predicted={predicted_label}, "
                          f"Score={result.get('score', 0):.2%}")
                else:
                    print(f"[{i}/{len(cve_list)}] ❌ {cve_id}: Error - {result['error']}")
        
        # Calculate metrics
        duration = time.time() - start_time
        metrics = self.calculate_metrics(results, duration)
        
        return {
            'results': results,
            'metrics': metrics,
            'config': {
                'total_tested': len(results),
                'detector_type': self.detector_type,
                'parallel': parallel,
                'use_cache': self.use_cache
            }
        }
    
    def calculate_metrics(self, results: List[Dict], duration: float) -> Dict[str, Any]:
        """Calculate comprehensive metrics"""
        # Basic counts
        total = len(results)
        errors = sum(1 for r in results if 'error' in r)
        valid_results = [r for r in results if 'error' not in r and r['predicted'] is not None]
        
        if not valid_results:
            return {'error': 'No valid results to calculate metrics'}
        
        # Confusion matrix
        tp = sum(1 for r in valid_results if r['actual'] and r['predicted'])
        tn = sum(1 for r in valid_results if not r['actual'] and not r['predicted'])
        fp = sum(1 for r in valid_results if not r['actual'] and r['predicted'])
        fn = sum(1 for r in valid_results if r['actual'] and not r['predicted'])
        
        # Metrics
        accuracy = (tp + tn) / len(valid_results) if valid_results else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Confidence analysis
        confidence_levels = [r.get('confidence', 0) for r in valid_results]
        avg_confidence = sum(confidence_levels) / len(confidence_levels) if confidence_levels else 0
        
        # Cache statistics
        cached_results = sum(1 for r in results if r.get('from_cache', False))
        cache_hit_rate = cached_results / total if total > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': {
                'true_positives': tp,
                'true_negatives': tn,
                'false_positives': fp,
                'false_negatives': fn
            },
            'confidence': {
                'average': avg_confidence,
                'min': min(confidence_levels) if confidence_levels else 0,
                'max': max(confidence_levels) if confidence_levels else 0
            },
            'performance': {
                'total_duration': duration,
                'avg_time_per_cve': duration / total if total > 0 else 0,
                'errors': errors,
                'cache_hit_rate': cache_hit_rate
            }
        }
    
    def save_results(self, test_data: Dict[str, Any], output_file: Optional[str] = None):
        """Save test results to file"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f'universal_test_results_{timestamp}.json'
        
        # Add metadata
        test_data['metadata'] = {
            'timestamp': datetime.now().isoformat(),
            'detector_type': self.detector_type,
            'platform': sys.platform,
            'python_version': sys.version.split()[0]
        }
        
        with open(output_file, 'w') as f:
            json.dump(test_data, f, indent=2)
        
        return output_file
    
    def print_summary(self, test_data: Dict[str, Any]):
        """Print comprehensive test summary"""
        metrics = test_data['metrics']
        config = test_data['config']
        
        print("\n" + "=" * 60)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 60)
        print(f"Detector: {config['detector_type']}")
        print(f"Total CVEs tested: {config['total_tested']}")
        
        if 'error' not in metrics:
            cm = metrics['confusion_matrix']
            print(f"\n🎯 Performance Metrics:")
            print(f"  Accuracy: {metrics['accuracy']:.1%}")
            print(f"  Precision: {metrics['precision']:.1%}")
            print(f"  Recall: {metrics['recall']:.1%}")
            print(f"  F1 Score: {metrics['f1_score']:.3f}")
            
            print(f"\n📈 Confusion Matrix:")
            print(f"  True Positives: {cm['true_positives']}")
            print(f"  True Negatives: {cm['true_negatives']}")
            print(f"  False Positives: {cm['false_positives']}")
            print(f"  False Negatives: {cm['false_negatives']}")
            
            print(f"\n⚡ Performance:")
            perf = metrics['performance']
            print(f"  Total time: {perf['total_duration']:.1f}s")
            print(f"  Avg per CVE: {perf['avg_time_per_cve']:.1f}s")
            print(f"  Cache hit rate: {perf['cache_hit_rate']:.1%}")
            if perf['errors'] > 0:
                print(f"  ⚠️ Errors: {perf['errors']}")
            
            print(f"\n💭 Confidence Analysis:")
            conf = metrics['confidence']
            print(f"  Average: {conf['average']:.1%}")
            print(f"  Range: {conf['min']:.1%} - {conf['max']:.1%}")


def main():
    parser = argparse.ArgumentParser(
        description='Universal Zero-Day Detection Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 60 random CVEs
  %(prog)s --total 60
  
  # Test with specific distribution
  %(prog)s --zero-days 30 --regular 30
  
  # Test all CVEs matching pattern
  %(prog)s --pattern "CVE-2024-.*"
  
  # Fast parallel testing
  %(prog)s --total 100 --parallel --workers 8
  
  # Test without cache for fresh results
  %(prog)s --total 20 --no-cache
        """
    )
    
    # Test selection
    parser.add_argument('--total', type=int, help='Total number of CVEs to test')
    parser.add_argument('--zero-days', type=int, help='Number of zero-days to test')
    parser.add_argument('--regular', type=int, help='Number of regular CVEs to test')
    parser.add_argument('--pattern', type=str, help='Regex pattern to filter CVEs')
    parser.add_argument('--all', action='store_true', help='Test all available CVEs')
    
    # Execution options
    parser.add_argument('--enhanced', action='store_true', default=True,
                        help='Use enhanced detector (default)')
    parser.add_argument('--standard', action='store_true', help='Use standard detector')
    parser.add_argument('--parallel', action='store_true', help='Run tests in parallel')
    parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers')
    parser.add_argument('--no-cache', action='store_true', help='Disable result caching')
    
    # Output options
    parser.add_argument('--output', type=str, help='Output file for results')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    
    args = parser.parse_args()
    
    # Initialize tester
    use_enhanced = not args.standard
    use_cache = not args.no_cache
    tester = UniversalTester(use_enhanced=use_enhanced, use_cache=use_cache)
    
    # Load datasets
    print("📚 Loading datasets...")
    datasets = tester.load_datasets()
    
    if not datasets:
        print("❌ No datasets found!")
        return 1
    
    # Select CVEs to test
    if args.all:
        cve_list = list(datasets.keys())
        print(f"\n🎯 Testing ALL {len(cve_list)} CVEs")
    else:
        cve_list = tester.filter_cves(
            datasets,
            zero_days=args.zero_days,
            regular=args.regular,
            total=args.total,
            pattern=args.pattern
        )
        
        if not cve_list:
            print("❌ No CVEs selected based on criteria!")
            return 1
        
        print(f"\n🎯 Selected {len(cve_list)} CVEs for testing")
    
    # Run tests
    test_results = tester.run_tests(
        cve_list, 
        datasets,
        parallel=args.parallel,
        max_workers=args.workers
    )
    
    # Save results
    output_file = tester.save_results(test_results, args.output)
    
    # Print summary
    if not args.quiet:
        tester.print_summary(test_results)
        print(f"\n💾 Results saved to: {output_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())