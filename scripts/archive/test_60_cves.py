#!/usr/bin/env python3
"""
Test the system with 60 CVEs (30 zero-days + 30 regular)
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import json
import argparse
from datetime import datetime
from dotenv import load_dotenv
import random

# Load environment variables
load_dotenv()

def test_with_60_cves(use_enhanced=True, sample_size=None):
    """Test the system with 60 CVEs"""
    
    # Load expanded dataset
    dataset_path = Path('data/expanded_dataset_60.json')
    if not dataset_path.exists():
        print("❌ Expanded dataset not found. Run expand_dataset.py first.")
        return
    
    with open(dataset_path, 'r') as f:
        dataset = json.load(f)
    
    # Get zero-days and regular CVEs
    zero_days = [cve for cve, data in dataset.items() if data['is_zero_day']]
    regular_cves = [cve for cve, data in dataset.items() if not data['is_zero_day']]
    
    print("🚀 Testing Zero-Day Detection System with 60 CVEs")
    print("=" * 60)
    print(f"Total CVEs: {len(dataset)}")
    print(f"Zero-days: {len(zero_days)}")
    print(f"Regular CVEs: {len(regular_cves)}")
    print("=" * 60)
    
    # If sample size specified, randomly sample
    if sample_size and sample_size < len(dataset):
        # Sample proportionally
        zero_day_sample_size = int(sample_size * len(zero_days) / len(dataset))
        regular_sample_size = sample_size - zero_day_sample_size
        
        zero_days = random.sample(zero_days, zero_day_sample_size)
        regular_cves = random.sample(regular_cves, regular_sample_size)
        
        print(f"\n📊 Testing with sample of {sample_size} CVEs")
        print(f"   Zero-days in sample: {len(zero_days)}")
        print(f"   Regular CVEs in sample: {len(regular_cves)}")
        print("=" * 60)
    
    # Prepare test command
    cve_list = zero_days + regular_cves
    random.shuffle(cve_list)  # Shuffle to avoid bias
    
    # Build command based on whether to use enhanced or standard detection
    if use_enhanced:
        script = "scripts/detect_zero_days_enhanced.py"
        detector_type = "Enhanced"
    else:
        script = "scripts/detect_zero_days.py"
        detector_type = "Standard"
    
    print(f"\n🔍 Using {detector_type} Detection System")
    print(f"Testing {len(cve_list)} CVEs...\n")
    
    # Import detector directly for better control
    if use_enhanced:
        from detect_zero_days_enhanced import EnhancedZeroDayDetector
        detector = EnhancedZeroDayDetector()
    else:
        from detect_zero_days import ZeroDayDetector
        detector = ZeroDayDetector()
    
    # Test all CVEs
    results = []
    correct_predictions = 0
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0
    
    start_time = datetime.now()
    
    for i, cve_id in enumerate(cve_list, 1):
        print(f"\n[{i}/{len(cve_list)}] Testing {cve_id}...")
        
        try:
            # Get ground truth
            is_actual_zero_day = dataset[cve_id]['is_zero_day']
            
            # Detect
            result = detector.detect(cve_id, verbose=False)
            is_predicted_zero_day = result['is_zero_day']
            
            # Check if correct
            is_correct = is_predicted_zero_day == is_actual_zero_day
            if is_correct:
                correct_predictions += 1
                if is_actual_zero_day:
                    true_positives += 1
                else:
                    true_negatives += 1
            else:
                if is_predicted_zero_day:
                    false_positives += 1
                else:
                    false_negatives += 1
            
            # Store result
            results.append({
                'cve_id': cve_id,
                'actual': is_actual_zero_day,
                'predicted': is_predicted_zero_day,
                'correct': is_correct,
                'confidence': result['confidence'],
                'score': result['detection_score']
            })
            
            # Print result
            status = "✅" if is_correct else "❌"
            actual_label = "Zero-day" if is_actual_zero_day else "Regular"
            predicted_label = "Zero-day" if is_predicted_zero_day else "Regular"
            print(f"{status} {cve_id}: Actual={actual_label}, Predicted={predicted_label}, "
                  f"Score={result['detection_score']:.2%}, Confidence={result['confidence']:.2%}")
            
        except Exception as e:
            print(f"❌ Error testing {cve_id}: {e}")
            results.append({
                'cve_id': cve_id,
                'actual': dataset[cve_id]['is_zero_day'],
                'predicted': None,
                'correct': False,
                'error': str(e)
            })
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Calculate metrics
    total_tested = len(results)
    accuracy = correct_predictions / total_tested if total_tested > 0 else 0
    
    # Precision, Recall, F1
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"Total CVEs tested: {total_tested}")
    print(f"Correct predictions: {correct_predictions}/{total_tested} ({accuracy:.1%})")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives: {true_positives}")
    print(f"  True Negatives: {true_negatives}")
    print(f"  False Positives: {false_positives}")
    print(f"  False Negatives: {false_negatives}")
    print(f"\nMetrics:")
    print(f"  Accuracy: {accuracy:.1%}")
    print(f"  Precision: {precision:.1%}")
    print(f"  Recall: {recall:.1%}")
    print(f"  F1 Score: {f1_score:.3f}")
    print(f"\nExecution time: {duration:.1f} seconds ({duration/60:.1f} minutes)")
    print(f"Average time per CVE: {duration/total_tested:.1f} seconds")
    
    # Save results
    results_file = f'test_results_60_cves_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    results_data = {
        'test_config': {
            'total_cves': total_tested,
            'zero_days': len([r for r in results if r.get('actual', False)]),
            'regular_cves': len([r for r in results if not r.get('actual', False)]),
            'detector_type': detector_type,
            'sample_size': sample_size
        },
        'metrics': {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'true_positives': true_positives,
            'true_negatives': true_negatives,
            'false_positives': false_positives,
            'false_negatives': false_negatives
        },
        'execution': {
            'total_seconds': duration,
            'avg_seconds_per_cve': duration/total_tested if total_tested > 0 else 0
        },
        'results': results
    }
    
    with open(results_file, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {results_file}")
    
    # Show errors if any
    errors = [r for r in results if 'error' in r]
    if errors:
        print(f"\n⚠️ Errors encountered: {len(errors)}")
        for err in errors[:5]:  # Show first 5 errors
            print(f"  - {err['cve_id']}: {err['error']}")

def main():
    parser = argparse.ArgumentParser(description='Test system with 60 CVEs')
    parser.add_argument('--enhanced', action='store_true', default=True,
                       help='Use enhanced detection (default: True)')
    parser.add_argument('--standard', action='store_true',
                       help='Use standard detection')
    parser.add_argument('--sample', type=int,
                       help='Test with a random sample of CVEs')
    
    args = parser.parse_args()
    
    # Determine which detector to use
    use_enhanced = not args.standard
    
    test_with_60_cves(use_enhanced=use_enhanced, sample_size=args.sample)

if __name__ == "__main__":
    main()