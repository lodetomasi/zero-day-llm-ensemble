#!/usr/bin/env python3
"""Run a properly balanced test with guaranteed mix of zero-days and regular CVEs"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from src.data.collector import DataCollector
from src.data.preprocessor import DataPreprocessor
from src.ensemble.multi_agent import MultiAgentSystem
from src.utils.logger import get_logger, experiment_logger
import json
import random
from datetime import datetime

logger = get_logger(__name__)

def main():
    parser = argparse.ArgumentParser(description='Run balanced zero-day detection test')
    parser.add_argument('--zero-days', type=int, default=25, help='Number of zero-days to test')
    parser.add_argument('--regular', type=int, default=25, help='Number of regular CVEs to test')
    parser.add_argument('--parallel', action='store_true', help='Run agents in parallel')
    args = parser.parse_args()
    
    print("🎯 Balanced Zero-Day Detection Test")
    print("=" * 60)
    print(f"Zero-days: {args.zero_days}")
    print(f"Regular CVEs: {args.regular}")
    print(f"Total samples: {args.zero_days + args.regular}")
    print(f"Parallel execution: {args.parallel}")
    print("=" * 60)
    
    # Initialize components
    collector = DataCollector()
    preprocessor = DataPreprocessor()
    
    # 1. Collect EXACTLY the requested number of each type
    print("\n📊 Phase 1: Collecting balanced data...")
    
    # Fetch zero-days
    print(f"  Fetching {args.zero_days} zero-days from CISA KEV...")
    cisa_data = collector.fetch_cisa_zero_days(max_count=args.zero_days * 2, use_cache=False)
    if len(cisa_data) < args.zero_days:
        print(f"  ⚠️  Only {len(cisa_data)} zero-days available")
        cisa_data = cisa_data[:args.zero_days]
    else:
        cisa_data = cisa_data[:args.zero_days]
    
    # Fetch regular CVEs  
    print(f"  Fetching {args.regular} regular CVEs from NVD...")
    nvd_data = collector.fetch_nvd_regular_cves(max_count=args.regular * 2)
    if len(nvd_data) < args.regular:
        print(f"  ⚠️  Only {len(nvd_data)} regular CVEs available")
        nvd_data = nvd_data[:args.regular]
    else:
        nvd_data = nvd_data[:args.regular]
    
    print(f"  ✓ Collected {len(cisa_data)} zero-days")
    print(f"  ✓ Collected {len(nvd_data)} regular CVEs")
    
    # 2. Preprocess and mix data
    print("\n🔧 Phase 2: Preprocessing and mixing data...")
    all_data = []
    
    # Process zero-days
    zero_day_count = 0
    for cve in cisa_data:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = True  # Ensure correct label
            all_data.append(processed)
            zero_day_count += 1
    
    # Process regular CVEs
    regular_count = 0
    for cve in nvd_data:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = False  # Ensure correct label
            all_data.append(processed)
            regular_count += 1
    
    # Shuffle to mix zero-days and regular
    random.shuffle(all_data)
    
    print(f"  ✓ Processed {zero_day_count} zero-days")
    print(f"  ✓ Processed {regular_count} regular CVEs")
    print(f"  ✓ Total samples: {len(all_data)}")
    
    # 3. Initialize system
    print("\n🤖 Phase 3: Initializing multi-agent system...")
    system = MultiAgentSystem(
        use_thompson_sampling=False,
        parallel_execution=args.parallel
    )
    
    # 4. Run analysis
    print("\n🔍 Phase 4: Analyzing CVEs...")
    print("-" * 60)
    
    results = []
    tp, fp, tn, fn = 0, 0, 0, 0
    
    for i, cve_data in enumerate(all_data, 1):
        cve_id = cve_data['cve_id']
        is_zero_day = cve_data['is_zero_day']
        
        print(f"\n[{i}/{len(all_data)}] {cve_id}")
        print(f"  Type: {'Zero-day' if is_zero_day else 'Regular'}")
        print(f"  Vendor: {cve_data.get('vendor', 'Unknown')}")
        
        # Analyze
        result = system.analyze_vulnerability(cve_data, verbose=False)
        
        # Extract prediction
        ensemble = result.get('ensemble', {})
        prediction = ensemble.get('prediction', 0.5)
        confidence = ensemble.get('confidence', 0.5)
        
        # Classification
        is_zero_day_pred = prediction >= 0.5
        
        print(f"  Prediction: {prediction:.3f} (conf: {confidence:.3f})")
        print(f"  Classification: {'Zero-day' if is_zero_day_pred else 'Regular'}")
        
        # Update confusion matrix
        if is_zero_day and is_zero_day_pred:
            tp += 1
            print("  ✓ True Positive")
        elif not is_zero_day and is_zero_day_pred:
            fp += 1
            print("  ✗ False Positive")
        elif not is_zero_day and not is_zero_day_pred:
            tn += 1
            print("  ✓ True Negative")
        else:
            fn += 1
            print("  ✗ False Negative")
        
        results.append({
            'cve_id': cve_id,
            'actual': is_zero_day,
            'predicted': is_zero_day_pred,
            'probability': prediction,
            'confidence': confidence,
            'correct': is_zero_day == is_zero_day_pred
        })
    
    # 5. Calculate metrics
    total = len(results)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # 6. Display results
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS - BALANCED TEST")
    print("=" * 60)
    
    print(f"\n📈 Data Distribution:")
    print(f"  Zero-days tested: {tp + fn}")
    print(f"  Regular CVEs tested: {tn + fp}")
    
    print(f"\n🎯 Confusion Matrix:")
    print(f"                 Predicted")
    print(f"              Zero-day  Regular")
    print(f"Actual Zero-day   {tp:3d}      {fn:3d}")
    print(f"       Regular    {fp:3d}      {tn:3d}")
    
    print(f"\n📊 Metrics:")
    print(f"  Accuracy:  {accuracy:.1%}")
    print(f"  Precision: {precision:.1%}")
    print(f"  Recall:    {recall:.1%}")
    print(f"  F1 Score:  {f1:.3f}")
    
    # 7. Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_file = Path('results') / f'balanced_test_{timestamp}.json'
    
    with open(results_file, 'w') as f:
        json.dump({
            'test_type': 'balanced',
            'samples': {
                'zero_days': tp + fn,
                'regular': tn + fp,
                'total': total
            },
            'confusion_matrix': {
                'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn
            },
            'metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1
            },
            'predictions': results
        }, f, indent=2)
    
    print(f"\n💾 Results saved to: {results_file}")

if __name__ == "__main__":
    main()