#!/usr/bin/env python3
"""Test using pre-downloaded CVE dataset"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from src.data.preprocessor import DataPreprocessor
from src.ensemble.multi_agent import MultiAgentSystem
from src.utils.logger import get_logger
import json
import random
from datetime import datetime
import time

logger = get_logger(__name__)

class RealTimeMonitor:
    """Monitor and display real-time statistics"""
    def __init__(self):
        self.predictions = []
        self.start_time = time.time()
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
    
    def update(self, actual, predicted, probability):
        """Update statistics with new prediction"""
        self.predictions.append({
            'actual': actual,
            'predicted': predicted,
            'probability': probability,
            'timestamp': time.time() - self.start_time
        })
        
        # Update confusion matrix
        if actual and predicted:
            self.tp += 1
        elif not actual and predicted:
            self.fp += 1
        elif not actual and not predicted:
            self.tn += 1
        else:
            self.fn += 1
    
    def get_metrics(self):
        """Calculate current metrics"""
        total = self.tp + self.fp + self.tn + self.fn
        if total == 0:
            return {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0}
        
        accuracy = (self.tp + self.tn) / total
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }

def load_dataset(zero_days_count, regular_count):
    """Load CVEs from pre-downloaded dataset"""
    dataset_dir = Path("data/test_dataset")
    
    # Check if dataset exists
    if not dataset_dir.exists():
        print("❌ Dataset not found! Run 'python download_cve_dataset.py' first.")
        sys.exit(1)
    
    # Load zero-days
    zero_day_file = dataset_dir / "zero_day_cves.json"
    if not zero_day_file.exists():
        print("❌ Zero-day dataset not found!")
        sys.exit(1)
        
    with open(zero_day_file, 'r') as f:
        all_zero_days = json.load(f)
    
    # Load regular CVEs
    regular_file = dataset_dir / "regular_cves.json"
    if not regular_file.exists():
        print("❌ Regular CVE dataset not found!")
        sys.exit(1)
        
    with open(regular_file, 'r') as f:
        all_regular = json.load(f)
    
    # Sample requested amounts
    zero_days = random.sample(all_zero_days, min(zero_days_count, len(all_zero_days)))
    regular = random.sample(all_regular, min(regular_count, len(all_regular)))
    
    print(f"✅ Loaded {len(zero_days)} zero-days from dataset (available: {len(all_zero_days)})")
    print(f"✅ Loaded {len(regular)} regular CVEs from dataset (available: {len(all_regular)})")
    
    return zero_days, regular

def main():
    parser = argparse.ArgumentParser(description='Test with pre-downloaded dataset')
    parser.add_argument('--zero-days', type=int, default=10, help='Number of zero-days')
    parser.add_argument('--regular', type=int, default=10, help='Number of regular CVEs')
    parser.add_argument('--parallel', action='store_true', help='Run agents in parallel')
    args = parser.parse_args()
    
    print("🚀 Zero-Day Detection Test (From Dataset)")
    print("=" * 60)
    print(f"Zero-days: {args.zero_days}")
    print(f"Regular CVEs: {args.regular}")
    print(f"Total samples: {args.zero_days + args.regular}")
    print(f"Parallel execution: {args.parallel}")
    print("=" * 60)
    
    # Load dataset
    print("\n📊 Loading dataset...")
    zero_days, regular_cves = load_dataset(args.zero_days, args.regular)
    
    # Initialize
    preprocessor = DataPreprocessor()
    monitor = RealTimeMonitor()
    
    # Preprocess and combine
    print("\n🔧 Preprocessing data...")
    all_data = []
    
    for cve in zero_days:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = True
            all_data.append(processed)
    
    for cve in regular_cves:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = False
            all_data.append(processed)
    
    random.shuffle(all_data)
    print(f"  ✓ Total samples ready: {len(all_data)}")
    
    # Initialize system
    print("\n🤖 Initializing system...")
    system = MultiAgentSystem(
        use_thompson_sampling=False,
        parallel_execution=args.parallel
    )
    
    # Run analysis
    print("\n🔍 Analyzing CVEs...")
    print("-" * 60)
    
    results = []
    
    for i, cve_data in enumerate(all_data, 1):
        cve_id = cve_data['cve_id']
        is_zero_day = cve_data['is_zero_day']
        
        print(f"\n[{i}/{len(all_data)}] {cve_id} ({'Zero-day' if is_zero_day else 'Regular'})")
        
        # Analyze
        result = system.analyze_vulnerability(cve_data, verbose=False)
        ensemble = result.get('ensemble', {})
        prediction = ensemble.get('prediction', 0.5)
        confidence = ensemble.get('confidence', 0.5)
        
        # Classification
        is_zero_day_pred = prediction >= 0.5
        
        print(f"  → Prediction: {prediction:.3f} (conf: {confidence:.3f})")
        
        # Update monitor
        monitor.update(is_zero_day, is_zero_day_pred, prediction)
        
        # Save result
        results.append({
            'cve_id': cve_id,
            'actual': is_zero_day,
            'predicted': is_zero_day_pred,
            'probability': prediction,
            'confidence': confidence,
            'correct': is_zero_day == is_zero_day_pred
        })
        
        # Print real-time stats every 5 CVEs
        if i % 5 == 0:
            metrics = monitor.get_metrics()
            print(f"\n📊 Progress [{i}/{len(all_data)}]:")
            print(f"  Accuracy:  {metrics['accuracy']:.1%}")
            print(f"  Precision: {metrics['precision']:.1%}")
            print(f"  Recall:    {metrics['recall']:.1%}")
    
    # Final results
    metrics = monitor.get_metrics()
    
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    
    cm = {
        'tp': monitor.tp, 'fp': monitor.fp,
        'tn': monitor.tn, 'fn': monitor.fn
    }
    
    print(f"\n🎯 Confusion Matrix:")
    print(f"                 Predicted")
    print(f"              Zero-day  Regular")
    print(f"Actual Zero-day   {cm['tp']:3d}      {cm['fn']:3d}")
    print(f"       Regular    {cm['fp']:3d}      {cm['tn']:3d}")
    
    print(f"\n📊 Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.1%}")
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall:    {metrics['recall']:.1%}")
    print(f"  F1 Score:  {metrics['f1']:.3f}")
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path('results')
    results_file = output_dir / f'dataset_test_{timestamp}.json'
    
    with open(results_file, 'w') as f:
        json.dump({
            'test_type': 'dataset_based',
            'timestamp': timestamp,
            'samples': {
                'zero_days': monitor.tp + monitor.fn,
                'regular': monitor.tn + monitor.fp,
                'total': len(results)
            },
            'confusion_matrix': cm,
            'metrics': metrics,
            'predictions': results
        }, f, indent=2)
    
    print(f"\n💾 Results saved to: {results_file}")
    print("\n✅ Test completed successfully!")

if __name__ == "__main__":
    main()