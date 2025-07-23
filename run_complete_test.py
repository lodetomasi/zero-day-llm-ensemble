#!/usr/bin/env python3
"""Complete test with visualizations and real-time monitoring"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from src.data.collector import DataCollector
from src.data.preprocessor import DataPreprocessor
from src.ensemble.multi_agent import MultiAgentSystem
from src.utils.logger import get_logger
import json
import random
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import defaultdict
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
    
    def print_realtime_stats(self, cve_num, total):
        """Print real-time statistics"""
        metrics = self.get_metrics()
        elapsed = time.time() - self.start_time
        rate = cve_num / elapsed if elapsed > 0 else 0
        
        print(f"\n📊 Real-time Stats [{cve_num}/{total}]:")
        print(f"  Accuracy:  {metrics['accuracy']:.1%}")
        print(f"  Precision: {metrics['precision']:.1%}")
        print(f"  Recall:    {metrics['recall']:.1%}")
        print(f"  F1-Score:  {metrics['f1']:.3f}")
        print(f"  Rate:      {rate:.1f} CVE/min")
        print(f"  ETA:       {(total-cve_num)/rate:.1f} min" if rate > 0 else "  ETA:       --")

def create_visualizations(results_file, output_dir):
    """Create comprehensive visualizations"""
    print("\n📊 Creating visualizations...")
    
    # Load results
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    predictions = data['predictions']
    metrics = data['metrics']
    cm = data['confusion_matrix']
    
    # Create figure with subplots
    fig = plt.figure(figsize=(20, 12))
    
    # 1. Confusion Matrix
    ax1 = plt.subplot(2, 3, 1)
    cm_matrix = np.array([[cm['tp'], cm['fn']], [cm['fp'], cm['tn']]])
    sns.heatmap(cm_matrix, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Predicted\nZero-day', 'Predicted\nRegular'],
                yticklabels=['Actual\nZero-day', 'Actual\nRegular'])
    ax1.set_title('Confusion Matrix', fontsize=14)
    
    # 2. Metrics Bar Chart
    ax2 = plt.subplot(2, 3, 2)
    metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    metric_values = [metrics['accuracy'], metrics['precision'], 
                     metrics['recall'], metrics['f1']]
    bars = ax2.bar(metric_names, metric_values, color=['green', 'blue', 'orange', 'red'])
    ax2.set_ylim(0, 1.1)
    ax2.set_ylabel('Score')
    ax2.set_title('Performance Metrics', fontsize=14)
    
    # Add value labels on bars
    for bar, value in zip(bars, metric_values):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                f'{value:.2%}', ha='center', va='bottom')
    
    # 3. Probability Distribution
    ax3 = plt.subplot(2, 3, 3)
    zero_day_probs = [p['probability'] for p in predictions if p['actual']]
    regular_probs = [p['probability'] for p in predictions if not p['actual']]
    
    ax3.hist(zero_day_probs, bins=20, alpha=0.5, label='Zero-day', color='red')
    ax3.hist(regular_probs, bins=20, alpha=0.5, label='Regular', color='blue')
    ax3.axvline(x=0.5, color='black', linestyle='--', label='Threshold')
    ax3.set_xlabel('Prediction Score')
    ax3.set_ylabel('Count')
    ax3.set_title('Prediction Score Distribution', fontsize=14)
    ax3.legend()
    
    # 4. ROC-like Curve
    ax4 = plt.subplot(2, 3, 4)
    sorted_preds = sorted(predictions, key=lambda x: x['probability'], reverse=True)
    
    tpr_list = []
    fpr_list = []
    
    for threshold in np.linspace(0, 1, 50):
        tp = sum(1 for p in predictions if p['actual'] and p['probability'] >= threshold)
        fp = sum(1 for p in predictions if not p['actual'] and p['probability'] >= threshold)
        fn = sum(1 for p in predictions if p['actual'] and p['probability'] < threshold)
        tn = sum(1 for p in predictions if not p['actual'] and p['probability'] < threshold)
        
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        tpr_list.append(tpr)
        fpr_list.append(fpr)
    
    ax4.plot(fpr_list, tpr_list, 'b-', linewidth=2)
    ax4.plot([0, 1], [0, 1], 'r--', label='Random')
    ax4.set_xlabel('False Positive Rate')
    ax4.set_ylabel('True Positive Rate')
    ax4.set_title('ROC Curve', fontsize=14)
    ax4.grid(True, alpha=0.3)
    
    # 5. Prediction Timeline
    ax5 = plt.subplot(2, 3, 5)
    timestamps = list(range(len(predictions)))
    colors = ['green' if p['actual'] == p['predicted'] else 'red' for p in predictions]
    
    ax5.scatter(timestamps, [p['probability'] for p in predictions], 
                c=colors, alpha=0.6, s=50)
    ax5.axhline(y=0.5, color='black', linestyle='--', alpha=0.5)
    ax5.set_xlabel('Prediction Number')
    ax5.set_ylabel('Prediction Score')
    ax5.set_title('Prediction Timeline', fontsize=14)
    ax5.set_ylim(-0.05, 1.05)
    
    # 6. Performance by Confidence
    ax6 = plt.subplot(2, 3, 6)
    conf_bins = [(0, 0.6), (0.6, 0.7), (0.7, 0.8), (0.8, 0.9), (0.9, 1.0)]
    conf_accuracy = []
    conf_labels = []
    
    for low, high in conf_bins:
        in_bin = [p for p in predictions if low <= p.get('confidence', 0.5) < high]
        if in_bin:
            acc = sum(1 for p in in_bin if p['actual'] == p['predicted']) / len(in_bin)
            conf_accuracy.append(acc)
            conf_labels.append(f'{low:.1f}-{high:.1f}')
    
    if conf_accuracy:
        ax6.bar(conf_labels, conf_accuracy, color='purple', alpha=0.7)
        ax6.set_xlabel('Confidence Range')
        ax6.set_ylabel('Accuracy')
        ax6.set_title('Accuracy by Confidence Level', fontsize=14)
        ax6.set_ylim(0, 1.1)
    
    plt.tight_layout()
    
    # Save plots
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    plot_file = output_dir / f'analysis_plots_{timestamp}.png'
    plt.savefig(plot_file, dpi=300, bbox_inches='tight')
    print(f"✓ Plots saved to: {plot_file}")
    
    # Create summary report
    create_summary_report(data, output_dir, timestamp)

def create_summary_report(data, output_dir, timestamp):
    """Create a text summary report"""
    report_file = output_dir / f'report_{timestamp}.txt'
    
    with open(report_file, 'w') as f:
        f.write("ZERO-DAY DETECTION SYSTEM - PERFORMANCE REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Samples: {data['samples']['total']}\n")
        f.write(f"  - Zero-days: {data['samples']['zero_days']}\n")
        f.write(f"  - Regular CVEs: {data['samples']['regular']}\n")
        f.write("\n")
        
        f.write("PERFORMANCE METRICS\n")
        f.write("-" * 30 + "\n")
        metrics = data['metrics']
        f.write(f"Accuracy:  {metrics['accuracy']:.1%}\n")
        f.write(f"Precision: {metrics['precision']:.1%}\n")
        f.write(f"Recall:    {metrics['recall']:.1%}\n")
        f.write(f"F1-Score:  {metrics['f1']:.3f}\n")
        f.write("\n")
        
        f.write("CONFUSION MATRIX\n")
        f.write("-" * 30 + "\n")
        cm = data['confusion_matrix']
        f.write("                 Predicted\n")
        f.write("              Zero-day  Regular\n")
        f.write(f"Actual Zero-day   {cm['tp']:3d}      {cm['fn']:3d}\n")
        f.write(f"       Regular    {cm['fp']:3d}      {cm['tn']:3d}\n")
        f.write("\n")
        
        f.write("KEY INSIGHTS\n")
        f.write("-" * 30 + "\n")
        if cm['fp'] == 0:
            f.write("✓ PERFECT PRECISION: No false positives!\n")
        if cm['fn'] == 0:
            f.write("✓ PERFECT RECALL: Found all zero-days!\n")
        if metrics['accuracy'] >= 0.8:
            f.write("✓ HIGH ACCURACY: System performs well overall\n")
        
        f.write(f"\nDetailed results: {output_dir / f'complete_test_{timestamp}.json'}\n")
    
    print(f"✓ Report saved to: {report_file}")

def main():
    parser = argparse.ArgumentParser(description='Complete test with visualizations')
    parser.add_argument('--zero-days', type=int, default=25, help='Number of zero-days')
    parser.add_argument('--regular', type=int, default=25, help='Number of regular CVEs')
    parser.add_argument('--parallel', action='store_true', help='Run agents in parallel')
    args = parser.parse_args()
    
    print("🚀 Complete Zero-Day Detection Test with Visualizations")
    print("=" * 60)
    print(f"Zero-days: {args.zero_days}")
    print(f"Regular CVEs: {args.regular}")
    print(f"Total samples: {args.zero_days + args.regular}")
    print(f"Parallel execution: {args.parallel}")
    print("=" * 60)
    
    # Initialize
    collector = DataCollector()
    preprocessor = DataPreprocessor()
    monitor = RealTimeMonitor()
    
    # 1. Collect data
    print("\n📊 Phase 1: Collecting balanced data...")
    cisa_data = collector.fetch_cisa_zero_days(max_count=args.zero_days * 2, use_cache=False)[:args.zero_days]
    nvd_data = collector.fetch_nvd_regular_cves(max_count=args.regular * 2)[:args.regular]
    
    print(f"  ✓ Collected {len(cisa_data)} zero-days")
    print(f"  ✓ Collected {len(nvd_data)} regular CVEs")
    
    # 2. Preprocess
    print("\n🔧 Phase 2: Preprocessing data...")
    all_data = []
    
    for cve in cisa_data:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = True
            all_data.append(processed)
    
    for cve in nvd_data:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = False
            all_data.append(processed)
    
    random.shuffle(all_data)
    print(f"  ✓ Total samples: {len(all_data)}")
    
    # 3. Initialize system
    print("\n🤖 Phase 3: Initializing system...")
    system = MultiAgentSystem(
        use_thompson_sampling=False,
        parallel_execution=args.parallel
    )
    
    # 4. Run analysis with real-time monitoring
    print("\n🔍 Phase 4: Analyzing CVEs with real-time monitoring...")
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
            monitor.print_realtime_stats(i, len(all_data))
    
    # 5. Final results
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
    
    # 6. Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path('results')
    results_file = output_dir / f'complete_test_{timestamp}.json'
    
    with open(results_file, 'w') as f:
        json.dump({
            'test_type': 'complete_with_visualizations',
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
    
    # 7. Create visualizations
    create_visualizations(results_file, output_dir)
    
    print("\n✅ Test completed successfully!")

if __name__ == "__main__":
    main()