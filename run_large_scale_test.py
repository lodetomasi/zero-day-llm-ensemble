#!/usr/bin/env python3
"""
Large-scale testing system with caching and batch processing
Designed to minimize API costs while maintaining accuracy
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

import json
import time
import os
from datetime import datetime
import pandas as pd
from detect_zero_days import ZeroDayDetector
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

class CachedDetector:
    """Wrapper for ZeroDayDetector with caching capabilities"""
    
    def __init__(self, cache_dir="cache"):
        self.detector = ZeroDayDetector()
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "detection_cache.json"
        self.cache = self._load_cache()
        
    def _load_cache(self):
        """Load existing cache"""
        if self.cache_file.exists():
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_cache(self):
        """Save cache to disk"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def detect(self, cve_id, force_refresh=False):
        """Detect with caching"""
        if not force_refresh and cve_id in self.cache:
            print(f"  📦 Using cached result for {cve_id}")
            return self.cache[cve_id]
        
        # Run detection
        result = self.detector.detect(cve_id, verbose=False)
        
        # Cache result
        self.cache[cve_id] = result
        self._save_cache()
        
        return result

def run_batch_test(batch_file, cached_detector, ground_truth):
    """Run test on a single batch"""
    with open(batch_file, 'r') as f:
        batch = json.load(f)
    
    results = {}
    for cve_id, data in batch.items():
        print(f"\n🔍 Testing {cve_id}...")
        try:
            result = cached_detector.detect(cve_id)
            results[cve_id] = {
                'result': result,
                'ground_truth': data['is_zero_day'],
                'correct': result['is_zero_day'] == data['is_zero_day']
            }
            
            status = "✅" if results[cve_id]['correct'] else "❌"
            print(f"  {status} Prediction: {'Zero-day' if result['is_zero_day'] else 'Not zero-day'}")
            print(f"     Truth: {'Zero-day' if data['is_zero_day'] else 'Not zero-day'}")
            print(f"     Score: {result['detection_score']:.2%}")
            
            # Rate limiting
            time.sleep(1)
            
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results[cve_id] = {
                'error': str(e),
                'ground_truth': data['is_zero_day']
            }
    
    return results

def analyze_all_results(all_results):
    """Analyze results from all batches"""
    y_true = []
    y_pred = []
    y_scores = []
    errors = []
    
    for cve_id, data in all_results.items():
        if 'error' in data:
            errors.append(cve_id)
            continue
            
        y_true.append(data['ground_truth'])
        y_pred.append(data['result']['is_zero_day'])
        y_scores.append(data['result']['detection_score'])
    
    if not y_true:
        print("❌ No successful predictions to analyze")
        return
    
    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    
    print("\n" + "="*60)
    print("📊 OVERALL PERFORMANCE METRICS")
    print("="*60)
    print(f"Total CVEs tested: {len(all_results)}")
    print(f"Successful: {len(y_true)}")
    print(f"Errors: {len(errors)}")
    print(f"\nAccuracy: {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"F1 Score: {f1:.2%}")
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"              Predicted")
    print(f"             No    Yes")
    print(f"Actual No    {cm[0,0]:<5} {cm[0,1]}")
    print(f"       Yes   {cm[1,0]:<5} {cm[1,1]}")
    
    # Create visualizations
    create_visualizations(y_true, y_pred, y_scores, all_results)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'total_tested': len(all_results),
        'successful': len(y_true),
        'errors': len(errors)
    }

def create_visualizations(y_true, y_pred, y_scores, all_results):
    """Create performance visualizations"""
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    
    # 1. Confusion Matrix Heatmap
    cm = confusion_matrix(y_true, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0,0])
    axes[0,0].set_title('Confusion Matrix')
    axes[0,0].set_xlabel('Predicted')
    axes[0,0].set_ylabel('Actual')
    
    # 2. Score Distribution
    zero_day_scores = [s for i, s in enumerate(y_scores) if y_true[i]]
    regular_scores = [s for i, s in enumerate(y_scores) if not y_true[i]]
    
    axes[0,1].hist(zero_day_scores, bins=20, alpha=0.7, label='Zero-days', color='red')
    axes[0,1].hist(regular_scores, bins=20, alpha=0.7, label='Regular CVEs', color='blue')
    axes[0,1].set_title('Detection Score Distribution')
    axes[0,1].set_xlabel('Detection Score')
    axes[0,1].set_ylabel('Count')
    axes[0,1].legend()
    axes[0,1].axvline(x=0.7, color='black', linestyle='--', label='Threshold')
    
    # 3. ROC-like curve (score vs ground truth)
    sorted_indices = sorted(range(len(y_scores)), key=lambda i: y_scores[i], reverse=True)
    cumulative_tp = []
    cumulative_fp = []
    
    tp, fp = 0, 0
    for idx in sorted_indices:
        if y_true[idx]:
            tp += 1
        else:
            fp += 1
        cumulative_tp.append(tp)
        cumulative_fp.append(fp)
    
    total_positives = sum(y_true)
    total_negatives = len(y_true) - total_positives
    
    tpr = [tp/total_positives for tp in cumulative_tp] if total_positives > 0 else [0]
    fpr = [fp/total_negatives for fp in cumulative_fp] if total_negatives > 0 else [0]
    
    axes[1,0].plot(fpr, tpr, 'b-', linewidth=2)
    axes[1,0].plot([0, 1], [0, 1], 'k--', alpha=0.5)
    axes[1,0].set_title('ROC-like Curve')
    axes[1,0].set_xlabel('False Positive Rate')
    axes[1,0].set_ylabel('True Positive Rate')
    axes[1,0].grid(True, alpha=0.3)
    
    # 4. Performance by CVE year
    years = {}
    for cve_id, data in all_results.items():
        if 'error' in data:
            continue
        year = cve_id.split('-')[1]
        if year not in years:
            years[year] = {'correct': 0, 'total': 0}
        years[year]['total'] += 1
        if data['correct']:
            years[year]['correct'] += 1
    
    sorted_years = sorted(years.keys())
    accuracies = [years[y]['correct']/years[y]['total'] if years[y]['total'] > 0 else 0 for y in sorted_years]
    
    axes[1,1].bar(sorted_years, accuracies)
    axes[1,1].set_title('Accuracy by CVE Year')
    axes[1,1].set_xlabel('Year')
    axes[1,1].set_ylabel('Accuracy')
    axes[1,1].set_ylim(0, 1.1)
    
    # Add accuracy labels
    for i, (year, acc) in enumerate(zip(sorted_years, accuracies)):
        axes[1,1].text(i, acc + 0.02, f'{acc:.0%}', ha='center')
    
    plt.tight_layout()
    plt.savefig('large_scale_test_results.png', dpi=300, bbox_inches='tight')
    print("\n📊 Visualizations saved to large_scale_test_results.png")
    plt.close()

def main():
    print("🚀 Large-Scale Zero-Day Detection Test")
    print("="*60)
    
    # Check if we should use cache or force refresh
    use_cache = input("\nUse cached results where available? (y/n): ").lower() == 'y'
    
    # Initialize cached detector
    detector = CachedDetector()
    
    # Load dataset info
    with open('data/dataset_summary.json', 'r') as f:
        summary = json.load(f)
    
    print(f"\n📊 Dataset Summary:")
    print(f"   - Total CVEs: {summary['total_cves']}")
    print(f"   - Zero-days: {summary['zero_days']}")
    print(f"   - Regular CVEs: {summary['regular_cves']}")
    print(f"   - Batches: {summary['batches']}")
    
    # Test batches
    all_results = {}
    batch_files = sorted(Path('data').glob('test_batch_*.json'))
    
    for i, batch_file in enumerate(batch_files):
        print(f"\n{'='*60}")
        print(f"📦 Processing Batch {i+1}/{len(batch_files)}")
        print(f"{'='*60}")
        
        batch_results = run_batch_test(batch_file, detector, summary)
        all_results.update(batch_results)
        
        # Save intermediate results
        with open(f'results/batch_{i+1}_results.json', 'w') as f:
            json.dump(batch_results, f, indent=2)
        
        # Ask to continue
        if i < len(batch_files) - 1:
            cont = input("\nContinue to next batch? (y/n): ")
            if cont.lower() != 'y':
                break
    
    # Analyze all results
    metrics = analyze_all_results(all_results)
    
    # Save final results
    final_results = {
        'timestamp': datetime.now().isoformat(),
        'metrics': metrics,
        'detailed_results': all_results,
        'dataset_summary': summary
    }
    
    os.makedirs('results', exist_ok=True)
    with open('results/large_scale_test_results.json', 'w') as f:
        json.dump(final_results, f, indent=2)
    
    print("\n✅ Test complete! Results saved to results/large_scale_test_results.json")

if __name__ == "__main__":
    main()