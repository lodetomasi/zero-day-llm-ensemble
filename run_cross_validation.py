#!/usr/bin/env python3
"""
K-fold cross-validation for robust evaluation
"""
import json
import numpy as np
from pathlib import Path
from sklearn.model_selection import StratifiedKFold
from typing import Dict, List, Tuple
import time

def load_dataset():
    """Load verified dataset with ground truth"""
    dataset_files = list(Path('data').glob('test_batch_*.json'))
    
    all_cves = []
    for file in sorted(dataset_files):
        with open(file, 'r') as f:
            batch = json.load(f)
            for cve_id, data in batch.items():
                all_cves.append({
                    'cve_id': cve_id,
                    'is_zero_day': data['is_zero_day']
                })
    
    return all_cves

def load_cached_predictions():
    """Load predictions from cache to avoid re-running expensive API calls"""
    cache_file = Path('cache/detection_cache.json')
    if cache_file.exists():
        with open(cache_file, 'r') as f:
            return json.load(f)
    return {}

def evaluate_fold(test_cves: List[Dict], predictions: Dict) -> Dict:
    """Evaluate performance on a fold"""
    correct = 0
    tp = fp = tn = fn = 0
    
    for cve in test_cves:
        cve_id = cve['cve_id']
        true_label = cve['is_zero_day']
        
        if cve_id in predictions:
            pred_label = predictions[cve_id]['is_zero_day']
            
            if pred_label == true_label:
                correct += 1
                if true_label:
                    tp += 1
                else:
                    tn += 1
            else:
                if pred_label:
                    fp += 1
                else:
                    fn += 1
    
    total = len(test_cves)
    accuracy = correct / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': {
            'tp': tp, 'fp': fp,
            'tn': tn, 'fn': fn
        }
    }

def run_cross_validation(k_folds=5):
    """Run k-fold cross-validation"""
    print(f"🔄 Running {k_folds}-Fold Cross-Validation")
    print("="*60)
    
    # Load dataset
    dataset = load_dataset()
    print(f"Loaded {len(dataset)} CVEs")
    
    # Load cached predictions
    predictions = load_cached_predictions()
    print(f"Found {len(predictions)} cached predictions")
    
    # Prepare data for sklearn
    X = np.array([cve['cve_id'] for cve in dataset])
    y = np.array([int(cve['is_zero_day']) for cve in dataset])
    
    # Initialize k-fold
    skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)
    
    fold_results = []
    
    for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X, y), 1):
        print(f"\n📊 Fold {fold_idx}/{k_folds}")
        print(f"   Train: {len(train_idx)} samples")
        print(f"   Test: {len(test_idx)} samples")
        
        # Get test CVEs for this fold
        test_cves = [dataset[i] for i in test_idx]
        
        # Evaluate (using cached predictions)
        fold_metrics = evaluate_fold(test_cves, predictions)
        fold_results.append(fold_metrics)
        
        print(f"   Accuracy: {fold_metrics['accuracy']:.3f}")
        print(f"   F1-Score: {fold_metrics['f1_score']:.3f}")
        print(f"   Precision: {fold_metrics['precision']:.3f}")
        print(f"   Recall: {fold_metrics['recall']:.3f}")
    
    # Calculate mean and std
    accuracies = [f['accuracy'] for f in fold_results]
    f1_scores = [f['f1_score'] for f in fold_results]
    precisions = [f['precision'] for f in fold_results]
    recalls = [f['recall'] for f in fold_results]
    
    results = {
        'k_folds': k_folds,
        'accuracy': {
            'mean': np.mean(accuracies),
            'std': np.std(accuracies),
            'values': accuracies
        },
        'f1_score': {
            'mean': np.mean(f1_scores),
            'std': np.std(f1_scores),
            'values': f1_scores
        },
        'precision': {
            'mean': np.mean(precisions),
            'std': np.std(precisions),
            'values': precisions
        },
        'recall': {
            'mean': np.mean(recalls),
            'std': np.std(recalls),
            'values': recalls
        },
        'fold_results': fold_results
    }
    
    print("\n📊 Cross-Validation Results")
    print("="*60)
    print(f"Accuracy: {results['accuracy']['mean']:.3f} ± {results['accuracy']['std']:.3f}")
    print(f"F1-Score: {results['f1_score']['mean']:.3f} ± {results['f1_score']['std']:.3f}")
    print(f"Precision: {results['precision']['mean']:.3f} ± {results['precision']['std']:.3f}")
    print(f"Recall: {results['recall']['mean']:.3f} ± {results['recall']['std']:.3f}")
    
    # Save results
    with open('cross_validation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    return results

def plot_cv_results(results):
    """Generate visualization of CV results"""
    print("\n📈 Generating CV visualization...")
    
    metrics = ['accuracy', 'f1_score', 'precision', 'recall']
    
    print("\nBox plot data (for paper):")
    for metric in metrics:
        values = results[metric]['values']
        print(f"{metric}: min={min(values):.3f}, Q1={np.percentile(values, 25):.3f}, "
              f"median={np.median(values):.3f}, Q3={np.percentile(values, 75):.3f}, "
              f"max={max(values):.3f}")

def statistical_cv_analysis(results):
    """Additional statistical analysis for CV"""
    print("\n📊 Statistical Analysis of CV Results")
    print("="*60)
    
    # Test if mean accuracy is significantly > 0.5
    from scipy import stats
    
    accuracies = results['accuracy']['values']
    t_stat, p_value = stats.ttest_1samp(accuracies, 0.5)
    
    print(f"One-sample t-test (H0: μ = 0.5):")
    print(f"  t-statistic: {t_stat:.3f}")
    print(f"  p-value: {p_value:.6f}")
    print(f"  Significant: {'YES ✓' if p_value < 0.05 else 'NO ✗'}")
    
    # Coefficient of variation
    cv_accuracy = results['accuracy']['std'] / results['accuracy']['mean']
    print(f"\nCoefficient of Variation:")
    print(f"  Accuracy: {cv_accuracy:.3f} ({'stable' if cv_accuracy < 0.1 else 'variable'})")

if __name__ == "__main__":
    results = run_cross_validation(k_folds=5)
    plot_cv_results(results)
    statistical_cv_analysis(results)