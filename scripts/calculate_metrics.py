#!/usr/bin/env python3
"""
Calculate metrics for zero-day detection evaluation
"""

import json
from typing import Dict, List, Tuple
import argparse

def load_ground_truth(filename: str = "test_cves_100.json") -> Dict[str, str]:
    """Load ground truth labels"""
    with open(filename, 'r') as f:
        data = json.load(f)
    return {item['cve_id']: item['expected'] for item in data}

def load_predictions(filename: str) -> Dict[str, bool]:
    """Load prediction results"""
    predictions = {}
    
    # Handle different formats
    if filename.endswith('.json'):
        with open(filename, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                # List of results
                for item in data:
                    if 'cve_id' in item and 'is_zero_day' in item:
                        predictions[item['cve_id']] = item['is_zero_day']
            elif isinstance(data, dict):
                # Single result
                if 'cve_id' in data and 'is_zero_day' in data:
                    predictions[data['cve_id']] = data['is_zero_day']
    else:
        # Try to parse text output
        with open(filename, 'r') as f:
            content = f.read()
            # Simple parsing - look for CVE IDs and results
            lines = content.split('\n')
            current_cve = None
            for line in lines:
                if 'CVE-' in line and 'Analyzing' in line:
                    # Extract CVE ID
                    parts = line.split()
                    for part in parts:
                        if part.startswith('CVE-'):
                            current_cve = part.strip('...')
                elif current_cve and ('ZERO-DAY DETECTED' in line or 'NOT A ZERO-DAY' in line):
                    predictions[current_cve] = 'ZERO-DAY DETECTED' in line
                    current_cve = None
    
    return predictions

def calculate_metrics(ground_truth: Dict[str, str], predictions: Dict[str, bool]) -> Dict:
    """Calculate evaluation metrics"""
    tp = fp = tn = fn = 0
    
    for cve_id, true_label in ground_truth.items():
        if cve_id not in predictions:
            print(f"Warning: No prediction for {cve_id}")
            continue
            
        predicted = predictions[cve_id]
        is_zero_day_truth = (true_label == 'zero_day')
        
        if is_zero_day_truth and predicted:
            tp += 1
        elif is_zero_day_truth and not predicted:
            fn += 1
        elif not is_zero_day_truth and predicted:
            fp += 1
        elif not is_zero_day_truth and not predicted:
            tn += 1
    
    total = tp + fp + tn + fn
    
    # Calculate metrics
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Matthews Correlation Coefficient
    mcc_num = (tp * tn) - (fp * fn)
    mcc_den = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = mcc_num / mcc_den if mcc_den > 0 else 0
    
    return {
        'total': total,
        'true_positives': tp,
        'false_positives': fp,
        'true_negatives': tn,
        'false_negatives': fn,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'mcc': mcc,
        'specificity': tn / (tn + fp) if (tn + fp) > 0 else 0,
        'false_positive_rate': fp / (fp + tn) if (fp + tn) > 0 else 0,
        'false_negative_rate': fn / (fn + tp) if (fn + tp) > 0 else 0
    }

def print_metrics(metrics: Dict, ground_truth: Dict[str, str], predictions: Dict[str, bool]):
    """Print metrics in a nice format"""
    print("\n" + "="*60)
    print("EVALUATION METRICS")
    print("="*60)
    
    # Ground truth distribution
    zero_days_truth = sum(1 for v in ground_truth.values() if v == 'zero_day')
    regular_truth = len(ground_truth) - zero_days_truth
    
    print(f"\nGround Truth Distribution:")
    print(f"  Zero-days: {zero_days_truth}")
    print(f"  Regular: {regular_truth}")
    print(f"  Total: {len(ground_truth)}")
    
    print(f"\nPredictions Coverage:")
    print(f"  Analyzed: {metrics['total']}/{len(ground_truth)} ({metrics['total']/len(ground_truth)*100:.1f}%)")
    
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"              Zero-day  Regular")
    print(f"  Zero-day      {metrics['true_positives']:3d}      {metrics['false_negatives']:3d}")
    print(f"  Regular       {metrics['false_positives']:3d}      {metrics['true_negatives']:3d}")
    
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy:    {metrics['accuracy']:.3f} ({metrics['accuracy']*100:.1f}%)")
    print(f"  Precision:   {metrics['precision']:.3f} ({metrics['precision']*100:.1f}%)")
    print(f"  Recall:      {metrics['recall']:.3f} ({metrics['recall']*100:.1f}%)")
    print(f"  F1 Score:    {metrics['f1_score']:.3f}")
    print(f"  MCC:         {metrics['mcc']:.3f}")
    print(f"  Specificity: {metrics['specificity']:.3f} ({metrics['specificity']*100:.1f}%)")
    
    print(f"\nError Rates:")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.3f} ({metrics['false_positive_rate']*100:.1f}%)")
    print(f"  False Negative Rate: {metrics['false_negative_rate']:.3f} ({metrics['false_negative_rate']*100:.1f}%)")
    
    # Show examples of errors
    if metrics['false_positives'] > 0:
        print(f"\nFalse Positives (predicted zero-day but actually regular):")
        count = 0
        for cve_id, true_label in ground_truth.items():
            if cve_id in predictions and true_label == 'regular' and predictions[cve_id]:
                print(f"  - {cve_id}")
                count += 1
                if count >= 5:
                    break
    
    if metrics['false_negatives'] > 0:
        print(f"\nFalse Negatives (predicted regular but actually zero-day):")
        count = 0
        for cve_id, true_label in ground_truth.items():
            if cve_id in predictions and true_label == 'zero_day' and not predictions[cve_id]:
                print(f"  - {cve_id}")
                count += 1
                if count >= 5:
                    break

def main():
    parser = argparse.ArgumentParser(description='Calculate zero-day detection metrics')
    parser.add_argument('predictions', help='Predictions file (JSON or text output)')
    parser.add_argument('--ground-truth', default='test_cves_100.json', 
                       help='Ground truth file (default: test_cves_100.json)')
    parser.add_argument('--save', help='Save metrics to JSON file')
    
    args = parser.parse_args()
    
    # Load data
    ground_truth = load_ground_truth(args.ground_truth)
    predictions = load_predictions(args.predictions)
    
    # Calculate metrics
    metrics = calculate_metrics(ground_truth, predictions)
    
    # Print results
    print_metrics(metrics, ground_truth, predictions)
    
    # Save if requested
    if args.save:
        with open(args.save, 'w') as f:
            json.dump(metrics, f, indent=2)
        print(f"\nMetrics saved to: {args.save}")

if __name__ == "__main__":
    main()