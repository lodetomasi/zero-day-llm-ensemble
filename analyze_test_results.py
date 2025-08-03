#!/usr/bin/env python3
"""
Analyze test results and calculate performance metrics
"""
import json
import glob
from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import numpy as np
from datetime import datetime

# Ground truth for test CVEs
GROUND_TRUTH = {
    # Confirmed zero-days
    'CVE-2023-23397': True,  # Microsoft Outlook - Russian APT
    'CVE-2023-20198': True,  # Cisco IOS XE - mass exploitation  
    'CVE-2024-3400': True,   # Palo Alto PAN-OS - state actors
    'CVE-2021-44228': True,  # Log4Shell - mass exploitation
    
    # Not zero-days
    'CVE-2024-38063': False, # Windows TCP/IP - regular CVE
    'CVE-2014-0160': False,  # Heartbleed - coordinated disclosure
}

def load_latest_results():
    """Load the most recent test results for each CVE"""
    results = {}
    
    for cve_id in GROUND_TRUTH.keys():
        # Find all reports for this CVE
        pattern = f"detection_reports/{cve_id}_detection_*.json"
        files = glob.glob(pattern)
        
        if files:
            # Get the most recent file
            latest_file = max(files, key=lambda f: Path(f).stat().st_mtime)
            
            with open(latest_file, 'r') as f:
                data = json.load(f)
                results[cve_id] = data
                
    return results

def analyze_results(results):
    """Analyze detection results and calculate metrics"""
    
    # Prepare data for metrics
    y_true = []
    y_pred = []
    y_scores = []
    confidences = []
    
    print("=== Individual CVE Results ===\n")
    
    for cve_id, ground_truth in GROUND_TRUTH.items():
        if cve_id in results:
            result = results[cve_id]['detection_result']
            prediction = result['is_zero_day']
            score = result['detection_score']
            confidence = result['confidence']
            
            y_true.append(ground_truth)
            y_pred.append(prediction)
            y_scores.append(score)
            confidences.append(confidence)
            
            # Check if prediction is correct
            correct = "✅" if prediction == ground_truth else "❌"
            
            print(f"{cve_id}:")
            print(f"  Ground Truth: {'Zero-day' if ground_truth else 'Not zero-day'}")
            print(f"  Prediction: {'Zero-day' if prediction else 'Not zero-day'} {correct}")
            print(f"  Score: {score:.2%}")
            print(f"  Confidence: {confidence:.2%} ({result['confidence_level']})")
            
            # Show agent predictions
            if 'llm_analysis' in results[cve_id]:
                agent_data = results[cve_id]['llm_analysis']['agent_predictions']
                print("  Agent Predictions:")
                for agent, data in agent_data.items():
                    if 'prediction' in data:
                        print(f"    - {agent}: {data['prediction']:.2f} (conf: {data['confidence']:.2f})")
            print()
    
    # Calculate metrics
    print("\n=== Overall Performance Metrics ===\n")
    
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"F1 Score: {f1:.2%}")
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"              Predicted")
    print(f"             No    Yes")
    print(f"Actual No    {cm[0,0]}     {cm[0,1]}")
    print(f"       Yes   {cm[1,0]}     {cm[1,1]}")
    
    # Average confidence
    avg_confidence = np.mean(confidences)
    print(f"\nAverage Confidence: {avg_confidence:.2%}")
    
    # Confidence by correctness
    correct_predictions = [conf for i, conf in enumerate(confidences) if y_true[i] == y_pred[i]]
    incorrect_predictions = [conf for i, conf in enumerate(confidences) if y_true[i] != y_pred[i]]
    
    if correct_predictions:
        print(f"Avg Confidence (Correct): {np.mean(correct_predictions):.2%}")
    if incorrect_predictions:
        print(f"Avg Confidence (Incorrect): {np.mean(incorrect_predictions):.2%}")
    
    # Detection threshold analysis
    print(f"\n=== Threshold Analysis ===")
    thresholds = [0.5, 0.6, 0.7, 0.8, 0.9]
    for threshold in thresholds:
        y_pred_thresh = [score >= threshold for score in y_scores]
        acc = accuracy_score(y_true, y_pred_thresh)
        prec = precision_score(y_true, y_pred_thresh) if any(y_pred_thresh) else 0
        rec = recall_score(y_true, y_pred_thresh)
        print(f"Threshold {threshold}: Acc={acc:.2%}, Prec={prec:.2%}, Rec={rec:.2%}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'avg_confidence': avg_confidence
    }

if __name__ == "__main__":
    print("🔍 Zero-Day Detection Test Results Analysis")
    print("=" * 50)
    
    # Load results
    results = load_latest_results()
    print(f"\nLoaded {len(results)} test results\n")
    
    # Analyze
    metrics = analyze_results(results)
    
    # Save summary
    summary = {
        'timestamp': datetime.now().isoformat(),
        'metrics': metrics,
        'test_size': len(GROUND_TRUTH),
        'zero_day_count': sum(GROUND_TRUTH.values()),
        'regular_cve_count': len(GROUND_TRUTH) - sum(GROUND_TRUTH.values())
    }
    
    with open('test_results_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n✅ Summary saved to test_results_summary.json")