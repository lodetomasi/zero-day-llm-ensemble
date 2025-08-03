#!/usr/bin/env python3
"""
Quick test for zero-day detection - uses small subset for faster results
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from detect_zero_days import ZeroDayDetector
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import time

def quick_test():
    """Run quick test on small subset"""
    
    # Small test set with known ground truth
    test_cases = [
        # Confirmed zero-days
        ('CVE-2023-23397', True, 'Microsoft Outlook - Russian APT'),
        ('CVE-2023-20198', True, 'Cisco IOS XE - mass exploitation'),
        ('CVE-2024-3400', True, 'Palo Alto PAN-OS - state actors'),
        
        # Confirmed non zero-days
        ('CVE-2021-44228', False, 'Log4Shell - research disclosure'),
        ('CVE-2014-0160', False, 'Heartbleed - coordinated disclosure'),
        ('CVE-2024-38063', False, 'Windows TCP/IP - patched before exploit')
    ]
    
    print("🚀 Quick Zero-Day Detection Test")
    print("="*60)
    print(f"Testing {len(test_cases)} CVEs...")
    print()
    
    detector = ZeroDayDetector()
    results = []
    ground_truth = []
    predictions = []
    
    start_time = time.time()
    
    for cve_id, is_zero_day, description in test_cases:
        print(f"Testing {cve_id} ({description})...")
        
        try:
            result = detector.detect(cve_id, verbose=False)
            
            results.append(result)
            ground_truth.append(is_zero_day)
            predictions.append(result['is_zero_day'])
            
            # Show result
            icon = "✅" if result['is_zero_day'] == is_zero_day else "❌"
            print(f"  {icon} Predicted: {'Zero-day' if result['is_zero_day'] else 'Regular'}")
            print(f"     Score: {result['detection_score']:.2%}, Confidence: {result['confidence_level']}")
            print()
            
        except Exception as e:
            print(f"  ⚠️ Error: {e}")
            predictions.append(False)
            print()
    
    # Calculate metrics
    elapsed = time.time() - start_time
    accuracy = accuracy_score(ground_truth, predictions)
    precision = precision_score(ground_truth, predictions)
    recall = recall_score(ground_truth, predictions)
    f1 = f1_score(ground_truth, predictions)
    
    print("="*60)
    print("📊 RESULTS")
    print("="*60)
    print(f"Accuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"F1-Score:  {f1:.3f}")
    print(f"\nTime: {elapsed:.1f} seconds")
    print(f"Avg per CVE: {elapsed/len(test_cases):.1f} seconds")
    
    # Show confusion
    tp = sum(1 for gt, pred in zip(ground_truth, predictions) if gt and pred)
    tn = sum(1 for gt, pred in zip(ground_truth, predictions) if not gt and not pred)
    fp = sum(1 for gt, pred in zip(ground_truth, predictions) if not gt and pred)
    fn = sum(1 for gt, pred in zip(ground_truth, predictions) if gt and not pred)
    
    print(f"\nConfusion Matrix:")
    print(f"TP: {tp} | FP: {fp}")
    print(f"FN: {fn} | TN: {tn}")

if __name__ == "__main__":
    quick_test()