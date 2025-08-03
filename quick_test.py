#!/usr/bin/env python3
"""
Quick test script - uses cached results, no API calls needed
Perfect for testing the evaluation pipeline
"""
import json
from pathlib import Path

def quick_test():
    """Run quick tests using cached data"""
    print("🚀 Quick Test Suite (No API Calls)")
    print("="*50)
    
    # 1. Check cache exists
    cache_file = Path('cache/detection_cache.json')
    if not cache_file.exists():
        print("❌ No cached predictions found")
        print("   Run 'python run_large_scale_test.py' first")
        return
    
    with open(cache_file, 'r') as f:
        cache = json.load(f)
    
    print(f"✅ Found {len(cache)} cached predictions\n")
    
    # 2. Calculate metrics
    correct = 0
    total = 0
    tp = fp = tn = fn = 0
    
    for cve_id, pred in cache.items():
        # Load ground truth
        found = False
        for i in range(1, 9):
            batch_file = Path(f'data/test_batch_{i}.json')
            if batch_file.exists():
                with open(batch_file, 'r') as f:
                    batch = json.load(f)
                    if cve_id in batch:
                        true_label = batch[cve_id]['is_zero_day']
                        pred_label = pred['is_zero_day']
                        
                        total += 1
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
                        found = True
                        break
    
    # 3. Calculate metrics
    accuracy = correct / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print("📊 Performance Metrics:")
    print(f"   Accuracy:  {accuracy:.1%}")
    print(f"   Precision: {precision:.1%}")
    print(f"   Recall:    {recall:.1%}")
    print(f"   F1-Score:  {f1:.3f}")
    
    print(f"\n📋 Confusion Matrix:")
    print(f"   True Positives:  {tp}")
    print(f"   True Negatives:  {tn}")
    print(f"   False Positives: {fp}")
    print(f"   False Negatives: {fn}")
    
    # 4. Test statistical significance
    print("\n📈 Statistical Tests:")
    print("   Run: python run_statistical_tests.py")
    
    # 5. Test cross-validation
    print("\n🔄 Cross-Validation:")
    print("   Run: python run_cross_validation.py")
    
    # 6. Test ablation
    print("\n🔬 Ablation Study:")
    print("   Run: python run_ablation_study.py")
    
    print("\n✅ Quick test complete!")
    print("   Use 'python run_complete_evaluation.py' for full suite")

if __name__ == "__main__":
    quick_test()