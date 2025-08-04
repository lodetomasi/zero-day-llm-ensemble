#!/usr/bin/env python3
"""
Balance the dataset to have equal zero-days and regular CVEs
"""
import json
import random
from pathlib import Path

def balance_dataset(input_file='data/full_dataset.json', target_size=100):
    """Create a balanced dataset with equal zero-days and regular CVEs"""
    
    # Load full dataset
    with open(input_file, 'r') as f:
        full_data = json.load(f)
    
    # Separate zero-days and regular
    zero_days = {k: v for k, v in full_data.items() if v.get('is_zero_day', False)}
    regular = {k: v for k, v in full_data.items() if not v.get('is_zero_day', False)}
    
    print(f"Full dataset: {len(full_data)} CVEs")
    print(f"  - Zero-days: {len(zero_days)}")
    print(f"  - Regular: {len(regular)}")
    
    # Calculate how many of each to sample
    per_type = target_size // 2
    
    # Sample randomly
    sampled_zero_days = dict(random.sample(list(zero_days.items()), 
                                         min(per_type, len(zero_days))))
    sampled_regular = dict(random.sample(list(regular.items()), 
                                       min(per_type, len(regular))))
    
    # Combine
    balanced = {}
    balanced.update(sampled_zero_days)
    balanced.update(sampled_regular)
    
    # Save balanced dataset
    output_file = f'data/balanced_dataset_{target_size}.json'
    with open(output_file, 'w') as f:
        json.dump(balanced, f, indent=2)
    
    print(f"\n✅ Created balanced dataset: {output_file}")
    print(f"   Total: {len(balanced)} CVEs")
    print(f"   Zero-days: {len(sampled_zero_days)}")
    print(f"   Regular: {len(sampled_regular)}")
    
    return output_file

if __name__ == "__main__":
    import sys
    
    # Get target size from command line or use default
    target_size = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    
    # Create balanced datasets of different sizes
    balance_dataset(target_size=target_size)
    
    # Also create common sizes
    if target_size == 100:
        balance_dataset(target_size=200)
        balance_dataset(target_size=500)