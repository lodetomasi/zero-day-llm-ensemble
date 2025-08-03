#!/usr/bin/env python3
"""
Create a large balanced dataset for academic evaluation
"""
import json
import random
from datetime import datetime

# Expanded list of verified zero-days (50+)
VERIFIED_ZERO_DAYS_LARGE = [
    # 2024
    "CVE-2024-3400", "CVE-2024-21412", "CVE-2024-1709", "CVE-2024-23692",
    "CVE-2024-0519", "CVE-2024-21893", "CVE-2024-20399", "CVE-2024-3273",
    
    # 2023  
    "CVE-2023-23397", "CVE-2023-20198", "CVE-2023-2868", "CVE-2023-27350",
    "CVE-2023-3519", "CVE-2023-4966", "CVE-2023-34362", "CVE-2023-46604",
    "CVE-2023-28121", "CVE-2023-29357", "CVE-2023-32233", "CVE-2023-20073",
    "CVE-2023-28252", "CVE-2023-21839", "CVE-2023-22952", "CVE-2023-28310",
    
    # 2022
    "CVE-2022-30190", "CVE-2022-26134", "CVE-2022-41040", "CVE-2022-41082",
    "CVE-2022-47966", "CVE-2022-27925", "CVE-2022-37969", "CVE-2022-35914",
    "CVE-2022-42475", "CVE-2022-41049", "CVE-2022-26904", "CVE-2022-24521",
    
    # 2021
    "CVE-2021-44228", "CVE-2021-34473", "CVE-2021-40539", "CVE-2021-27065",
    "CVE-2021-26855", "CVE-2021-21972", "CVE-2021-1675", "CVE-2021-34527",
    "CVE-2021-30116", "CVE-2021-40444", "CVE-2021-42321", "CVE-2021-35464",
    
    # 2020-2018
    "CVE-2020-10189", "CVE-2020-5902", "CVE-2020-14882", "CVE-2020-2551",
    "CVE-2019-19781", "CVE-2019-11510", "CVE-2019-2725", "CVE-2018-13379",
    "CVE-2018-8174", "CVE-2017-0144", "CVE-2014-6271"
]

# Expanded list of regular CVEs (50+)
VERIFIED_REGULAR_CVES_LARGE = [
    # 2024
    "CVE-2024-38063", "CVE-2024-30078", "CVE-2024-21338", "CVE-2024-38077",
    "CVE-2024-38014", "CVE-2024-35250", "CVE-2024-30046", "CVE-2024-26218",
    
    # 2023
    "CVE-2023-38408", "CVE-2023-35078", "CVE-2023-22515", "CVE-2023-4911",
    "CVE-2023-32233", "CVE-2023-36884", "CVE-2023-42793", "CVE-2023-38545",
    "CVE-2023-44487", "CVE-2023-50387", "CVE-2023-5363", "CVE-2023-31047",
    "CVE-2023-33246", "CVE-2023-32435", "CVE-2023-2828", "CVE-2023-25690",
    
    # 2022
    "CVE-2022-22965", "CVE-2022-23131", "CVE-2022-1388", "CVE-2022-26809",
    "CVE-2022-23277", "CVE-2022-29464", "CVE-2022-28219", "CVE-2022-3602",
    "CVE-2022-3786", "CVE-2022-42889", "CVE-2022-40684", "CVE-2022-31626",
    
    # 2021
    "CVE-2021-42287", "CVE-2021-3156", "CVE-2021-41773", "CVE-2021-22205",
    "CVE-2021-25735", "CVE-2021-22986", "CVE-2021-20837", "CVE-2021-3560",
    "CVE-2021-33739", "CVE-2021-36934", "CVE-2021-38647", "CVE-2021-42013",
    
    # 2020-2019
    "CVE-2020-1472", "CVE-2020-0601", "CVE-2019-0708", "CVE-2019-11477",
    "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-1182", "CVE-2018-11776",
    "CVE-2018-7600", "CVE-2014-0160"
]

def create_large_dataset(size=100, balanced=True):
    """Create a large dataset for academic evaluation"""
    
    if balanced:
        # Take equal numbers of zero-days and regular CVEs
        num_each = size // 2
        zero_days = random.sample(VERIFIED_ZERO_DAYS_LARGE, min(num_each, len(VERIFIED_ZERO_DAYS_LARGE)))
        regular = random.sample(VERIFIED_REGULAR_CVES_LARGE, min(num_each, len(VERIFIED_REGULAR_CVES_LARGE)))
        
        all_cves = []
        for cve in zero_days:
            all_cves.append({
                'cve_id': cve,
                'is_zero_day': True,
                'category': 'zero-day'
            })
        
        for cve in regular:
            all_cves.append({
                'cve_id': cve,
                'is_zero_day': False,
                'category': 'regular'
            })
    else:
        # Use all available CVEs
        all_cves = []
        for cve in VERIFIED_ZERO_DAYS_LARGE:
            all_cves.append({
                'cve_id': cve,
                'is_zero_day': True,
                'category': 'zero-day'
            })
        for cve in VERIFIED_REGULAR_CVES_LARGE:
            all_cves.append({
                'cve_id': cve,
                'is_zero_day': False,
                'category': 'regular'
            })
    
    # Shuffle
    random.shuffle(all_cves)
    
    # Create train/test split (70/30)
    split_idx = int(len(all_cves) * 0.7)
    train_set = all_cves[:split_idx]
    test_set = all_cves[split_idx:]
    
    # Save datasets
    dataset = {
        'metadata': {
            'created': datetime.now().isoformat(),
            'total_size': len(all_cves),
            'zero_days': len([c for c in all_cves if c['is_zero_day']]),
            'regular_cves': len([c for c in all_cves if not c['is_zero_day']]),
            'train_size': len(train_set),
            'test_size': len(test_set)
        },
        'full_dataset': {cve['cve_id']: cve for cve in all_cves},
        'train_set': {cve['cve_id']: cve for cve in train_set},
        'test_set': {cve['cve_id']: cve for cve in test_set}
    }
    
    with open('data/large_academic_dataset.json', 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"✅ Created large dataset:")
    print(f"   - Total CVEs: {len(all_cves)}")
    print(f"   - Zero-days: {dataset['metadata']['zero_days']}")
    print(f"   - Regular: {dataset['metadata']['regular_cves']}")
    print(f"   - Train set: {len(train_set)}")
    print(f"   - Test set: {len(test_set)}")
    
    return dataset

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--size', type=int, default=100, help='Dataset size')
    parser.add_argument('--balanced', action='store_true', help='Balance classes')
    args = parser.parse_args()
    
    create_large_dataset(args.size, args.balanced)