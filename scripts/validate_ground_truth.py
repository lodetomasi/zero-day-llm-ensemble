#!/usr/bin/env python3
"""
Validate ground truth labels against CISA KEV database
"""

import json
import requests
from typing import Dict, List, Tuple

def get_cisa_kev_cves() -> set:
    """Fetch all CVEs from CISA KEV"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = requests.get(url, timeout=30)
        data = response.json()
        return {vuln['cveID'] for vuln in data['vulnerabilities']}
    except Exception as e:
        print(f"Error fetching CISA KEV: {e}")
        return set()

def validate_test_file(filename: str = "test_cves_100.json") -> Dict:
    """Validate ground truth labels"""
    # Load test data
    with open(filename, 'r') as f:
        test_data = json.load(f)
    
    # Get CISA KEV CVEs
    print("Fetching CISA KEV database...")
    cisa_cves = get_cisa_kev_cves()
    print(f"Found {len(cisa_cves)} CVEs in CISA KEV")
    
    # Validate each entry
    errors = {
        'false_positives': [],  # Marked as zero-day but not in CISA
        'false_negatives': [],  # Marked as regular but in CISA
        'correct_zero_days': [],
        'correct_regular': []
    }
    
    for entry in test_data:
        cve_id = entry['cve_id']
        expected = entry['expected']
        in_cisa = cve_id in cisa_cves
        
        if expected == 'zero_day' and in_cisa:
            errors['correct_zero_days'].append(cve_id)
        elif expected == 'zero_day' and not in_cisa:
            errors['false_positives'].append(cve_id)
        elif expected == 'regular' and in_cisa:
            errors['false_negatives'].append(cve_id)
        elif expected == 'regular' and not in_cisa:
            errors['correct_regular'].append(cve_id)
    
    return errors

def print_validation_results(errors: Dict):
    """Print validation results"""
    print("\n" + "="*60)
    print("GROUND TRUTH VALIDATION RESULTS")
    print("="*60)
    
    total = sum(len(v) for v in errors.values())
    correct = len(errors['correct_zero_days']) + len(errors['correct_regular'])
    
    print(f"\nTotal CVEs: {total}")
    print(f"Correct labels: {correct} ({correct/total*100:.1f}%)")
    print(f"Incorrect labels: {total-correct} ({(total-correct)/total*100:.1f}%)")
    
    print(f"\n✅ Correctly labeled zero-days: {len(errors['correct_zero_days'])}")
    print(f"✅ Correctly labeled regular: {len(errors['correct_regular'])}")
    
    if errors['false_positives']:
        print(f"\n❌ FALSE POSITIVES (marked zero-day but not in CISA): {len(errors['false_positives'])}")
        for cve in errors['false_positives'][:10]:
            print(f"   - {cve}")
        if len(errors['false_positives']) > 10:
            print(f"   ... and {len(errors['false_positives'])-10} more")
    
    if errors['false_negatives']:
        print(f"\n❌ FALSE NEGATIVES (marked regular but in CISA): {len(errors['false_negatives'])}")
        for cve in errors['false_negatives'][:10]:
            print(f"   - {cve}")
        if len(errors['false_negatives']) > 10:
            print(f"   ... and {len(errors['false_negatives'])-10} more")

def fix_ground_truth(filename: str = "test_cves_100.json"):
    """Fix ground truth based on CISA KEV"""
    # Load test data
    with open(filename, 'r') as f:
        test_data = json.load(f)
    
    # Get CISA KEV CVEs
    cisa_cves = get_cisa_kev_cves()
    
    # Fix labels
    fixed_data = []
    changes = 0
    
    for entry in test_data:
        cve_id = entry['cve_id']
        old_expected = entry['expected']
        
        # Set correct label based on CISA KEV
        if cve_id in cisa_cves:
            new_expected = 'zero_day'
            category = 'known_zero_day'
        else:
            new_expected = 'regular'
            category = 'regular_vulnerability'
        
        if old_expected != new_expected:
            changes += 1
            print(f"Fixed {cve_id}: {old_expected} -> {new_expected}")
        
        fixed_data.append({
            'cve_id': cve_id,
            'expected': new_expected,
            'category': category
        })
    
    # Save fixed data
    fixed_filename = filename.replace('.json', '_fixed.json')
    with open(fixed_filename, 'w') as f:
        json.dump(fixed_data, f, indent=2)
    
    print(f"\n✅ Fixed {changes} labels")
    print(f"Saved to: {fixed_filename}")
    
    # Also update the text file
    txt_filename = filename.replace('.json', '.txt')
    with open(txt_filename, 'w') as f:
        for entry in fixed_data:
            f.write(f"{entry['cve_id']}\n")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Validate ground truth labels')
    parser.add_argument('--fix', action='store_true', help='Fix incorrect labels')
    parser.add_argument('--file', default='test_cves_100.json', help='Test file to validate')
    args = parser.parse_args()
    
    if args.fix:
        fix_ground_truth(args.file)
    else:
        errors = validate_test_file(args.file)
        print_validation_results(errors)

if __name__ == "__main__":
    main()