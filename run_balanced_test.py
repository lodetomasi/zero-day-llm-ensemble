#!/usr/bin/env python3
"""
Balanced testing system with ground truth verification
- Choose exact number of zero-days and regular CVEs
- Only download missing ones
- Verify ground truth without data leakage
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

import json
import time
import random
import argparse
from datetime import datetime
from typing import Dict, List, Tuple
from detect_zero_days import ZeroDayDetector

# VERIFIED GROUND TRUTH from public sources only (NO data leakage)
VERIFIED_ZERO_DAYS = [
    # 2024 - Confirmed by vendors/CISA
    "CVE-2024-3400",   # Palo Alto PAN-OS
    "CVE-2024-21412",  # Microsoft Defender
    "CVE-2024-1709",   # ConnectWise ScreenConnect
    "CVE-2024-0519",   # Chrome zero-day
    "CVE-2024-21893",  # Ivanti Connect Secure
    
    # 2023 - Public exploitation confirmed
    "CVE-2023-23397",  # Microsoft Outlook
    "CVE-2023-20198",  # Cisco IOS XE
    "CVE-2023-2868",   # Barracuda ESG
    "CVE-2023-27350",  # PaperCut
    "CVE-2023-3519",   # Citrix ADC
    "CVE-2023-4966",   # Citrix Bleed
    "CVE-2023-34362",  # MOVEit
    "CVE-2023-46604",  # Apache ActiveMQ
    "CVE-2023-42793",  # TeamCity
    
    # 2022 - Known zero-days
    "CVE-2022-30190",  # Follina
    "CVE-2022-26134",  # Atlassian Confluence
    "CVE-2022-41040",  # ProxyNotShell
    "CVE-2022-47966",  # Zoho ManageEngine
    "CVE-2022-42475",  # Fortinet FortiOS
    
    # 2021 - Historic zero-days
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-34473",  # ProxyShell
    "CVE-2021-40539",  # ManageEngine ADSelfService
    "CVE-2021-27065",  # Exchange ProxyLogon
    "CVE-2021-30116",  # Kaseya VSA
    
    # Older confirmed
    "CVE-2020-10189",  # Zoho Desktop Central
    "CVE-2020-5902",   # F5 BIG-IP
    "CVE-2019-11510",  # Pulse Secure VPN
    "CVE-2019-19781",  # Citrix ADC
    "CVE-2018-8174",   # Windows VBScript
    "CVE-2017-0144",   # EternalBlue
    "CVE-2014-6271",   # Shellshock
]

VERIFIED_REGULAR_CVES = [
    # 2024 - Responsible disclosures
    "CVE-2024-38063",  # Windows TCP/IP - Patch Tuesday
    "CVE-2024-30078",  # Windows Wi-Fi Driver
    "CVE-2024-21338",  # Windows Kernel
    "CVE-2024-3094",   # XZ Utils backdoor (caught before exploitation)
    "CVE-2024-23692",  # Rejetto HTTP - researcher disclosure
    
    # 2023 - Research findings
    "CVE-2023-38408",  # OpenSSH - responsible disclosure
    "CVE-2023-38545",  # curl SOCKS5 - researcher found
    "CVE-2023-44487",  # HTTP/2 Rapid Reset - research
    "CVE-2023-5363",   # OpenSSL - coordinated
    "CVE-2023-35078",  # Ivanti - disputed timeline
    "CVE-2023-22515",  # Confluence template injection
    "CVE-2023-4911",   # Looney Tunables - Qualys
    "CVE-2023-32233",  # Linux kernel - researcher
    
    # 2022 - Non zero-days
    "CVE-2022-22965",  # Spring4Shell - leaked early
    "CVE-2022-23131",  # Zabbix - responsible disclosure
    "CVE-2022-1388",   # F5 BIG-IP - researcher
    "CVE-2022-3602",   # OpenSSL - pre-announcement
    
    # 2021 - Research disclosures
    "CVE-2021-42287",  # AD sAMAccountName - researcher
    "CVE-2021-3156",   # Sudo Baron Samedit - Qualys
    "CVE-2021-41773",  # Apache path traversal
    
    # 2020 - Famous but not zero-days
    "CVE-2020-1472",   # Zerologon - Tom Tervoort
    "CVE-2020-0601",   # CurveBall - NSA disclosure
    
    # Older research
    "CVE-2019-0708",   # BlueKeep - patched first
    "CVE-2018-11776",  # Apache Struts
    "CVE-2014-0160",   # Heartbleed - Codenomicon
]

class BalancedTester:
    def __init__(self):
        self.detector = ZeroDayDetector()
        self.cache_file = Path('cache/detection_cache.json')
        self.cache = self._load_cache()
        
    def _load_cache(self) -> Dict:
        """Load existing cache"""
        if self.cache_file.exists():
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_cache(self):
        """Save cache"""
        self.cache_file.parent.mkdir(exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def get_cached_stats(self) -> Tuple[List[str], List[str]]:
        """Get lists of cached zero-days and regular CVEs"""
        cached_zero_days = []
        cached_regular = []
        
        for cve_id, result in self.cache.items():
            if 'is_zero_day' in result:
                if result['is_zero_day']:
                    cached_zero_days.append(cve_id)
                else:
                    cached_regular.append(cve_id)
        
        return cached_zero_days, cached_regular
    
    def select_cves(self, n_zero_days: int, n_regular: int) -> Tuple[List[str], List[str]]:
        """Select CVEs to test, using cache when possible"""
        cached_zd, cached_reg = self.get_cached_stats()
        
        print(f"\n📦 Cache Status:")
        print(f"   Cached zero-days: {len(cached_zd)}")
        print(f"   Cached regular: {len(cached_reg)}")
        
        # Select zero-days
        selected_zd = []
        # First, use cached verified zero-days
        cached_verified_zd = [cve for cve in cached_zd if cve in VERIFIED_ZERO_DAYS]
        selected_zd.extend(cached_verified_zd[:n_zero_days])
        
        # If need more, select from verified list
        if len(selected_zd) < n_zero_days:
            remaining = [cve for cve in VERIFIED_ZERO_DAYS 
                        if cve not in selected_zd and cve not in self.cache]
            random.shuffle(remaining)
            selected_zd.extend(remaining[:n_zero_days - len(selected_zd)])
        
        # Select regular CVEs
        selected_reg = []
        # First, use cached verified regular
        cached_verified_reg = [cve for cve in cached_reg if cve in VERIFIED_REGULAR_CVES]
        selected_reg.extend(cached_verified_reg[:n_regular])
        
        # If need more, select from verified list
        if len(selected_reg) < n_regular:
            remaining = [cve for cve in VERIFIED_REGULAR_CVES 
                        if cve not in selected_reg and cve not in self.cache]
            random.shuffle(remaining)
            selected_reg.extend(remaining[:n_regular - len(selected_reg)])
        
        return selected_zd[:n_zero_days], selected_reg[:n_regular]
    
    def test_balanced(self, n_zero_days: int, n_regular: int, delay: int = 3):
        """Run balanced test with specified numbers"""
        print(f"\n🎯 Balanced Test Configuration")
        print(f"   Target zero-days: {n_zero_days}")
        print(f"   Target regular CVEs: {n_regular}")
        print(f"   Total: {n_zero_days + n_regular}")
        
        # Select CVEs
        selected_zd, selected_reg = self.select_cves(n_zero_days, n_regular)
        
        if len(selected_zd) < n_zero_days:
            print(f"\n⚠️  Only {len(selected_zd)} verified zero-days available")
        if len(selected_reg) < n_regular:
            print(f"⚠️  Only {len(selected_reg)} verified regular CVEs available")
        
        # Combine and shuffle
        all_cves = [(cve, True) for cve in selected_zd] + [(cve, False) for cve in selected_reg]
        random.shuffle(all_cves)
        
        # Count what needs testing
        need_testing = [(cve, is_zd) for cve, is_zd in all_cves if cve not in self.cache]
        using_cache = [(cve, is_zd) for cve, is_zd in all_cves if cve in self.cache]
        
        print(f"\n📊 Test Plan:")
        print(f"   Using cache: {len(using_cache)}")
        print(f"   Need testing: {len(need_testing)}")
        
        if need_testing:
            print(f"\n🔄 Testing {len(need_testing)} new CVEs...")
            for i, (cve_id, expected_zd) in enumerate(need_testing, 1):
                print(f"\n[{i}/{len(need_testing)}] Testing {cve_id}")
                print(f"   Ground truth: {'Zero-day' if expected_zd else 'Regular'}")
                
                try:
                    result = self.detector.detect(cve_id, verbose=False)
                    self.cache[cve_id] = result
                    self._save_cache()
                    
                    print(f"   ✅ Detected as: {'Zero-day' if result['is_zero_day'] else 'Regular'}")
                    print(f"   Confidence: {result['confidence']:.1%}")
                    
                except Exception as e:
                    print(f"   ❌ Error: {e}")
                
                if i < len(need_testing):
                    print(f"   ⏱️  Waiting {delay}s...")
                    time.sleep(delay)
        
        # Evaluate all results
        self._evaluate_results(all_cves)
    
    def _evaluate_results(self, test_set: List[Tuple[str, bool]]):
        """Evaluate results against ground truth"""
        print("\n" + "="*60)
        print("📊 EVALUATION RESULTS")
        print("="*60)
        
        correct = 0
        tp = fp = tn = fn = 0
        
        for cve_id, expected_zd in test_set:
            if cve_id in self.cache:
                predicted_zd = self.cache[cve_id].get('is_zero_day', False)
                
                if predicted_zd == expected_zd:
                    correct += 1
                    if expected_zd:
                        tp += 1
                    else:
                        tn += 1
                else:
                    if predicted_zd:
                        fp += 1
                        print(f"\n❌ False Positive: {cve_id}")
                        print(f"   Expected: Regular, Predicted: Zero-day")
                    else:
                        fn += 1
                        print(f"\n❌ False Negative: {cve_id}")
                        print(f"   Expected: Zero-day, Predicted: Regular")
        
        total = len(test_set)
        accuracy = correct / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\n📈 Performance Metrics:")
        print(f"   Accuracy:  {accuracy:.1%} ({correct}/{total})")
        print(f"   Precision: {precision:.1%}")
        print(f"   Recall:    {recall:.1%}")
        print(f"   F1-Score:  {f1:.3f}")
        
        print(f"\n📋 Confusion Matrix:")
        print(f"                 Predicted")
        print(f"                No    Yes")
        print(f"   Actual No    {tn:<5} {fp}")
        print(f"          Yes   {fn:<5} {tp}")
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results = {
            'timestamp': timestamp,
            'config': {
                'n_zero_days': sum(1 for _, is_zd in test_set if is_zd),
                'n_regular': sum(1 for _, is_zd in test_set if not is_zd),
                'total': len(test_set)
            },
            'metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn
            },
            'errors': {
                'false_positives': [cve for cve, exp in test_set 
                                  if not exp and self.cache.get(cve, {}).get('is_zero_day', False)],
                'false_negatives': [cve for cve, exp in test_set 
                                  if exp and not self.cache.get(cve, {}).get('is_zero_day', True)]
            }
        }
        
        output_file = f'results/balanced_test_{timestamp}.json'
        Path('results').mkdir(exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Run balanced test with exact numbers of zero-days and regular CVEs'
    )
    parser.add_argument('--zero-days', type=int,
                       help='Number of zero-day CVEs to test')
    parser.add_argument('--regular', type=int,
                       help='Number of regular CVEs to test')
    parser.add_argument('--delay', type=int, default=3,
                       help='Delay between API calls (seconds)')
    parser.add_argument('--list-available', action='store_true',
                       help='List available verified CVEs')
    
    args = parser.parse_args()
    
    if args.list_available:
        print(f"\n📋 Available Verified CVEs:")
        print(f"   Zero-days: {len(VERIFIED_ZERO_DAYS)}")
        print(f"   Regular: {len(VERIFIED_REGULAR_CVES)}")
        print(f"\nSample zero-days: {', '.join(VERIFIED_ZERO_DAYS[:5])}...")
        print(f"Sample regular: {', '.join(VERIFIED_REGULAR_CVES[:5])}...")
        return
    
    if not args.zero_days or not args.regular:
        parser.error("--zero-days and --regular are required unless using --list-available")
    
    tester = BalancedTester()
    tester.test_balanced(args.zero_days, args.regular, args.delay)

if __name__ == "__main__":
    main()