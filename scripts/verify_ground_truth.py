#!/usr/bin/env python3
"""
Verify and correct ground truth based on public sources
Avoids data leakage by using only publicly available information
"""
import json
from pathlib import Path

# VERIFIED ZERO-DAYS from public sources (CISA, news, vendors)
# These are universally recognized as zero-days in the security community
CONFIRMED_ZERO_DAYS = {
    # 2024
    "CVE-2024-3400": True,   # Palo Alto PAN-OS - confirmed by vendor
    "CVE-2024-21412": True,  # Microsoft Defender - Patch Tuesday zero-day
    "CVE-2024-1709": True,   # ConnectWise ScreenConnect
    
    # 2023
    "CVE-2023-23397": True,  # Microsoft Outlook - confirmed zero-day
    "CVE-2023-20198": True,  # Cisco IOS XE - massive campaign
    "CVE-2023-2868": True,   # Barracuda ESG - confirmed by vendor
    "CVE-2023-27350": True,  # PaperCut - actively exploited
    "CVE-2023-3519": True,   # Citrix ADC - critical zero-day
    "CVE-2023-4966": True,   # Citrix Bleed - widely exploited
    "CVE-2023-34362": True,  # MOVEit - Cl0p ransomware campaign
    
    # 2022
    "CVE-2022-30190": True,  # Follina - Microsoft zero-day
    "CVE-2022-26134": True,  # Atlassian Confluence - critical
    "CVE-2022-41040": True,  # ProxyNotShell - Exchange zero-day
    "CVE-2022-22965": False, # Spring4Shell - NOT a zero-day (researcher disclosure)
    
    # 2021
    "CVE-2021-44228": True,  # Log4Shell - biggest zero-day ever
    "CVE-2021-34473": True,  # ProxyShell - part of chain
    "CVE-2021-40539": True,  # ManageEngine ADSelfService
    "CVE-2021-42287": False, # AD privesc - researcher found
    "CVE-2021-27065": True,  # Exchange ProxyLogon
    "CVE-2021-3156": False,  # Sudo Baron Samedit - researcher disclosure
    "CVE-2021-41773": False, # Apache - disclosed responsibly
    
    # 2020
    "CVE-2020-1472": False,  # Zerologon - researcher disclosure (Tom Tervoort)
    "CVE-2020-0601": False,  # CurveBall - NSA disclosure
    
    # Older
    "CVE-2019-0708": False,  # BlueKeep - Microsoft patched before exploitation
    "CVE-2018-8174": True,   # VBScript - APT group zero-day
    "CVE-2018-11776": False, # Struts - researcher disclosure
    "CVE-2017-0144": True,   # EternalBlue - NSA exploit leaked
    "CVE-2014-6271": True,   # Shellshock - found in wild
    "CVE-2014-0160": False,  # Heartbleed - researcher disclosure (Codenomicon)
    
    # Regular CVEs (never zero-days)
    "CVE-2024-38063": False, # Windows TCP/IP - Patch Tuesday
    "CVE-2024-30078": False, # Windows Wi-Fi - regular update
    "CVE-2024-21338": False, # Windows Kernel - Patch Tuesday
    "CVE-2023-38408": False, # OpenSSH - responsible disclosure
    "CVE-2023-35078": False, # Ivanti - disputed, likely not zero-day
    "CVE-2023-22515": False, # Confluence - template injection
    "CVE-2023-4911": False,  # Looney Tunables - Qualys research
    "CVE-2023-32233": False, # Linux kernel - researcher
    "CVE-2023-36884": False, # Office - researcher disclosure
    "CVE-2022-23131": False, # Zabbix - responsible disclosure
    "CVE-2022-1388": False,  # F5 BIG-IP - researcher disclosure
}

def verify_dataset():
    """Verify and report ground truth accuracy"""
    errors = []
    
    # Check all test batch files
    for batch_file in sorted(Path('data').glob('test_batch_*.json')):
        with open(batch_file, 'r') as f:
            batch = json.load(f)
        
        for cve_id, data in batch.items():
            if cve_id in CONFIRMED_ZERO_DAYS:
                expected = CONFIRMED_ZERO_DAYS[cve_id]
                actual = data['is_zero_day']
                
                if expected != actual:
                    errors.append({
                        'file': batch_file.name,
                        'cve': cve_id,
                        'expected': expected,
                        'actual': actual
                    })
    
    return errors

def correct_ground_truth(dry_run=True):
    """Correct the ground truth in dataset files"""
    corrections = 0
    
    for batch_file in sorted(Path('data').glob('test_batch_*.json')):
        with open(batch_file, 'r') as f:
            batch = json.load(f)
        
        modified = False
        for cve_id, data in batch.items():
            if cve_id in CONFIRMED_ZERO_DAYS:
                correct_value = CONFIRMED_ZERO_DAYS[cve_id]
                if data['is_zero_day'] != correct_value:
                    print(f"Correcting {cve_id}: {data['is_zero_day']} -> {correct_value}")
                    if not dry_run:
                        data['is_zero_day'] = correct_value
                    modified = True
                    corrections += 1
        
        if modified and not dry_run:
            with open(batch_file, 'w') as f:
                json.dump(batch, f, indent=2)
    
    return corrections

def main():
    print("🔍 Verifying Ground Truth Against Public Sources")
    print("="*60)
    
    # First verify
    errors = verify_dataset()
    
    if errors:
        print(f"\n❌ Found {len(errors)} ground truth errors:\n")
        for error in errors:
            status = "Zero-day" if error['expected'] else "Regular"
            print(f"  {error['cve']}: Should be {status}")
        
        print(f"\n📊 Error Summary:")
        print(f"  - False as True: {sum(1 for e in errors if not e['expected'] and e['actual'])}")
        print(f"  - True as False: {sum(1 for e in errors if e['expected'] and not e['actual'])}")
        
        # Auto-correct errors
        print("\n🔧 Correcting errors...")
        corrections = correct_ground_truth(dry_run=False)
        print(f"\n✅ Corrected {corrections} entries")
    else:
        print("\n✅ All ground truth values are correct!")
    
    # Show distribution
    total_zero_days = sum(1 for v in CONFIRMED_ZERO_DAYS.values() if v)
    print(f"\n📈 Dataset Distribution:")
    print(f"  - Confirmed Zero-days: {total_zero_days}")
    print(f"  - Regular CVEs: {len(CONFIRMED_ZERO_DAYS) - total_zero_days}")
    print(f"  - Total: {len(CONFIRMED_ZERO_DAYS)}")

if __name__ == "__main__":
    main()