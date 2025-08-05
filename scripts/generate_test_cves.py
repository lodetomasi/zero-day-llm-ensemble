#!/usr/bin/env python3
"""
Generate a balanced list of CVEs for testing:
- 50 known zero-days from CISA KEV
- 50 regular vulnerabilities
"""

import json
import random
from datetime import datetime

# Known zero-days from CISA KEV (high-profile cases)
KNOWN_ZERO_DAYS = [
    # 2024
    "CVE-2024-3400",   # Palo Alto Networks GlobalProtect
    "CVE-2024-21413",  # Microsoft Outlook
    "CVE-2024-1709",   # ConnectWise ScreenConnect
    "CVE-2024-21893",  # Ivanti Connect Secure
    "CVE-2024-21887",  # Ivanti Connect Secure
    
    # 2023  
    "CVE-2023-20198",  # Cisco IOS XE
    "CVE-2023-3519",   # Citrix ADC
    "CVE-2023-2868",   # Barracuda ESG
    "CVE-2023-27350",  # PaperCut
    "CVE-2023-34362",  # MOVEit Transfer
    "CVE-2023-46604",  # Apache ActiveMQ
    "CVE-2023-22515",  # Atlassian Confluence
    "CVE-2023-28252",  # Windows CLFS
    "CVE-2023-23397",  # Microsoft Outlook
    "CVE-2023-20269",  # Cisco ASA
    
    # 2022
    "CVE-2022-40684",  # Fortinet FortiOS
    "CVE-2022-41040",  # Exchange ProxyNotShell
    "CVE-2022-41082",  # Exchange ProxyNotShell  
    "CVE-2022-47966",  # Zoho ManageEngine
    "CVE-2022-42475",  # Fortinet SSL-VPN
    "CVE-2022-26134",  # Atlassian Confluence
    "CVE-2022-1388",   # F5 BIG-IP
    "CVE-2022-22972",  # VMware Workspace ONE
    "CVE-2022-22954",  # VMware Workspace ONE
    "CVE-2022-30190",  # Follina
    
    # 2021
    "CVE-2021-44228",  # Log4j (Log4Shell)
    "CVE-2021-40539",  # Zoho ManageEngine
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2021-21972",  # VMware vCenter
    "CVE-2021-26855",  # Exchange ProxyLogon
    "CVE-2021-26857",  # Exchange ProxyLogon
    "CVE-2021-26858",  # Exchange ProxyLogon
    "CVE-2021-27065",  # Exchange ProxyLogon
    "CVE-2021-35211",  # SolarWinds Serv-U
    "CVE-2021-34473",  # Exchange ProxyShell
    
    # 2020
    "CVE-2020-1472",   # Zerologon
    "CVE-2020-0601",   # Windows CryptoAPI
    "CVE-2020-5902",   # F5 BIG-IP
    "CVE-2020-3452",   # Cisco ASA
    "CVE-2020-2021",   # Palo Alto Networks
    "CVE-2020-14882",  # Oracle WebLogic
    "CVE-2020-25213",  # WordPress File Manager
    "CVE-2020-17144",  # Exchange
    "CVE-2020-10189",  # Zoho ManageEngine
    "CVE-2020-0688",   # Exchange
    
    # Older but significant
    "CVE-2019-19781",  # Citrix ADC
    "CVE-2019-11510",  # Pulse Secure VPN
    "CVE-2019-0708",   # BlueKeep
    "CVE-2018-13379",  # Fortinet FortiGate
    "CVE-2017-11882",  # Microsoft Office
    "CVE-2017-0144",   # EternalBlue
    "CVE-2017-0143",   # EternalBlue
    "CVE-2017-5638",   # Apache Struts
    "CVE-2016-4117",   # Adobe Flash
    "CVE-2014-0160",   # Heartbleed
]

# Regular vulnerabilities (non zero-days)
REGULAR_CVES = [
    # Recent Chrome/Browser bugs
    "CVE-2023-1234",   # Chrome intent spoofing
    "CVE-2023-4863",   # Chrome WebP
    "CVE-2023-3079",   # Chrome V8
    "CVE-2023-2033",   # Chrome V8
    "CVE-2022-4262",   # Chrome V8
    "CVE-2022-3723",   # Chrome V8
    "CVE-2022-2294",   # Chrome WebRTC
    "CVE-2021-30563",  # Chrome V8
    "CVE-2021-21220",  # Chrome V8
    "CVE-2020-6507",   # Chrome V8
    
    # Linux kernel vulnerabilities
    "CVE-2023-35001",  # Linux kernel nftables
    "CVE-2023-32233",  # Linux kernel netfilter
    "CVE-2023-2124",   # Linux kernel XFS
    "CVE-2022-34918",  # Linux kernel netfilter
    "CVE-2022-2588",   # Linux kernel
    "CVE-2021-33909",  # Linux kernel (Sequoia)
    "CVE-2021-22555",  # Linux kernel netfilter
    "CVE-2020-14386",  # Linux kernel
    "CVE-2019-15666",  # Linux kernel
    "CVE-2017-5754",   # Meltdown
    
    # Common application vulnerabilities
    "CVE-2023-38408",  # OpenSSH
    "CVE-2023-32784",  # KeePass
    "CVE-2023-28531",  # OpenSSH
    "CVE-2023-25690",  # Apache HTTP Server
    "CVE-2023-25136",  # OpenSSH
    "CVE-2022-23812",  # Node.js
    "CVE-2022-23307",  # Apache Log4j
    "CVE-2022-22965",  # Spring Framework
    "CVE-2022-0778",   # OpenSSL
    "CVE-2021-45046",  # Log4j (follow-up)
    
    # Database vulnerabilities
    "CVE-2023-21980",  # Oracle Database
    "CVE-2022-21500",  # Oracle Database
    "CVE-2021-2471",   # MySQL
    "CVE-2020-14812",  # MySQL
    "CVE-2019-2627",   # MySQL
    "CVE-2023-34034",  # VMware Tools
    "CVE-2023-20867",  # VMware Tools
    "CVE-2022-31626",  # PHP
    "CVE-2022-31625",  # PHP
    "CVE-2021-21703",  # PHP
    
    # More application vulnerabilities
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2023-38545",  # cURL
    "CVE-2023-38546",  # cURL
    "CVE-2023-32002",  # Node.js
    "CVE-2023-30547",  # Node.js
    "CVE-2023-29489",  # cPanel
    "CVE-2023-29357",  # Microsoft SharePoint
    "CVE-2023-28303",  # Windows SNMP
    "CVE-2023-24932",  # Windows Secure Boot
    "CVE-2023-24880",  # Windows SmartScreen
]

def generate_test_list():
    """Generate a balanced test list of 100 CVEs"""
    # Take first 50 from each list
    zero_days = KNOWN_ZERO_DAYS[:50]
    regular = REGULAR_CVES[:50]
    
    # If we don't have enough, pad with generated ones
    if len(zero_days) < 50:
        print(f"Warning: Only {len(zero_days)} known zero-days available")
    
    if len(regular) < 50:
        # Generate some recent CVE IDs that are likely regular vulnerabilities
        for year in [2023, 2022, 2021]:
            for i in range(50 - len(regular)):
                regular.append(f"CVE-{year}-{random.randint(10000, 40000)}")
            if len(regular) >= 50:
                break
    
    # Create the test list
    test_cves = []
    
    # Add zero-days
    for cve in zero_days[:50]:
        test_cves.append({
            "cve_id": cve,
            "expected": "zero_day",
            "category": "known_zero_day"
        })
    
    # Add regular CVEs
    for cve in regular[:50]:
        test_cves.append({
            "cve_id": cve,
            "expected": "regular",
            "category": "regular_vulnerability"
        })
    
    # Shuffle to randomize order
    random.shuffle(test_cves)
    
    return test_cves

def main():
    """Generate and save test CVE list"""
    test_cves = generate_test_list()
    
    # Save to JSON
    with open('test_cves_100.json', 'w') as f:
        json.dump(test_cves, f, indent=2)
    
    # Save just the CVE IDs to a text file
    with open('test_cves_100.txt', 'w') as f:
        for item in test_cves:
            f.write(f"{item['cve_id']}\n")
    
    # Print summary
    print("✅ Generated test list with 100 CVEs:")
    print(f"   - {sum(1 for c in test_cves if c['expected'] == 'zero_day')} known zero-days")
    print(f"   - {sum(1 for c in test_cves if c['expected'] == 'regular')} regular vulnerabilities")
    print("\nFiles created:")
    print("   - test_cves_100.json (with metadata)")
    print("   - test_cves_100.txt (just CVE IDs)")
    
    # Show sample
    print("\nFirst 10 CVEs in test:")
    for item in test_cves[:10]:
        print(f"   {item['cve_id']} ({item['expected']})")

if __name__ == "__main__":
    main()