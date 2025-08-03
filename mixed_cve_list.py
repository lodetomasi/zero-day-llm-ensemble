#!/usr/bin/env python3
"""
Mixed list of 50 CVEs for dynamic dataset acquisition
25 confirmed zero-days + 25 regular CVEs
"""

MIXED_CVE_LIST = [
    # === CONFIRMED ZERO-DAYS (25) ===
    
    # 2024 Zero-days
    "CVE-2024-3400",   # Palo Alto PAN-OS
    "CVE-2024-21412",  # Microsoft Defender SmartScreen
    "CVE-2024-1709",   # ConnectWise ScreenConnect
    "CVE-2024-23397",  # Microsoft Exchange 
    "CVE-2024-28995",  # SolarWinds Serv-U
    
    # 2023 Zero-days
    "CVE-2023-23397",  # Microsoft Outlook
    "CVE-2023-20198",  # Cisco IOS XE
    "CVE-2023-2868",   # Barracuda ESG
    "CVE-2023-27350",  # PaperCut
    "CVE-2023-3519",   # Citrix ADC
    "CVE-2023-4966",   # Citrix NetScaler (CitrixBleed)
    "CVE-2023-28252",  # Windows CLFS
    
    # 2022 Zero-days
    "CVE-2022-30190",  # Follina
    "CVE-2022-26134",  # Atlassian Confluence
    "CVE-2022-41040",  # ProxyNotShell
    "CVE-2022-22047",  # Windows Print Spooler
    
    # 2021 Zero-days
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-34473",  # ProxyShell
    "CVE-2021-40539",  # Zoho ManageEngine
    "CVE-2021-42287",  # Active Directory
    "CVE-2021-26855",  # Exchange ProxyLogon
    
    # Historical Zero-days
    "CVE-2020-1472",   # Zerologon
    "CVE-2017-0144",   # EternalBlue
    "CVE-2014-6271",   # Shellshock
    "CVE-2012-0158",   # MS Office
    
    # === REGULAR CVEs (25) ===
    
    # Recent patches (2024)
    "CVE-2024-38063",  # Windows TCP/IP
    "CVE-2024-38077",  # Windows Remote Desktop
    "CVE-2024-30078",  # Windows Wi-Fi
    "CVE-2024-43491",  # Windows Update
    "CVE-2024-38014",  # Windows Installer
    
    # 2023 Responsible disclosure
    "CVE-2023-35078",  # Ivanti EPMM
    "CVE-2023-22515",  # Atlassian Confluence
    "CVE-2023-38408",  # OpenSSH
    "CVE-2023-4911",   # GNU libc Looney Tunables
    "CVE-2023-32233",  # Linux Kernel
    "CVE-2023-29357",  # Microsoft SharePoint
    
    # 2022 Research discoveries  
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2022-1388",   # F5 BIG-IP
    "CVE-2022-23131",  # Zabbix
    "CVE-2022-31626",  # PHP
    
    # 2021 Coordinated disclosure
    "CVE-2021-3156",   # Sudo Baron Samedit
    "CVE-2021-41773",  # Apache Path Traversal
    "CVE-2021-27065",  # Microsoft Exchange
    "CVE-2021-45046",  # Log4j (follow-up)
    
    # Famous but not zero-day
    "CVE-2019-0708",   # BlueKeep
    "CVE-2018-8174",   # Windows VBScript
    "CVE-2018-11776",  # Apache Struts
    "CVE-2017-5638",   # Apache Struts (Equifax)
    "CVE-2014-0160",   # Heartbleed
    "CVE-2008-0166",   # Debian OpenSSL
]

if __name__ == "__main__":
    print(f"Mixed CVE list created:")
    print(f"- Total: {len(MIXED_CVE_LIST)}")
    print(f"- Zero-days: 25")
    print(f"- Regular CVEs: 25")
    
    # Save to file for reference
    import json
    with open("data/mixed_cve_list.json", "w") as f:
        json.dump({
            "total": len(MIXED_CVE_LIST),
            "zero_days": MIXED_CVE_LIST[:25],
            "regular_cves": MIXED_CVE_LIST[25:],
            "all_cves": MIXED_CVE_LIST
        }, f, indent=2)