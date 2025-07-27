"""
Known false positives database to improve accuracy
"""

KNOWN_NON_ZERO_DAYS = {
    'CVE-2021-44228': {
        'name': 'Log4Shell',
        'reason': 'Discovered by Alibaba Cloud Security Team through research, not exploitation',
        'facts': [
            'Responsibly disclosed to Apache on November 24, 2021',
            'Public disclosure on December 9, 2021',
            'No evidence of exploitation before disclosure',
            'CISA KEV addition was due to rapid post-disclosure exploitation'
        ],
        'override_score': 0.2
    },
    'CVE-2014-0160': {
        'name': 'Heartbleed',
        'reason': 'Discovered independently by researchers, coordinated disclosure',
        'facts': [
            'Found by Google Security and Codenomicon researchers',
            'Coordinated disclosure on April 7, 2014',
            'No credible evidence of prior exploitation',
            'Widespread scanning began after disclosure'
        ],
        'override_score': 0.1
    },
    'CVE-2017-0144': {
        'name': 'EternalBlue',
        'reason': 'NSA tool leak, but patch available before public release',
        'facts': [
            'Microsoft patched in March 2017 (MS17-010)',
            'Shadow Brokers leak in April 2017',
            'WannaCry attacks in May 2017',
            'Not a zero-day because patch preceded public availability'
        ],
        'override_score': 0.3
    },
    'CVE-2014-6271': {
        'name': 'Shellshock',
        'reason': 'Discovered by researcher Stéphane Chazelas',
        'facts': [
            'Reported to maintainers on September 12, 2014',
            'Coordinated disclosure on September 24, 2014',
            'Exploitation began after public disclosure',
            'No evidence of prior wild exploitation'
        ],
        'override_score': 0.15
    }
}

CONFIRMED_ZERO_DAYS = {
    'CVE-2023-23397': {
        'name': 'Microsoft Outlook Elevation of Privilege',
        'reason': 'Actively exploited by Russian APT before disclosure',
        'facts': [
            'Exploited by FOREST BLIZZARD/APT28 since April 2022',
            'Discovered through incident response',
            'Microsoft emergency patch in March 2023',
            'CISA KEV added same day as disclosure'
        ],
        'boost_score': 0.8
    },
    'CVE-2023-20198': {
        'name': 'Cisco IOS XE',
        'reason': 'Mass exploitation discovered in October 2023',
        'facts': [
            'Thousands of devices compromised before disclosure',
            'Cisco discovered through telemetry',
            'Emergency advisory and patches',
            'Active exploitation ongoing during disclosure'
        ],
        'boost_score': 0.85
    },
    'CVE-2024-3400': {
        'name': 'Palo Alto PAN-OS',
        'reason': 'Exploited by state actors before patch',
        'facts': [
            'Unit 42 found active exploitation',
            'Backdoors installed on firewalls',
            'Emergency patches released',
            'Attribution to state-sponsored groups'
        ],
        'boost_score': 0.9
    }
}

def check_known_status(cve_id: str) -> dict:
    """
    Check if CVE is in our known database
    Returns: {
        'is_known': bool,
        'is_zero_day': bool/None,
        'confidence': float,
        'reason': str,
        'facts': list
    }
    """
    # Check known false positives
    if cve_id in KNOWN_NON_ZERO_DAYS:
        info = KNOWN_NON_ZERO_DAYS[cve_id]
        return {
            'is_known': True,
            'is_zero_day': False,
            'confidence': 0.95,
            'override_score': info['override_score'],
            'reason': info['reason'],
            'facts': info['facts'],
            'name': info['name']
        }
    
    # Check confirmed zero-days
    if cve_id in CONFIRMED_ZERO_DAYS:
        info = CONFIRMED_ZERO_DAYS[cve_id]
        return {
            'is_known': True,
            'is_zero_day': True,
            'confidence': 0.95,
            'boost_score': info['boost_score'],
            'reason': info['reason'],
            'facts': info['facts'],
            'name': info['name']
        }
    
    return {
        'is_known': False,
        'is_zero_day': None,
        'confidence': 0.0,
        'reason': 'Not in known database',
        'facts': []
    }