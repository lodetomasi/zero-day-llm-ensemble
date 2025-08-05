#!/usr/bin/env python3
"""
Example of what gets passed to LLMs in the zero-day detection system

This file demonstrates:
- The evidence collected by the crawler
- The features extracted from evidence
- The exact prompt format sent to each LLM agent
- How the system processes LLM responses
"""
import json

def show_llm_example():
    """Show example of what gets passed to LLMs"""
    
    # This is what the system extracts from all the evidence
    features = {
        "in_cisa_kev": 1.0,  # Strong indicator - in CISA Known Exploited Vulnerabilities
        "days_to_kev": -1.0,  # Unknown timeline
        "has_exploit_code": 0.0,  # No public exploits found
        "cvss_score": 0.0,  # Not yet scored
        "social_media_buzz": 0.8,  # High Reddit activity (250+ score posts)
        "apt_association": 0.0,  # No APT groups identified yet
        "ransomware_campaign": 0.0,  # Not used in ransomware
        "emergency_patches": 1.0,  # Rapid patch release
        "has_branded_name": 1.0,  # Has a name (common for serious vulns)
    }
    
    # Evidence summary prepared for LLMs
    evidence_summary = {
        'cve_id': 'CVE-2024-3400',
        'nvd_description': 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software...',
        'cvss_score': 0,
        'cisa_kev': {
            'in_kev': True,
            'date_added': '2024-04-12',
            'vendor': 'Palo Alto Networks',
            'product': 'PAN-OS',
            'vulnerability_name': 'Command Injection Vulnerability'
        },
        'exploit_availability': {
            'exploit_db': 0,
            'github': 0,
        },
        'social_signals': {
            'reddit_posts': 25,
            'reddit_top_score': 250,
            'high_activity_discussions': [
                'Mitigations not effective',
                'Emergency patches released',
                'Guide for identifying exploitation'
            ]
        },
        'key_indicators': [
            'Listed in CISA KEV catalog',
            'High social media activity',
            'Emergency patches released',
            'Vendor acknowledged critical severity'
        ]
    }
    
    print("=== WHAT GETS PASSED TO EACH LLM ===\n")
    
    # Show the actual prompt
    prompt = f"""You are a digital forensics expert specializing in zero-day vulnerability analysis.

Analyze the following vulnerability for zero-day indicators:

CVE ID: CVE-2024-3400

Evidence Summary:
{json.dumps(evidence_summary, indent=2)}

Key Features Detected:
- CISA KEV Status: Yes (Added: 2024-04-12)
- Days to KEV: Unknown
- Exploit Code Available: No
- CVSS Score: Not yet scored
- Social Media Buzz Score: 0.80 (High)
- APT Association: No
- Ransomware Usage: No
- Emergency Patches: Yes
- Has Branded Name: Yes

Provide your analysis in the following format:
1. Zero-day likelihood score (0.0 to 1.0)
2. Confidence level (0.0 to 1.0)
3. Key evidence supporting your assessment
4. Brief reasoning (2-3 sentences)

Consider these factors:
- Presence in CISA KEV is a very strong indicator
- High social media activity suggests active exploitation
- Emergency patches indicate vendor urgency
- Lack of public exploits may mean it's still being kept private"""
    
    print("### PROMPT SENT TO FORENSIC ANALYST ###")
    print(prompt)
    
    print("\n\n### EXAMPLE LLM RESPONSE ###")
    example_response = """Based on my analysis:

1. Zero-day likelihood score: 0.95
2. Confidence level: 0.90
3. Key evidence:
   - Listed in CISA KEV catalog (strongest indicator)
   - Emergency patches released by vendor
   - High social media activity with security community concern
   - Mitigation attempts reported as ineffective
   
4. Reasoning: The inclusion in CISA KEV indicates confirmed exploitation in the wild. The emergency patch release and high community activity, combined with reports of ineffective mitigations, strongly suggest this was an actively exploited zero-day vulnerability before patches were available."""
    
    print(example_response)
    
    print("\n\n### HOW THE SYSTEM PROCESSES THIS ###")
    print("""
The system:
1. Sends the same evidence to 5 different specialized agents
2. Each agent analyzes from their perspective:
   - ForensicAnalyst: Technical indicators
   - PatternDetector: Historical patterns
   - TemporalAnalyst: Timeline anomalies
   - AttributionExpert: Threat actor behavior
   - MetaAnalyst: Cross-validation
   
3. Combines scores using Thompson Sampling weights
4. Makes final decision based on:
   - 60% objective features (CISA KEV, etc.)
   - 30% LLM ensemble consensus
   - 10% threat intelligence signals
""")

if __name__ == "__main__":
    show_llm_example()