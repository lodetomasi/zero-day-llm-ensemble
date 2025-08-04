# Dataset Structure Documentation

## Overview
The zero-day detection system uses multiple dataset formats for different purposes.

## 1. Main Dataset Format (`expanded_dataset_60.json`)

Simple format for ground truth labels:

```json
{
  "CVE-2024-3400": {
    "is_zero_day": true,
    "description": "Palo Alto Networks PAN-OS - Command Injection",
    "evidence": "State-sponsored actors, Operation MidnightEclipse"
  },
  "CVE-2021-3156": {
    "is_zero_day": false,
    "description": "Sudo - Heap-based buffer overflow",
    "evidence": "Qualys research team, 10-year old bug"
  }
}
```

### Fields:
- **is_zero_day**: `true` if exploited before patch, `false` otherwise
- **description**: Brief vulnerability description
- **evidence**: Key evidence supporting the classification

## 2. Raw Evidence Format (`data/raw_evidence/CVE-*_raw.json`)

Comprehensive data collected from web scraping:

```json
{
  "cve_id": "CVE-2024-3400",
  "scraped_at": "2025-08-03T18:43:36.614926",
  "sources": {
    "nvd": {
      "found": true,
      "published_date": "2024-04-12T08:15:06.230",
      "cvss_score": 10.0,
      "references": [...],
      "timeline_analysis": {
        "days_between_publish_modify": 231,
        "rapid_update": false
      }
    },
    "cisa_kev": {
      "in_kev": true,
      "date_added": "2024-04-12",
      "vulnerability_name": "Palo Alto Networks PAN-OS Command Injection",
      "required_action": "Apply mitigations..."
    },
    "exploit_db": {
      "exploit_db": true,
      "metasploit": true,
      "exploit_count": 2
    },
    "github": {
      "poc_repos": [...],
      "first_poc_date": "2024-04-15",
      "days_to_first_poc": 3
    },
    "security_news": {
      "articles": [...],
      "zero_day_mentions": 15,
      "first_mention_date": "2024-04-12"
    }
  }
}
```

## 3. Detection Report Format (`detection_reports/CVE-*_enhanced_detection_*.json`)

Complete analysis results:

```json
{
  "detection_result": {
    "cve_id": "CVE-2024-3400",
    "is_zero_day": true,
    "detection_score": 0.6799,
    "confidence": 0.5820,
    "confidence_level": "LOW",
    "threshold_used": 0.30,
    "evidence_summary": {
      "sources_checked": 21,
      "sources_with_data": 18,
      "cisa_kev": true,
      "government_alerts": 0,
      "researcher_analyses": 1,
      "apt_groups": 0,
      "honeypot_activity": true,
      "exploitation_evidence": true
    },
    "key_indicators": [
      "Listed in CISA KEV",
      "Rapid KEV addition (<7 days)",
      "Exploitation before patch",
      "Honeypot detections: 3"
    ]
  },
  "features_extracted": {
    "days_to_kev": 0.0,
    "rapid_kev_addition": 1.0,
    "in_cisa_kev": 1.0,
    "exploitation_before_patch": 1.0,
    "cvss_score": 10.0,
    "apt_group_count": 0.0,
    // ... 40+ more features
  },
  "llm_analysis": {
    "agent_predictions": {
      "ForensicAnalyst": {
        "prediction": 0.8,
        "confidence": 0.7,
        "reasoning": "..."
      },
      // ... other agents
    },
    "ensemble": {
      "prediction": 0.7238,
      "confidence": 0.6334,
      "agreement": 0.8
    }
  }
}
```

## 4. Dataset Summary (`data/expanded_dataset_summary.json`)

Overview of dataset contents:

```json
{
  "total_cves": 60,
  "zero_days": 30,
  "regular_cves": 30,
  "created": "2025-08-04T09:57:23.935423",
  "zero_day_list": [
    "CVE-2024-3400",
    "CVE-2023-20198",
    // ... all zero-day CVEs
  ],
  "regular_cve_list": [
    "CVE-2021-3156",
    "CVE-2024-38063",
    // ... all regular CVEs
  ]
}
```

## Ground Truth Verification

All zero-day classifications are based on:
- **CISA KEV listings** - Known Exploited Vulnerabilities
- **Security vendor reports** - Incident response findings
- **Threat intelligence** - APT campaign associations
- **Public disclosures** - Vendor advisories mentioning active exploitation
- **Academic research** - Published papers on zero-day incidents

Regular CVEs are verified to have:
- **Responsible disclosure** - Credited security researchers
- **No exploitation evidence** - Before patch release
- **Coordinated patches** - Not emergency/out-of-band