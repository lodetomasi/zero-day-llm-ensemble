# Dynamic Dataset Analysis

## Overview

This document presents the analysis of our dynamically acquired dataset through real-time web scraping from 8 authoritative security sources.

## Data Acquisition Summary

- **Total CVEs Requested**: 50 (mixed zero-days and regular vulnerabilities)
- **Successfully Scraped**: 37 CVEs (74% success rate)
- **Failed Due to Rate Limiting**: 13 CVEs
- **Acquisition Time**: ~20 minutes

## Key Findings

### 1. CISA KEV Coverage
- **81.1% of scraped CVEs are in CISA KEV** (30 out of 37)
- This high percentage validates our focus on actively exploited vulnerabilities
- CISA KEV inclusion is the strongest indicator of zero-day activity

### 2. Source Coverage Statistics

| Source | Coverage | Notes |
|--------|----------|-------|
| NVD | 100% | All CVEs have official NVD entries |
| CISA KEV | 81.1% | Strong indicator of exploitation |
| ExploitDB | 100% | All have public exploits |
| Security News | 94.6% | High media attention |
| GitHub PoCs | Variable | From 0 to 50+ repositories |
| Vendor Advisories | ~75% | Emergency patches common |

### 3. Temporal Patterns

**Year Distribution**:
- 2024: 12 CVEs (most recent)
- 2023: 10 CVEs
- 2022: 8 CVEs
- 2021: 5 CVEs
- 2020 and earlier: 2 CVEs

**Key Observation**: Recent CVEs (2023-2024) show higher zero-day confidence scores, likely due to:
- Better documentation of exploitation timelines
- More complete evidence availability
- Active threat campaigns

### 4. Top Zero-Day Indicators

Based on our analysis, the strongest indicators of zero-day exploitation are:

1. **Rapid CISA KEV Addition** (within 7 days of disclosure)
2. **Emergency/Out-of-band Patches** from vendors
3. **CVSS Score of 9.5+** combined with exploitation evidence
4. **Multiple Security News Articles** mentioning "zero-day"
5. **APT Group Associations** in threat intelligence

### 5. Evidence Quality Analysis

**High-Quality Evidence** (>80% confidence):
- CVE-2024-21412: Microsoft Defender bypass with clear zero-day indicators
- CVE-2023-20198: Cisco IOS XE with documented pre-patch exploitation
- CVE-2023-4966: Citrix Bleed with extensive APT usage

**Medium-Quality Evidence** (50-80% confidence):
- CVEs with partial timeline data
- Limited news coverage but CISA KEV listing
- Vendor acknowledgment without explicit zero-day confirmation

### 6. Rate Limiting Observations

**Google Search** (via news scraping):
- Rate limited after ~15 consecutive searches
- HTTP 429 errors with reCAPTCHA challenges
- Recommendation: Implement exponential backoff and proxy rotation

**GitHub API**:
- More permissive with authenticated requests
- Successfully scraped all requested CVEs
- Repository creation dates crucial for timeline analysis

### 7. Zero-Day Confidence Distribution

```
Confidence Range | Count | Percentage
-----------------|-------|------------
90-100%         |   8   |   21.6%
70-89%          |  12   |   32.4%
50-69%          |  10   |   27.0%
30-49%          |   5   |   13.5%
0-29%           |   2   |    5.4%
```

## Recommendations for Future Work

1. **Implement Distributed Scraping**
   - Use multiple IP addresses/proxies
   - Implement request queuing with delays
   - Cache results more aggressively

2. **Enhance Timeline Analysis**
   - Cross-reference multiple sources for disclosure dates
   - Identify "patch gap" periods more accurately
   - Correlate with threat intelligence feeds

3. **Expand Evidence Sources**
   - Include dark web forums (with appropriate access)
   - Monitor security researcher Twitter/Mastodon
   - Track exploit kit integration timelines

4. **Machine Learning Integration**
   - Train models on this real-world dataset
   - Use scraped features for automated classification
   - Implement active learning for ambiguous cases

## Conclusion

The dynamic dataset acquisition demonstrates the feasibility of real-time zero-day detection through comprehensive evidence gathering. The high correlation with CISA KEV listings (81.1%) validates our multi-source approach and provides a strong foundation for academic evaluation of the system.