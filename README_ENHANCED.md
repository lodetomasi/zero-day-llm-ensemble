# Zero-Day LLM Ensemble - Enhanced with Web Scraping

## Overview

This enhanced version combines the original multi-agent LLM system with comprehensive web scraping to achieve superior zero-day detection accuracy.

### Key Improvements

1. **Comprehensive Web Scraping**: Collects evidence from 8+ sources including:
   - CISA Known Exploited Vulnerabilities (KEV)
   - National Vulnerability Database (NVD)
   - Security news outlets (The Hacker News, BleepingComputer, SecurityWeek)
   - GitHub exploit repositories
   - Threat intelligence sources
   - Vendor security advisories
   - Social media discussions

2. **Evidence-Based Scoring**: Combines web evidence (70%) with LLM analysis (30%) for more reliable predictions

3. **Real-World Performance**: Achieved **83.3% accuracy** on test set with known ground truth

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble

# Install dependencies
pip install -r requirements.txt

# Set API key
export OPENROUTER_API_KEY="your-api-key"
```

### Basic Usage

```bash
# Analyze specific CVEs
python run_analysis.py CVE-2023-23397 CVE-2021-44228 CVE-2024-3400

# Analyze from file
python run_analysis.py --file cve_list.txt

# Verbose output with details
python run_analysis.py CVE-2023-23397 --verbose
```

### Advanced Features

```python
# Programmatic usage
from src.scraping.comprehensive_scraper import create_cve_report

# Generate comprehensive report for a CVE
report_path = create_cve_report("CVE-2023-23397")
```

## Architecture

### Enhanced Data Flow

```
CVE Input → Web Scraping (8 sources) → Evidence Analysis → LLM Ensemble → Combined Score → Classification
```

### Scoring Components

1. **Web Evidence Score** (70% weight):
   - CISA KEV listing: +0.3
   - Security news zero-day mentions: +0.1 per article
   - APT group associations: +0.15
   - Emergency patches: +0.1
   - Vendor out-of-band updates: +0.15

2. **LLM Ensemble Score** (30% weight):
   - 5 specialized agents analyzing patterns
   - Unweighted average of predictions

### Evidence Sources

| Source | Type | Indicators |
|--------|------|------------|
| CISA KEV | Official | Confirmed exploited vulnerabilities |
| NVD | Official | CVE details, CVSS scores, references |
| Security News | Media | Zero-day mentions, exploitation reports |
| GitHub | Code | PoC availability, timeline analysis |
| Threat Intel | Analysis | APT associations, campaign names |
| Vendor Advisories | Official | Emergency patches, severity |
| Social Media | Community | Security researcher discussions |
| Exploit DBs | Technical | Metasploit modules, commercial exploits |

## Performance Results

### Test Set Results (6 CVEs with known ground truth)

```
Confusion Matrix:
                 Predicted
              Zero-day  Regular
Actual Zero-day     3        0
       Regular      1        2

Accuracy:  83.3%
Precision: 75.0%
Recall:    100.0%
F1 Score:  0.857
```

### Individual CVE Results

| CVE | Ground Truth | Evidence Score | LLM Score | Combined | Verdict |
|-----|--------------|----------------|-----------|----------|---------|
| CVE-2023-23397 | Zero-day | 75% | 59% | 69% | ✓ Zero-day |
| CVE-2023-20198 | Zero-day | 75% | 74% | 75% | ✓ Zero-day |
| CVE-2024-3400 | Zero-day | 65% | 77% | 70% | ✓ Zero-day |
| CVE-2014-0160 | Regular | 55% | 41% | 49% | ✓ Regular |
| CVE-2017-5638 | Regular | 65% | 39% | 54% | ✓ Regular |
| CVE-2021-44228 | Regular | 65% | 53% | 60% | ✗ Zero-day |

## Technical Details

### Caching System

- 7-day cache for scraped content
- Reduces API calls and improves performance
- Cache location: `data/scraping_cache/`

### Rate Limiting

- Automatic rate limiting per domain
- Configurable delays between requests
- Prevents blocking by security sites

### Parallel Processing

- Concurrent scraping from multiple sources
- Thread pool for efficient data collection
- Maintains rate limits per domain

## API Reference

### ComprehensiveZeroDayScraper

```python
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper

# Initialize scraper
scraper = ComprehensiveZeroDayScraper()

# Scrape all sources for a CVE
evidence = scraper.scrape_all_sources("CVE-2023-23397")

# Access results
print(f"Zero-day confidence: {evidence['scores']['zero_day_confidence']:.1%}")
print(f"Evidence quality: {evidence['scores']['evidence_quality']:.1%}")
print(f"Summary: {evidence['summary']}")
```

### Key Methods

- `scrape_all_sources(cve_id)`: Comprehensive evidence collection
- `scrape_nvd_details(cve_id)`: NVD specific data
- `scrape_cisa_kev(cve_id)`: Check CISA KEV listing
- `scrape_security_news(cve_id)`: News article analysis
- `scrape_github_activity(cve_id)`: GitHub PoC timeline
- `scrape_threat_intelligence(cve_id)`: APT associations
- `scrape_vendor_advisories(cve_id)`: Vendor response analysis

## Output Files

### JSON Report
```json
{
  "cve_id": "CVE-2023-23397",
  "scraped_at": "2025-07-27T14:30:00",
  "sources": {
    "nvd": { ... },
    "cisa_kev": { "in_kev": true, ... },
    "security_news": { "zero_day_mentions": 3, ... },
    "github": { "poc_repositories": 5, ... }
  },
  "scores": {
    "zero_day_confidence": 0.75,
    "exploitation_likelihood": 0.80,
    "evidence_quality": 0.85
  }
}
```

### Markdown Summary
- Human-readable report
- Key indicators highlighted
- Confidence scores explained
- Evidence sources listed

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create Pull Request

## License

MIT License - see LICENSE file for details

## Citation

```bibtex
@software{zero_day_llm_ensemble_enhanced,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Detection Using LLM Ensemble with Web Evidence},
  year = {2025},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble}
}
```